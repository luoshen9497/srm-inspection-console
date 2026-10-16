#!/usr/bin/env bash
set -Eeuo pipefail
exec 8>/var/lock/srm-inspection-build.lock
flock -n 8 || { echo 'Another image build is running'; exit 1; }
RELEASE=$(cd -- "$(dirname -- "$0")/.." && pwd)
cd "$RELEASE"
python3 deploy/verify_release.py
VERSION=$(python3 -c 'import json;print(json.load(open("release.json"))["version"])')
[[ $VERSION =~ ^r-[a-f0-9]{16}$ ]] || exit 1
BASE_IMAGE=${SRM_BASE_IMAGE:-python:3.13-slim}
PIP_INDEX=${SRM_PIP_INDEX:-https://mirrors.aliyun.com/pypi/simple}
CACHE=/opt/srm-inspection/build-cache
BUILD_ARGS=(--build-arg "PYTHON_IMAGE=$BASE_IMAGE" --build-arg "PIP_INDEX_URL=$PIP_INDEX" --build-arg "RELEASE_VERSION=$VERSION" --build-arg DEBIAN_MIRROR=https://mirrors.aliyun.com)
if [[ -f $CACHE/cache.sha256 ]]; then
    (cd "$CACHE" && sha256sum -c cache.sha256)
    # Serve only cached dependencies on loopback during this build.
    python3 -m http.server 18992 --bind 127.0.0.1 --directory "$CACHE" > "$CACHE/http-build.log" 2>&1 &
    CACHE_PID=$!
    trap 'kill "$CACHE_PID" 2>/dev/null || true; wait "$CACHE_PID" 2>/dev/null || true' EXIT
    for attempt in $(seq 1 20); do
        curl -fsS --max-time 1 http://127.0.0.1:18992/cache.sha256 >/dev/null 2>&1 && break
        sleep 0.2
    done
    kill -0 "$CACHE_PID"
    BUILD_ARGS+=(--build-arg PIP_FIND_LINKS=http://127.0.0.1:18992/wheels/ --build-arg PIP_NO_INDEX=true --build-arg PLAYWRIGHT_DOWNLOAD_HOST=http://127.0.0.1:18992)
fi
docker build --network host "${BUILD_ARGS[@]}" -f deploy/Dockerfile -t "srm-inspection:$VERSION" .
