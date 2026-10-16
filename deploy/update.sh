#!/usr/bin/env bash
# Local entry point. SSH prompts for a password; no password is stored here.
set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "$0")/.." && pwd)
TARGET=${SRM_SSH_TARGET:?Set SRM_SSH_TARGET to your deployment SSH target}
BASE_IMAGE=${SRM_BASE_IMAGE:-python:3.13-slim}
PIP_INDEX=${SRM_PIP_INDEX:-https://mirrors.aliyun.com/pypi/simple}
[[ $TARGET =~ ^[a-zA-Z0-9_.-]+@[a-zA-Z0-9_.-]+$ ]] || exit 1
[[ $BASE_IMAGE =~ ^[a-zA-Z0-9_.:/-]+$ ]] || exit 1
[[ $PIP_INDEX =~ ^https://[a-zA-Z0-9_./-]+$ ]] || exit 1
cd "$ROOT"
python3 -m unittest discover -s tests -v
META=$(python3 deploy/prepare_release.py)
VERSION=$(printf '%s' "$META" | python3 -c 'import json,sys;print(json.load(sys.stdin)["version"])')
SHA=$(printf '%s' "$META" | python3 -c 'import json,sys;print(json.load(sys.stdin)["archive_sha256"])')
[[ $VERSION =~ ^r-[a-f0-9]{16}$ && $SHA =~ ^[a-f0-9]{64}$ ]] || exit 1
REMOTE=/opt/srm-inspection/releases/$VERSION
CONTROL=$(mktemp -d /tmp/srm-deploy.XXXXXX)
chmod 700 "$CONTROL"
SSH_OPTIONS=(-o StrictHostKeyChecking=yes -o ControlMaster=auto -o ControlPersist=10m -o "ControlPath=$CONTROL/ssh")
cleanup() {
    ssh "${SSH_OPTIONS[@]}" -O exit "$TARGET" >/dev/null 2>&1 || true
    rm -rf -- "$CONTROL"
}
trap cleanup EXIT
ssh "${SSH_OPTIONS[@]}" "$TARGET" "mkdir -p '$REMOTE'"
scp "${SSH_OPTIONS[@]}" "$ROOT/.releases/$VERSION/release.tar.gz" "$TARGET:$REMOTE/release.tar.gz"
ssh "${SSH_OPTIONS[@]}" "$TARGET" \
    "cd '$REMOTE' && echo '$SHA  release.tar.gz' | sha256sum -c - && tar -xzf release.tar.gz && SRM_BASE_IMAGE='$BASE_IMAGE' SRM_PIP_INDEX='$PIP_INDEX' bash deploy/build.sh && bash deploy/publish.sh"
