#!/usr/bin/env bash
# Run on the server after the complete image has been built and checked.
set -Eeuo pipefail
umask 077
[[ ${EUID} -eq 0 ]] || { echo 'Run as root'; exit 1; }
RELEASE=$(cd -- "$(dirname -- "$0")/.." && pwd)
[[ $RELEASE == /opt/srm-inspection/releases/r-* ]] || { echo 'Unexpected release path'; exit 1; }
exec 9>/var/lock/srm-inspection-deploy.lock
flock -n 9 || { echo 'Another deployment is running'; exit 1; }
IMAGE=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["image"])' "$RELEASE/release.json")
[[ $IMAGE =~ ^srm-inspection:r-[a-f0-9]{16}$ ]] || exit 1
python3 "$RELEASE/deploy/verify_release.py"
docker image inspect "$IMAGE" >/dev/null
docker run --rm --user 10001:10001 --read-only --shm-size=1g --security-opt no-new-privileges \
    --tmpfs /tmp:rw,noexec,nosuid,size=256m --entrypoint python \
    -v /etc/srm-inspection:/config:ro -v "$RELEASE/deploy/check_image.py:/app/check_image.py:ro" \
    "$IMAGE" /app/check_image.py

BACKUP=/var/backups/srm-inspection/$(date -u +%Y%m%dT%H%M%SZ)-${IMAGE#*:}
mkdir -p "$BACKUP"
cp -a /etc/systemd/system/srm-inspection.service "$BACKUP/service.unit"
if [[ -f /etc/nginx/sites-available/srm-inspection ]]; then
    cp -a /etc/nginx/sites-available/srm-inspection "$BACKUP/nginx-site.conf"
fi
docker inspect srm-inspection --format '{{.Image}}' > "$BACKUP/previous-image-id"
if [[ -f /etc/srm-inspection/deployment.env ]]; then
    cp -a /etc/srm-inspection/deployment.env "$BACKUP/deployment.env"
fi
ROLLBACK_REQUIRED=0
rollback_on_error() {
    result=$?
    trap - ERR INT TERM
    if [[ $ROLLBACK_REQUIRED -eq 1 ]]; then
        echo "Deployment failed; restoring $BACKUP" >&2
        bash "$RELEASE/deploy/rollback.sh" "$BACKUP" --restore-data --lock-held
    fi
    exit "$result"
}
trap rollback_on_error ERR INT TERM
# An active inspection is a reason to wait, not to kill a business request.
python3 "$RELEASE/deploy/check_idle.py"
systemctl stop srm-inspection
ROLLBACK_REQUIRED=1
tar -czf "$BACKUP/config-data.tar.gz" -C / etc/srm-inspection var/lib/srm-inspection
tar -tzf "$BACKUP/config-data.tar.gz" >/dev/null
touch "$BACKUP/backup-complete"

if [[ ! -f /var/lib/srm-inspection/admin.json ]]; then
    docker run --rm --user 10001:10001 --read-only --tmpfs /tmp:rw,nosuid,size=64m \
        --entrypoint python -v /var/lib/srm-inspection:/data:rw "$IMAGE" -c \
        'import json; from pathlib import Path; from app import AuthManager; a=AuthManager(Path("/data/auth.db"),Path("/data/admin.json")); print(json.dumps({"username":a.username,"password":a.bootstrap_password}))' \
        > /etc/srm-inspection/initial-admin.json
    chmod 600 /etc/srm-inspection/initial-admin.json
    touch /etc/srm-inspection/.verify-bootstrap
fi

# Keep existing environment settings and change only the selected image. The
# existing nginx entry point is HTTPS, so use secure session cookies.
python3 - "$IMAGE" <<'PY'
from pathlib import Path
import sys
p=Path('/etc/srm-inspection/deployment.env')
lines=p.read_text().splitlines() if p.exists() else []
lines=[v for v in lines if not v.startswith(('INSPECTION_IMAGE=', 'INSPECTION_COOKIE_SECURE='))]
lines += ['INSPECTION_IMAGE='+sys.argv[1], 'INSPECTION_COOKIE_SECURE=1']
p.write_text('\n'.join(lines)+'\n')
p.chmod(0o600)
PY
install -m 644 "$RELEASE/deploy/srm-inspection.service" /etc/systemd/system/srm-inspection.service
systemctl daemon-reload
systemctl start srm-inspection
for attempt in $(seq 1 30); do
    status=$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 http://127.0.0.1:18091/api/auth/session || true)
    [[ $status == 401 ]] && break
    sleep 1
done
[[ $status == 401 ]]
systemctl is-active --quiet srm-inspection
python3 "$RELEASE/deploy/verify_runtime.py"
rm -f /etc/srm-inspection/.verify-bootstrap
# nginx keeps TLS and reverse proxying; application sessions protect the data.
[[ $(curl -k -s -o /dev/null -w '%{http_code}' --max-time 5 https://127.0.0.1:8091/) == 303 ]]
[[ $(curl -k -s -o /dev/null -w '%{http_code}' --max-time 5 https://127.0.0.1:8091/login) == 200 ]]
[[ $(curl -k -s -o /dev/null -w '%{http_code}' --max-time 5 https://127.0.0.1:8091/api/systems) == 401 ]]
printf '%s\n' "$IMAGE" > "$BACKUP/deployed-image"
ln -sfn "$RELEASE" /opt/srm-inspection/current
ln -sfn "$BACKUP" /var/backups/srm-inspection/latest
install -m 644 "$RELEASE/deploy/rollback.sh" /opt/srm-inspection/rollback.sh
ROLLBACK_REQUIRED=0
trap - ERR INT TERM
echo "DEPLOYED=$IMAGE"
echo "BACKUP=$BACKUP"
