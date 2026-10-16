#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
[[ ${EUID} -eq 0 ]] || exit 1
BACKUP=$(readlink -f -- "${1:?Supply the backup path}")
[[ $BACKUP == /var/backups/srm-inspection/* && -f $BACKUP/service.unit ]] || exit 1
python3 - "$BACKUP" <<'PY'
from pathlib import Path
import sys
backup=Path(sys.argv[1])
legacy='-v /opt/srm-inspection/app.py:' in (backup/'service.unit').read_text()
if legacy and not (backup/'nginx-site.conf').exists():
    raise SystemExit('Legacy application rollback requires its original nginx authentication configuration')
PY
if [[ ${3:-} != --lock-held ]]; then
    exec 9>/var/lock/srm-inspection-deploy.lock
    flock -n 9 || { echo 'Another deployment is running'; exit 1; }
fi
systemctl stop srm-inspection
if [[ ${2:-} == --restore-data && -f $BACKUP/backup-complete ]]; then
    # Use only immediately after a failed deployment. Later rollbacks should keep
    # reports produced since release and separately assess schema compatibility.
    for path in /etc/srm-inspection /var/lib/srm-inspection; do
        if [[ -d $path ]]; then
            mv "$path" "$path.failed-$(date -u +%Y%m%dT%H%M%SZ)-$$"
        fi
    done
    tar -xzf "$BACKUP/config-data.tar.gz" -C /
elif [[ -f $BACKUP/deployment.env ]]; then
    install -m 600 "$BACKUP/deployment.env" /etc/srm-inspection/deployment.env
else
    rm -f /etc/srm-inspection/deployment.env
fi
install -m 644 "$BACKUP/service.unit" /etc/systemd/system/srm-inspection.service
if [[ -f $BACKUP/nginx-site.conf ]]; then
    install -m 644 "$BACKUP/nginx-site.conf" /etc/nginx/sites-available/srm-inspection
    nginx -t
    systemctl reload nginx
fi
systemctl daemon-reload
systemctl start srm-inspection
systemctl is-active --quiet srm-inspection
echo "RESTORED=$BACKUP"
