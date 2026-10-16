#!/usr/bin/env bash
# Configuration-only sync; SSH prompts for a password when needed.
set -Eeuo pipefail
ROOT=$(cd -- "$(dirname -- "$0")/.." && pwd)
TARGET=${SRM_SSH_TARGET:?Set SRM_SSH_TARGET to your deployment SSH target}
SYSTEM=overseas-srm
APPLY=()
WITH_CREDENTIALS=0
while (($#)); do
    case "$1" in
        --system) SYSTEM=${2:?Missing system ID}; shift 2 ;;
        --apply|--enable) APPLY+=("$1"); shift ;;
        --with-ui-credentials) WITH_CREDENTIALS=1; shift ;;
        *) echo "Unknown argument: $1" >&2; exit 1 ;;
    esac
done
[[ $TARGET =~ ^[a-zA-Z0-9_.-]+@[a-zA-Z0-9_.-]+$ ]] || exit 1
[[ $SYSTEM =~ ^[a-z0-9][a-z0-9_-]{1,63}$ ]] || exit 1
WORK=$(mktemp -d /tmp/srm-ui-sync.XXXXXX)
chmod 700 "$WORK"
REMOTE=
SSH_OPTIONS=(-o StrictHostKeyChecking=yes -o ControlMaster=auto -o ControlPersist=10m
             -o "ControlPath=${SRM_SSH_CONTROL_PATH:-$WORK/ssh}")
cleanup() {
    if [[ -n $REMOTE ]]; then
        ssh "${SSH_OPTIONS[@]}" "$TARGET" "rm -rf -- '$REMOTE'" >/dev/null 2>&1 || true
    fi
    if [[ -z ${SRM_SSH_CONTROL_PATH:-} ]]; then
        ssh "${SSH_OPTIONS[@]}" -O exit "$TARGET" >/dev/null 2>&1 || true
    fi
    rm -rf -- "$WORK"
}
trap cleanup EXIT
python3 - "$ROOT" "$SYSTEM" "$WORK/bundle.json" "$WITH_CREDENTIALS" <<'PY'
import json, os, sys
from pathlib import Path
root, system, output, with_credentials = sys.argv[1:]
root = Path(root)
document = json.loads((root / 'config/systems' / system / 'ui-scenes.json').read_text())
if document.get('schema_version') != 1 or not document.get('items'):
    raise SystemExit('No UI scenes to sync; empty collections never delete server scenes')
bundle = {'system_id': system, 'items': document['items']}
if with_credentials == '1':
    secrets = json.loads((root / 'data/systems' / system / 'secrets.json').read_text())
    bundle['credentials'] = {target: secrets.get(source, '') for target, source in
                             [('ui_username', 'SRM_UI_USERNAME'), ('ui_password', 'SRM_UI_PASSWORD')]}
    if not all(bundle['credentials'].values()):
        raise SystemExit('Local UI username/password are not configured')
with open(output, 'x', opener=lambda p, flags: os.open(p, flags, 0o600)) as file:
    json.dump(bundle, file, ensure_ascii=False)
PY
REMOTE=$(ssh "${SSH_OPTIONS[@]}" "$TARGET" 'umask 077; mktemp -d /tmp/srm-ui-sync.XXXXXXXX')
[[ $REMOTE =~ ^/tmp/srm-ui-sync\.[a-zA-Z0-9]+$ ]] || exit 1
scp "${SSH_OPTIONS[@]}" "$WORK/bundle.json" "$ROOT/deploy/sync_ui_scenes.py" \
    "$ROOT/deploy/verification_session.py" "$TARGET:$REMOTE/"
ssh "${SSH_OPTIONS[@]}" "$TARGET" \
    "python3 '$REMOTE/sync_ui_scenes.py' '$REMOTE/bundle.json' ${APPLY[*]:-}"
