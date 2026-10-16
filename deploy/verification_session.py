"""Create and reliably revoke a temporary deployment verification session."""
from contextlib import contextmanager
import json
import subprocess


@contextmanager
def verification_session():
    # Execute as the container's application user, so SQLite WAL files keep the
    # same ownership as the running application.
    code = '''import hashlib,json,secrets,sqlite3,time
from pathlib import Path
token,csrf=secrets.token_urlsafe(32),secrets.token_urlsafe(24)
token_hash=hashlib.sha256(token.encode()).hexdigest()
username=json.loads(Path('/data/admin.json').read_text())['username']
now=int(time.time())
database=sqlite3.connect('/data/auth.db')
with database:
    database.execute('INSERT INTO auth_sessions VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        (token_hash,username,csrf,now,now+180,now,'127.0.0.1','deployment-verification'))
database.close()
print(json.dumps({'cookie':'__Host-srm_session='+token,'csrf':csrf,'token_hash':token_hash}))
'''
    result = subprocess.run(['docker', 'exec', 'srm-inspection', 'python', '-c', code],
                            check=True, capture_output=True, text=True)
    session = json.loads(result.stdout)
    try:
        yield session['cookie'], session['csrf']
    finally:
        cleanup = "import sqlite3,sys; c=sqlite3.connect('/data/auth.db'); c.execute('DELETE FROM auth_sessions WHERE token_hash=?',(sys.argv[1],)); c.commit(); c.close()"
        subprocess.run(['docker', 'exec', 'srm-inspection', 'python', '-c', cleanup,
                        session['token_hash']], check=True, capture_output=True, text=True)
