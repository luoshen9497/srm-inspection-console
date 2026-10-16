"""Check authentication and read-only APIs via the loopback backend."""
import json
from contextlib import nullcontext
from verification_session import verification_session
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import HTTPError

BASE = "http://127.0.0.1:18091"
credentials_path = Path("/etc/srm-inspection/initial-admin.json")


def request(path, body=None, cookie=None, csrf=None):
    headers = {"Content-Type": "application/json"}
    if cookie:
        headers["Cookie"] = cookie
    if csrf:
        headers["X-CSRF-Token"] = csrf
    data = json.dumps(body).encode() if body is not None else None
    with urlopen(Request(BASE + path, data=data, headers=headers), timeout=10) as response:
        raw = response.read()
        return response.status, response.headers, json.loads(raw) if raw else None


try:
    request("/api/systems")
except HTTPError as error:
    assert error.code == 401, error.code
else:
    raise AssertionError("Unauthenticated API unexpectedly accessible")
if Path("/etc/srm-inspection/.verify-bootstrap").exists():
    credentials = json.loads(credentials_path.read_text())
    status, headers, body = request("/api/auth/login", credentials)
    assert status == 200 and body.get("authenticated"), body
    assert "Secure" in headers["Set-Cookie"]
    cookie = headers["Set-Cookie"].split(";", 1)[0]
    csrf = body["csrf_token"]
    context = nullcontext((cookie, csrf))
else:
    context = verification_session()
with context as (cookie, csrf):
    status, _, systems = request("/api/systems", cookie=cookie)
    assert status == 200
    assert isinstance(systems, list) and len(systems) > 0
    print("authenticated_systems:", len(systems))
    for entry in systems:
        system_id = entry["system_id"]
        for path in ("/api/config", "/api/reports/api", "/api/reports/ui", "/api/ui/capabilities"):
            status, _, result = request("/api/systems/" + system_id + path[4:], cookie=cookie)
            assert status == 200
            if path == "/api/ui/capabilities":
                assert result["playwright_installed"]
        print("read_apis_verified:", system_id)
    request("/api/auth/logout", {}, cookie=cookie, csrf=csrf)
    print("runtime_verification_passed")
