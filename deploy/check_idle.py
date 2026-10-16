"""Wait for the old runtime to finish an inspection using read-only summary APIs."""
import json
import time
from contextlib import nullcontext
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from verification_session import verification_session

BASE = "http://127.0.0.1:18091"
headers = {}
try:
    with urlopen(BASE + "/api/systems", timeout=5) as response:
        json.load(response)
except HTTPError as error:
    if error.code == 401:
        authenticated = True
    else:
        raise
else:
    authenticated = False
with verification_session() if authenticated else nullcontext(None) as session:
    if session:
        headers["Cookie"] = session[0]
    for _ in range(60):
        with urlopen(Request(BASE+"/api/systems", headers=headers), timeout=5) as response:
            systems = json.load(response)
        assert isinstance(systems, list) and systems
        assert all("active_run_id" in state for state in systems), "Unknown running-state schema"
        if not any(state["active_run_id"] for state in systems):
            print("No active inspection")
            break
        time.sleep(2)
    else:
        raise SystemExit("Inspection still active; retry publishing after it finishes")
