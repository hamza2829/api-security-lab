"""Start real loopback servers so tests reuse the requests-based exploits."""

import os
import secrets
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest
import requests

from exploits.common import LocalAPI


ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="session")
def signing_secret():
    return secrets.token_urlsafe(48)


@pytest.fixture(scope="session")
def start_server(tmp_path_factory, signing_secret):
    processes = []

    def start(module: str) -> LocalAPI:
        # Reserve an unused loopback port, then hand it to Uvicorn.
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        folder = tmp_path_factory.mktemp(module)
        env = os.environ.copy()
        env["LAB_DB_PATH"] = str(folder / "lab.db")
        env["LAB_JWT_SECRET"] = signing_secret
        log = (folder / "server.log").open("w", encoding="utf-8")
        process = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", f"{module}.main:app",
             "--host", "127.0.0.1", "--port", str(port), "--log-level", "warning"],
            cwd=ROOT, env=env, stdout=log, stderr=log,
        )
        processes.append((process, log))
        api = LocalAPI(f"http://127.0.0.1:{port}")
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if process.poll() is not None:
                break
            try:
                if api.get("/openapi.json").status_code == 200:
                    return api
            except requests.ConnectionError:
                pass
            time.sleep(0.1)
        log.flush()
        pytest.fail((folder / "server.log").read_text(encoding="utf-8"))

    yield start
    for process, log in processes:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        log.close()


@pytest.fixture(scope="session")
def vulnerable_api(start_server):
    return start_server("app_vulnerable")
