"""Tests for the panel's request guards and parameter validation.

No tool is ever launched: subprocess.Popen is replaced by a fake.
"""

import io
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import app as panel  # noqa: E402

LOCAL = "http://127.0.0.1:5000"
HAS_LO = os.path.exists("/sys/class/net/lo")


class FakeProc:
    pid = 999999
    returncode = 0

    def __init__(self):
        self.stdout = io.StringIO("")

    def wait(self):
        return 0

    def poll(self):
        return 0


@pytest.fixture
def client():
    panel.app.config["TESTING"] = True
    return panel.app.test_client()


@pytest.fixture
def launched(monkeypatch):
    calls = []

    def fake_popen(argv, **kwargs):
        calls.append(argv)
        return FakeProc()

    monkeypatch.setattr(panel.subprocess, "Popen", fake_popen)
    return calls


def run(client, body, origin=None, base_url=LOCAL):
    headers = {"Origin": origin} if origin else {}
    return client.post("/api/run", json=body, headers=headers, base_url=base_url)


def test_foreign_host_is_rejected(client):
    # DNS rebinding: attacker domain resolving to 127.0.0.1.
    assert client.get("/api/catalog", base_url="http://evil.example:5000").status_code == 403


@pytest.mark.parametrize("base", [LOCAL, "http://localhost:5000"])
def test_local_hosts_are_allowed(client, base):
    assert client.get("/api/catalog", base_url=base).status_code == 200


def test_cross_site_origin_is_rejected(client, launched):
    r = run(client, {"id": "ids", "params": {"interface": "lo"}}, origin="http://evil.example")
    assert r.status_code == 403
    assert launched == []


def test_null_origin_is_rejected(client, launched):
    r = run(client, {"id": "ids", "params": {"interface": "lo"}}, origin="null")
    assert r.status_code == 403
    assert launched == []


def test_non_json_body_is_rejected(client, launched):
    # What a cross-site page can send without a CORS preflight.
    r = client.post("/api/run", data='{"id": "ids", "params": {}}',
                    content_type="text/plain", base_url=LOCAL)
    assert r.status_code == 415
    assert launched == []


@pytest.mark.parametrize("iface", ["lo; id", "$(id)", "-z", "..", "a" * 16])
def test_bad_interface_is_rejected(client, launched, iface):
    r = run(client, {"id": "ids", "params": {"interface": iface}}, origin=LOCAL)
    assert r.status_code == 400
    assert launched == []


def test_leading_dash_value_is_rejected(client, launched):
    r = run(client, {"id": "ddos-simulator", "params": {"target": "--help"}}, origin=LOCAL)
    assert r.status_code == 400
    assert launched == []


@pytest.mark.skipif(not HAS_LO, reason="needs Linux sysfs")
def test_ids_runs_without_sudo_from_own_origin(client, launched):
    r = run(client, {"id": "ids", "params": {"interface": "lo", "time": "1"}}, origin=LOCAL)
    assert r.status_code == 200, r.get_json()
    argv = launched[0]
    assert "sudo" not in argv
    assert argv[argv.index("-i") + 1] == "lo"


@pytest.mark.skipif(not HAS_LO, reason="needs Linux sysfs")
def test_root_tools_use_non_interactive_sudo():
    argv, _ = panel.build_argv(panel.CATALOG_BY_ID["packet-sniffer"], {"interface": "lo"})
    assert argv[:2] == ["sudo", "-n"]
