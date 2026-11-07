"""Tests for how the IDS builds and launches its tcpdump capture.

They never run tcpdump: argv is checked directly, and subprocess.Popen is
replaced by a fake that records the call.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import ids_file  # noqa: E402


def test_line_buffered_output_is_requested():
    assert "-l" in ids_file.build_capture_cmd("lo", 10)


def test_filter_goes_after_double_dash():
    cmd = ids_file.build_capture_cmd("lo", 10, "tcp port 22")
    assert cmd[-2:] == ["--", "tcp port 22"]


def test_option_like_filter_stays_one_expression_argument():
    cmd = ids_file.build_capture_cmd("lo", 10, "-z /tmp/x -Z root")
    assert cmd[-2:] == ["--", "-z /tmp/x -Z root"]
    assert "-z" not in cmd and "-Z" not in cmd


def test_sudo_mode_keeps_password_prompt_on_terminal():
    cmd = ids_file.build_capture_cmd("lo", 5, use_sudo=True)
    assert cmd[:4] == ["timeout", "--foreground", "5", "sudo"]


def test_no_sudo_by_default():
    assert "sudo" not in ids_file.build_capture_cmd("lo", 5)


@pytest.mark.parametrize(
    "bad",
    ["lo; id", "lo && id", "$(id)", "`id`", "-z", "..", "eth0 -w /tmp/x", "a" * 16, ""],
)
def test_injection_like_interfaces_are_rejected(bad):
    with pytest.raises(ValueError):
        ids_file.validate_interface(bad)


@pytest.mark.skipif(not os.path.exists("/sys/class/net/lo"), reason="needs Linux sysfs")
def test_existing_interface_is_accepted():
    assert ids_file.validate_interface("lo") == "lo"


def test_capture_uses_argv_list_without_shell(monkeypatch):
    calls = {}

    class FakeProc:
        stdout = iter([])
        stderr = None
        returncode = 124

        def wait(self):
            return self.returncode

    def fake_popen(cmd, **kwargs):
        calls["cmd"], calls["kwargs"] = cmd, kwargs
        return FakeProc()

    monkeypatch.setattr(ids_file.subprocess, "Popen", fake_popen)
    # Bypass validation to prove that even a hostile value stays one argv element.
    monkeypatch.setattr(ids_file, "validate_interface", lambda iface: iface)
    ids = ids_file.IDS("lo; id")
    monkeypatch.setattr(ids, "generate_report", lambda: None)

    ids.capture_packets(1, bpf_filter="-z /tmp/x")

    assert isinstance(calls["cmd"], list)
    assert not calls["kwargs"].get("shell")
    assert "lo; id" in calls["cmd"]
    assert calls["cmd"][-2:] == ["--", "-z /tmp/x"]


def test_capture_rejects_unknown_interface_before_launching(monkeypatch):
    def fail_popen(*args, **kwargs):
        raise AssertionError("tcpdump must not be launched for an invalid interface")

    monkeypatch.setattr(ids_file.subprocess, "Popen", fail_popen)
    with pytest.raises(ValueError):
        ids_file.IDS("lo; id").capture_packets(1)
