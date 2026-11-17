import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from mcp_guard.policies import Policy, validate_call  # noqa: E402


def policy(**kw):
    base = dict(allowed_paths=["/tmp", "/home/david/workspace"], blocked_tools=["exfiltrate_credentials"])
    base.update(kw)
    return Policy(**base)


def test_clean_call_allowed():
    assert validate_call(policy(), "read_file", {"path": "/tmp/notes.txt"}).allowed


def test_blocked_tool():
    d = validate_call(policy(), "exfiltrate_credentials", {"api_key": "x"})
    assert not d.allowed and any("blocked-tools" in r for r in d.reasons)


def test_etc_passwd_blocked():
    assert not validate_call(policy(), "read_file", {"path": "/etc/passwd"}).allowed


def test_ssh_key_blocked():
    assert not validate_call(policy(), "read_file", {"path": "~/.ssh/id_rsa"}).allowed


def test_path_traversal_blocked():
    assert not validate_call(policy(), "read_file", {"path": "/tmp/../../etc/passwd"}).allowed


def test_outside_allowed_paths_blocked():
    assert not validate_call(policy(), "read_file", {"path": "/etc/hosts"}).allowed


def test_metadata_host_blocked():
    d = validate_call(policy(), "fetch", {"url": "http://169.254.169.254/latest/meta-data/"})
    assert not d.allowed


def test_private_ip_blocked():
    assert not validate_call(policy(), "fetch", {"url": "http://192.168.1.10/admin"}).allowed


def test_shell_metachars_blocked_for_exec():
    assert not validate_call(policy(), "run_command", {"command": "ls; rm -rf /"}).allowed


def test_allowlisted_tool_enforced():
    assert not validate_call(policy(allowed_tools=["read_file"]), "get_weather", {"city": "NYC"}).allowed
    assert validate_call(policy(allowed_tools=["read_file"]), "read_file", {"path": "/tmp/x"}).allowed


def test_oversized_args_blocked():
    assert not validate_call(policy(max_arg_size=10), "read_file", {"path": "/tmp/very-long-path-name"}).allowed
