from __future__ import annotations

from app.ssh.logs import (
    build_file_command,
    build_journal_command,
    build_list_directory_command,
    is_path_allowed,
    parse_directory_listing,
)

_ALLOWED = ["/var/log", "/var/lib/docker/containers"]


def test_is_path_allowed_exact_prefix_match():
    assert is_path_allowed("/var/log", _ALLOWED) is True


def test_is_path_allowed_file_under_prefix():
    assert is_path_allowed("/var/log/syslog", _ALLOWED) is True
    assert is_path_allowed("/var/log/nginx/access.log", _ALLOWED) is True


def test_is_path_allowed_rejects_outside_prefix():
    assert is_path_allowed("/etc/shadow", _ALLOWED) is False
    assert is_path_allowed("/var/logs/fake", _ALLOWED) is False  # not a real prefix match
    assert is_path_allowed("/var/log-other/x", _ALLOWED) is False


def test_is_path_allowed_rejects_relative_path():
    assert is_path_allowed("var/log/syslog", _ALLOWED) is False


def test_is_path_allowed_rejects_dot_dot_traversal():
    # Textually starts with an allowed prefix, but walks back out of it.
    assert is_path_allowed("/var/log/../../etc/shadow", _ALLOWED) is False
    assert is_path_allowed("/var/log/..", _ALLOWED) is False


def test_build_journal_command_defaults():
    command = build_journal_command(lines=200, search="", since="", until="")

    assert command == "journalctl --no-pager -n 200"


def test_build_journal_command_quotes_untrusted_input():
    command = build_journal_command(
        lines=50, search="; rm -rf /", since="1 hour ago", until=""
    )

    assert "journalctl --no-pager -n 50" in command
    assert "-g '; rm -rf /'" in command
    assert "--since '1 hour ago'" in command
    assert "--until" not in command


def test_build_journal_command_clamps_line_count():
    assert "-n 5000" in build_journal_command(lines=999_999, search="", since="", until="")
    assert "-n 1" in build_journal_command(lines=0, search="", since="", until="")


def test_build_file_command_plain_tail():
    command = build_file_command(path="/var/log/syslog", lines=100, search="")

    assert command == "tail -n 100 -- /var/log/syslog 2>/dev/null"


def test_build_file_command_with_search_greps_then_tails():
    command = build_file_command(path="/var/log/syslog", lines=50, search="error")

    assert command == "grep -F -- error /var/log/syslog 2>/dev/null | tail -n 50"


def test_build_file_command_quotes_a_path_with_spaces():
    command = build_file_command(path="/var/log/my app.log", lines=10, search="")

    assert "'/var/log/my app.log'" in command


def test_build_file_command_quotes_untrusted_search_term():
    command = build_file_command(path="/var/log/syslog", lines=10, search="$(whoami)")

    assert "'$(whoami)'" in command


def test_build_list_directory_command_quotes_the_path():
    command = build_list_directory_command("/var/log/my app")

    assert command == "ls -1p -- '/var/log/my app' 2>/dev/null"


def test_parse_directory_listing_splits_dirs_from_files():
    raw = "nginx/\nsyslog\nsyslog.1\ndocker/\n"

    entries = parse_directory_listing(raw)

    assert entries == [
        ("nginx", True),
        ("syslog", False),
        ("syslog.1", False),
        ("docker", True),
    ]


def test_parse_directory_listing_drops_hidden_entries():
    entries = parse_directory_listing(".hidden\n..\nvisible\n")

    assert entries == [("visible", False)]


def test_parse_directory_listing_handles_empty_output():
    assert parse_directory_listing("") == []
    assert parse_directory_listing("\n\n") == []
