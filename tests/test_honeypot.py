"""
LLMPot — Honeypot Unit Tests
"""

import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from honeypot.auth_handler import AuthHandler
from honeypot.command_processor import CommandProcessor
from filesystem.vfs import VirtualFilesystem


class TestAuthHandler:
    """Test authentication handling."""

    def setup_method(self):
        self.auth = AuthHandler()

    def test_known_credentials_accepted(self):
        assert self.auth.check_credentials("root", "root", "1.2.3.4") is True

    def test_known_credentials_admin(self):
        assert self.auth.check_credentials("admin", "admin", "1.2.3.5") is True

    def test_wrong_password_rejected(self):
        # With AUTH_ACCEPT_PROBABILITY > 0, this might occasionally pass
        # Run multiple times to check — at least some should be rejected
        results = [
            self.auth.check_credentials("root", "xYz!impossible#99", f"10.0.0.{i}")
            for i in range(20)
        ]
        # At least some should be rejected (with prob 0.15, ~17/20 rejected)
        assert results.count(False) > 10

    def test_attempt_counting(self):
        ip = "5.5.5.5"
        self.auth.check_credentials("root", "wrong", ip)
        self.auth.check_credentials("root", "wrong2", ip)
        assert self.auth.get_attempt_count(ip) == 2

    def test_reset_attempts(self):
        ip = "6.6.6.6"
        self.auth.check_credentials("root", "wrong", ip)
        self.auth.reset_attempts(ip)
        assert self.auth.get_attempt_count(ip) == 0


class TestCommandProcessor:
    """Test command processing."""

    def setup_method(self):
        self.vfs = VirtualFilesystem()
        self.proc = CommandProcessor(self.vfs, "root")

    def test_whoami(self):
        output, exit_flag = self.proc.process("whoami")
        assert output == "root"
        assert exit_flag is False

    def test_id_root(self):
        output, _ = self.proc.process("id")
        assert "uid=0(root)" in output

    def test_uname(self):
        output, _ = self.proc.process("uname")
        assert output == "Linux"

    def test_uname_a(self):
        output, _ = self.proc.process("uname -a")
        assert "Linux" in output
        assert "ubuntu-server" in output

    def test_hostname(self):
        output, _ = self.proc.process("hostname")
        assert output == "ubuntu-server"

    def test_pwd(self):
        output, _ = self.proc.process("pwd")
        assert output == "/root"

    def test_cd_tmp(self):
        self.proc.process("cd /tmp")
        output, _ = self.proc.process("pwd")
        assert output == "/tmp"

    def test_ls(self):
        output, _ = self.proc.process("ls /etc")
        assert "passwd" in output
        assert "hostname" in output

    def test_cat_passwd(self):
        output, _ = self.proc.process("cat /etc/passwd")
        assert "root:x:0:0" in output

    def test_unknown_command(self):
        output, _ = self.proc.process("nonexistent_cmd_xyz")
        assert "command not found" in output

    def test_exit(self):
        _, exit_flag = self.proc.process("exit")
        assert exit_flag is True

    def test_echo(self):
        output, _ = self.proc.process("echo hello world")
        assert output == "hello world"

    def test_date(self):
        output, _ = self.proc.process("date")
        assert len(output) > 10  # Should be a date string

    def test_df(self):
        output, _ = self.proc.process("df -h")
        assert "/dev/sda1" in output

    def test_prompt(self):
        prompt = self.proc.get_prompt()
        assert "root@" in prompt
        assert "#" in prompt

    def test_chained_commands(self):
        output, _ = self.proc.process("whoami; hostname")
        assert "root" in output
        assert "ubuntu-server" in output

    def test_pipe_handling(self):
        output, _ = self.proc.process("cat /etc/passwd | head")
        assert "root" in output
