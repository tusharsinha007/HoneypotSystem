"""
LLMPot — VFS Unit Tests
"""

import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from filesystem.vfs import VirtualFilesystem


class TestVirtualFilesystem:
    """Test the virtual filesystem."""

    def setup_method(self):
        self.vfs = VirtualFilesystem()

    def test_initial_cwd(self):
        assert self.vfs.get_pwd() == "/root"

    def test_root_exists(self):
        assert self.vfs.exists("/")
        assert self.vfs.is_dir("/")

    def test_etc_exists(self):
        assert self.vfs.exists("/etc")
        assert self.vfs.is_dir("/etc")

    def test_passwd_is_file(self):
        assert self.vfs.exists("/etc/passwd")
        assert self.vfs.is_file("/etc/passwd")

    def test_nonexistent_path(self):
        assert not self.vfs.exists("/nonexistent/path")

    def test_chdir_valid(self):
        success, _ = self.vfs.chdir("/tmp")
        assert success
        assert self.vfs.get_pwd() == "/tmp"

    def test_chdir_invalid(self):
        success, error = self.vfs.chdir("/fake_directory_xyz")
        assert not success
        assert "No such file" in error

    def test_chdir_to_file(self):
        success, error = self.vfs.chdir("/etc/passwd")
        assert not success
        assert "Not a directory" in error

    def test_chdir_dotdot(self):
        self.vfs.chdir("/etc/ssh")
        self.vfs.chdir("..")
        assert self.vfs.get_pwd() == "/etc"

    def test_listdir_etc(self):
        output = self.vfs.listdir("/etc")
        assert "passwd" in output
        assert "hostname" in output

    def test_listdir_long(self):
        output = self.vfs.listdir("/etc", long_format=True)
        assert "total" in output
        assert "root" in output

    def test_listdir_hidden(self):
        output_no_hidden = self.vfs.listdir("/root", show_hidden=False)
        output_with_hidden = self.vfs.listdir("/root", show_hidden=True)
        assert ".bashrc" not in output_no_hidden
        assert ".bashrc" in output_with_hidden

    def test_read_file(self):
        content = self.vfs.read_file("/etc/passwd")
        assert "root:x:0:0" in content

    def test_read_file_not_found(self):
        content = self.vfs.read_file("/etc/nonexistent")
        assert "No such file" in content

    def test_read_directory(self):
        content = self.vfs.read_file("/etc")
        assert "Is a directory" in content

    def test_create_file(self):
        success, _ = self.vfs.create_file("/tmp/test.txt", "hello")
        assert success
        assert self.vfs.exists("/tmp/test.txt")
        content = self.vfs.read_file("/tmp/test.txt")
        assert content == "hello"

    def test_create_dir(self):
        success, _ = self.vfs.create_dir("/tmp/testdir")
        assert success
        assert self.vfs.is_dir("/tmp/testdir")

    def test_remove_runtime_file(self):
        self.vfs.create_file("/tmp/deleteme.txt")
        success, _ = self.vfs.remove("/tmp/deleteme.txt")
        assert success

    def test_relative_path(self):
        self.vfs.chdir("/etc")
        assert self.vfs.exists("passwd")

    def test_home_dir(self):
        assert self.vfs.exists("/home/admin")
        assert self.vfs.is_dir("/home/admin")
