"""
LLMPot — Command Processor
Emulates ~30 common Linux commands with realistic output.
"""

import random
import time as time_module
from datetime import datetime, timedelta
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config import (FAKE_HOSTNAME, FAKE_KERNEL, FAKE_ARCH, FAKE_OS_RELEASE,
                    FAKE_IP_ADDRESS, FAKE_MAC_ADDRESS, FAKE_UPTIME_DAYS)
from filesystem.vfs import VirtualFilesystem
from utils.logger import get_logger

logger = get_logger("cmdproc")


class CommandProcessor:
    """Processes shell commands in the honeypot, returning fake output."""

    def __init__(self, vfs: VirtualFilesystem, username: str = "root"):
        self.vfs = vfs
        self.username = username
        self.hostname = FAKE_HOSTNAME
        self.env = {
            "HOME": "/root" if username == "root" else f"/home/{username}",
            "USER": username,
            "SHELL": "/bin/bash",
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "en_US.UTF-8",
            "TERM": "xterm-256color",
            "PWD": "/root" if username == "root" else f"/home/{username}",
        }
        self.history = []
        self._command_map = self._build_command_map()

    def _build_command_map(self) -> dict:
        """Map command names to handler functions."""
        return {
            "ls": self._cmd_ls,
            "dir": self._cmd_ls,
            "cd": self._cmd_cd,
            "pwd": self._cmd_pwd,
            "cat": self._cmd_cat,
            "echo": self._cmd_echo,
            "whoami": self._cmd_whoami,
            "id": self._cmd_id,
            "uname": self._cmd_uname,
            "hostname": self._cmd_hostname,
            "ifconfig": self._cmd_ifconfig,
            "ip": self._cmd_ip,
            "ps": self._cmd_ps,
            "top": self._cmd_top,
            "df": self._cmd_df,
            "free": self._cmd_free,
            "w": self._cmd_w,
            "uptime": self._cmd_uptime,
            "date": self._cmd_date,
            "history": self._cmd_history,
            "wget": self._cmd_wget,
            "curl": self._cmd_curl,
            "chmod": self._cmd_chmod,
            "chown": self._cmd_chown,
            "mkdir": self._cmd_mkdir,
            "rm": self._cmd_rm,
            "cp": self._cmd_cp,
            "mv": self._cmd_mv,
            "touch": self._cmd_touch,
            "exit": self._cmd_exit,
            "quit": self._cmd_exit,
            "logout": self._cmd_exit,
            "clear": self._cmd_clear,
            "env": self._cmd_env,
            "export": self._cmd_export,
            "unset": self._cmd_unset,
            "head": self._cmd_head,
            "tail": self._cmd_tail,
            "grep": self._cmd_grep,
            "find": self._cmd_find,
            "which": self._cmd_which,
            "type": self._cmd_type,
            "wc": self._cmd_wc,
            "netstat": self._cmd_netstat,
            "ss": self._cmd_ss,
            "ping": self._cmd_ping,
            "crontab": self._cmd_crontab,
            "service": self._cmd_service,
            "systemctl": self._cmd_systemctl,
            "apt": self._cmd_apt,
            "apt-get": self._cmd_apt,
            "nmap": self._cmd_nmap,
            "dd": self._cmd_dd,
            "passwd": self._cmd_passwd,
            "useradd": self._cmd_useradd,
            "su": self._cmd_su,
            "sudo": self._cmd_sudo,
        }

    def process(self, command_line: str) -> tuple:
        """
        Process a command line.
        Returns: (output: str, should_exit: bool)
        """
        command_line = command_line.strip()
        if not command_line:
            return "", False

        # Record in history
        self.history.append(command_line)

        # Handle pipes and redirections (simulate)
        if "|" in command_line:
            # Process first command only, ignore pipe
            command_line = command_line.split("|")[0].strip()

        if ">" in command_line and ">>" not in command_line:
            parts = command_line.split(">", 1)
            command_line = parts[0].strip()
            # Pretend to write to file
            if len(parts) > 1:
                target_file = parts[1].strip()
                self.vfs.create_file(target_file, "")

        # Handle && and ;
        if "&&" in command_line:
            results = []
            for sub_cmd in command_line.split("&&"):
                output, should_exit = self.process(sub_cmd.strip())
                results.append(output)
                if should_exit:
                    return "\n".join(filter(None, results)), True
            return "\n".join(filter(None, results)), False

        if ";" in command_line:
            results = []
            for sub_cmd in command_line.split(";"):
                output, should_exit = self.process(sub_cmd.strip())
                results.append(output)
                if should_exit:
                    return "\n".join(filter(None, results)), True
            return "\n".join(filter(None, results)), False

        # Parse command and arguments
        parts = command_line.split()
        cmd = parts[0]
        args = parts[1:]

        # Look up handler
        handler = self._command_map.get(cmd)
        if handler:
            try:
                return handler(args)
            except Exception as e:
                logger.error(f"Error processing command '{cmd}': {e}")
                return "", False

        # Unknown command
        return f"bash: {cmd}: command not found", False

    def get_prompt(self) -> str:
        """Return the shell prompt string."""
        cwd = self.vfs.get_pwd()
        if cwd == self.env.get("HOME", "/root"):
            cwd_display = "~"
        else:
            cwd_display = cwd

        if self.username == "root":
            return f"root@{self.hostname}:{cwd_display}# "
        return f"{self.username}@{self.hostname}:{cwd_display}$ "

    # ─── Command Implementations ─────────────────────────────────────────────

    def _cmd_ls(self, args: list) -> tuple:
        long_format = False
        show_hidden = False
        target = None

        for arg in args:
            if arg.startswith("-"):
                if "l" in arg:
                    long_format = True
                if "a" in arg:
                    show_hidden = True
            else:
                target = arg

        output = self.vfs.listdir(target, long_format=long_format,
                                  show_hidden=show_hidden)
        return output, False

    def _cmd_cd(self, args: list) -> tuple:
        if not args:
            target = self.env.get("HOME", "/root")
        elif args[0] == "-":
            target = self.env.get("OLDPWD", self.vfs.get_pwd())
        elif args[0] == "~":
            target = self.env.get("HOME", "/root")
        else:
            target = args[0]

        old_pwd = self.vfs.get_pwd()
        success, error = self.vfs.chdir(target)
        if success:
            self.env["OLDPWD"] = old_pwd
            self.env["PWD"] = self.vfs.get_pwd()
            return "", False
        return error, False

    def _cmd_pwd(self, args: list) -> tuple:
        return self.vfs.get_pwd(), False

    def _cmd_cat(self, args: list) -> tuple:
        if not args:
            return "", False
        results = []
        for f in args:
            if f.startswith("-"):
                continue
            content = self.vfs.read_file(f)
            results.append(content)
        return "\n".join(results), False

    def _cmd_echo(self, args: list) -> tuple:
        text = " ".join(args)
        # Handle variable substitution
        for var, val in self.env.items():
            text = text.replace(f"${var}", val)
            text = text.replace(f"${{{var}}}", val)
        # Remove quotes
        text = text.strip("'\"")
        return text, False

    def _cmd_whoami(self, args: list) -> tuple:
        return self.username, False

    def _cmd_id(self, args: list) -> tuple:
        if self.username == "root":
            return "uid=0(root) gid=0(root) groups=0(root)", False
        return (f"uid=1000({self.username}) gid=1000({self.username}) "
                f"groups=1000({self.username}),4(adm),27(sudo)"), False

    def _cmd_uname(self, args: list) -> tuple:
        if not args:
            return "Linux", False
        if "-a" in args or "--all" in args:
            return (f"Linux {FAKE_HOSTNAME} {FAKE_KERNEL} "
                    f"#97-Ubuntu SMP PREEMPT_DYNAMIC Fri Jan 12 18:34:01 UTC 2024 "
                    f"{FAKE_ARCH} {FAKE_ARCH} {FAKE_ARCH} GNU/Linux"), False
        if "-r" in args:
            return FAKE_KERNEL, False
        if "-n" in args:
            return FAKE_HOSTNAME, False
        if "-m" in args:
            return FAKE_ARCH, False
        if "-s" in args:
            return "Linux", False
        return "Linux", False

    def _cmd_hostname(self, args: list) -> tuple:
        return FAKE_HOSTNAME, False

    def _cmd_ifconfig(self, args: list) -> tuple:
        return (
            f"eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
            f"        inet {FAKE_IP_ADDRESS}  netmask 255.255.255.0  broadcast 10.0.0.255\n"
            f"        inet6 fe80::42:acff:fe11:2  prefixlen 64  scopeid 0x20<link>\n"
            f"        ether {FAKE_MAC_ADDRESS}  txqueuelen 1000  (Ethernet)\n"
            f"        RX packets 1542876  bytes 987654321 (987.6 MB)\n"
            f"        TX packets 1234567  bytes 567890123 (567.8 MB)\n\n"
            f"lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n"
            f"        inet 127.0.0.1  netmask 255.0.0.0\n"
            f"        inet6 ::1  prefixlen 128  scopeid 0x10<host>\n"
            f"        loop  txqueuelen 1000  (Local Loopback)\n"
        ), False

    def _cmd_ip(self, args: list) -> tuple:
        if not args or args[0] == "addr" or args[0] == "a":
            return (
                f"1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN\n"
                f"    inet 127.0.0.1/8 scope host lo\n"
                f"    inet6 ::1/128 scope host\n"
                f"2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP\n"
                f"    inet {FAKE_IP_ADDRESS}/24 brd 10.0.0.255 scope global eth0\n"
                f"    inet6 fe80::42:acff:fe11:2/64 scope link\n"
            ), False
        if args[0] == "route" or args[0] == "r":
            return (
                f"default via 10.0.0.1 dev eth0 proto dhcp src {FAKE_IP_ADDRESS}\n"
                f"10.0.0.0/24 dev eth0 proto kernel scope link src {FAKE_IP_ADDRESS}\n"
            ), False
        return f"Usage: ip [ addr | route ]", False

    def _cmd_ps(self, args: list) -> tuple:
        show_all = any("-e" in a or "-A" in a or "aux" in a for a in args)
        procs = [
            "    PID TTY          TIME CMD",
            "      1 ?        00:00:05 systemd",
            "      2 ?        00:00:00 kthreadd",
        ]
        if show_all:
            procs += [
                "    234 ?        00:00:01 systemd-journal",
                "    345 ?        00:00:00 systemd-udevd",
                "    567 ?        00:00:03 sshd",
                "    678 ?        00:00:00 cron",
                "    789 ?        00:00:05 rsyslogd",
                "    890 ?        00:00:01 apache2",
                "   1023 ?        00:00:00 sshd: root@pts/0",
                f"   1045 pts/0    00:00:00 bash",
                f"   {random.randint(2000, 9999)} pts/0    00:00:00 ps",
            ]
        else:
            procs += [
                f"   1045 pts/0    00:00:00 bash",
                f"   {random.randint(2000, 9999)} pts/0    00:00:00 ps",
            ]
        return "\n".join(procs), False

    def _cmd_top(self, args: list) -> tuple:
        uptime_str = f"up {FAKE_UPTIME_DAYS} days, 13:42"
        return (
            f"top - {datetime.now().strftime('%H:%M:%S')} {uptime_str},  "
            f"1 user,  load average: 0.08, 0.12, 0.15\n"
            f"Tasks: 127 total,   1 running, 126 sleeping,   0 stopped,   0 zombie\n"
            f"%Cpu(s):  2.3 us,  0.7 sy,  0.0 ni, 96.8 id,  0.1 wa,  0.0 hi,  0.1 si\n"
            f"MiB Mem :   3934.0 total,   1216.1 free,    847.5 used,   1870.4 buff/cache\n"
            f"MiB Swap:   2048.0 total,   2048.0 free,      0.0 used.   2809.1 avail Mem\n\n"
            f"    PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND\n"
            f"    890 www-data  20   0  274732  12844   8896 S   1.3   0.3   0:05.23 apache2\n"
            f"    567 root      20   0   15852   5632   4864 S   0.3   0.1   0:03.45 sshd\n"
            f"      1 root      20   0  167892  11456   8320 S   0.0   0.3   0:05.12 systemd\n"
        ), False

    def _cmd_df(self, args: list) -> tuple:
        human = any("-h" in a for a in args)
        if human:
            return (
                "Filesystem      Size  Used Avail Use% Mounted on\n"
                "/dev/sda1        47G   12G   33G  27% /\n"
                "tmpfs           2.0G     0  2.0G   0% /dev/shm\n"
                "/dev/sda2       976M  149M  760M  17% /boot\n"
                "tmpfs           395M  1.1M  394M   1% /run\n"
                "tmpfs           5.0M     0  5.0M   0% /run/lock\n"
            ), False
        return (
            "Filesystem     1K-blocks     Used Available Use% Mounted on\n"
            "/dev/sda1       49152000 12582912  34603008  27% /\n"
            "tmpfs            2028440        0   2028440   0% /dev/shm\n"
            "/dev/sda2         999320   152576    777932  17% /boot\n"
        ), False

    def _cmd_free(self, args: list) -> tuple:
        human = any("-h" in a for a in args)
        if human or any("-m" in a for a in args):
            return (
                "               total        used        free      shared  buff/cache   available\n"
                "Mem:           3.8Gi       847Mi       1.2Gi        19Mi       1.8Gi       2.7Gi\n"
                "Swap:          2.0Gi          0B       2.0Gi\n"
            ), False
        return (
            "               total        used        free      shared  buff/cache   available\n"
            "Mem:         4028440      867840     1245320       19456     1915280     2876544\n"
            "Swap:        2097148           0     2097148\n"
        ), False

    def _cmd_w(self, args: list) -> tuple:
        now = datetime.now().strftime("%H:%M:%S")
        return (
            f" {now} up {FAKE_UPTIME_DAYS} days, 13:42,  1 user,  "
            f"load average: 0.08, 0.12, 0.15\n"
            f"USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT\n"
            f"{self.username:8s} pts/0    10.0.0.1         {now}    0.00s  0.01s  0.00s w\n"
        ), False

    def _cmd_uptime(self, args: list) -> tuple:
        now = datetime.now().strftime("%H:%M:%S")
        return (
            f" {now} up {FAKE_UPTIME_DAYS} days, 13:42,  1 user,  "
            f"load average: 0.08, 0.12, 0.15"
        ), False

    def _cmd_date(self, args: list) -> tuple:
        return datetime.now().strftime("%a %b %d %H:%M:%S UTC %Y"), False

    def _cmd_history(self, args: list) -> tuple:
        lines = []
        for i, cmd in enumerate(self.history, 1):
            lines.append(f"  {i:4d}  {cmd}")
        return "\n".join(lines), False

    def _cmd_wget(self, args: list) -> tuple:
        if not args:
            return "wget: missing URL\nUsage: wget [OPTION]... [URL]...", False
        url = args[-1]
        time_module.sleep(0.5)  # Simulate download delay
        return (
            f"--{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}--  {url}\n"
            f"Resolving {url.split('/')[2] if '/' in url else url}... "
            f"failed: Temporary failure in name resolution.\n"
            f"wget: unable to resolve host address '{url.split('/')[2] if '/' in url else url}'"
        ), False

    def _cmd_curl(self, args: list) -> tuple:
        if not args:
            return "curl: try 'curl --help' for more information", False
        url = args[-1]
        time_module.sleep(0.3)
        return (
            f"curl: (6) Could not resolve host: "
            f"{url.split('/')[2] if '/' in url else url}"
        ), False

    def _cmd_chmod(self, args: list) -> tuple:
        if len(args) < 2:
            return "chmod: missing operand", False
        return "", False  # Silently succeed

    def _cmd_chown(self, args: list) -> tuple:
        if len(args) < 2:
            return "chown: missing operand", False
        return "", False

    def _cmd_mkdir(self, args: list) -> tuple:
        for arg in args:
            if arg.startswith("-"):
                continue
            self.vfs.create_dir(arg)
        return "", False

    def _cmd_rm(self, args: list) -> tuple:
        for arg in args:
            if arg.startswith("-"):
                continue
            self.vfs.remove(arg)
        return "", False

    def _cmd_cp(self, args: list) -> tuple:
        if len(args) < 2:
            return "cp: missing file operand", False
        return "", False

    def _cmd_mv(self, args: list) -> tuple:
        if len(args) < 2:
            return "mv: missing file operand", False
        return "", False

    def _cmd_touch(self, args: list) -> tuple:
        for arg in args:
            if arg.startswith("-"):
                continue
            self.vfs.create_file(arg)
        return "", False

    def _cmd_exit(self, args: list) -> tuple:
        return "logout", True

    def _cmd_clear(self, args: list) -> tuple:
        return "\033[2J\033[H", False

    def _cmd_env(self, args: list) -> tuple:
        lines = [f"{k}={v}" for k, v in self.env.items()]
        return "\n".join(lines), False

    def _cmd_export(self, args: list) -> tuple:
        for arg in args:
            if "=" in arg:
                key, val = arg.split("=", 1)
                self.env[key] = val.strip("'\"")
        return "", False

    def _cmd_unset(self, args: list) -> tuple:
        for arg in args:
            self.env.pop(arg, None)
        return "", False

    def _cmd_head(self, args: list) -> tuple:
        if not args:
            return "", False
        target = args[-1]
        content = self.vfs.read_file(target)
        lines = content.split("\n")[:10]
        return "\n".join(lines), False

    def _cmd_tail(self, args: list) -> tuple:
        if not args:
            return "", False
        target = args[-1]
        content = self.vfs.read_file(target)
        lines = content.split("\n")[-10:]
        return "\n".join(lines), False

    def _cmd_grep(self, args: list) -> tuple:
        if len(args) < 2:
            return "Usage: grep [OPTION]... PATTERN [FILE]...", False
        pattern = args[0]
        target = args[-1]
        content = self.vfs.read_file(target)
        matches = [l for l in content.split("\n") if pattern in l]
        return "\n".join(matches), False

    def _cmd_find(self, args: list) -> tuple:
        return f"find: This command is not fully supported", False

    def _cmd_which(self, args: list) -> tuple:
        results = []
        for cmd in args:
            if cmd in self._command_map:
                results.append(f"/usr/bin/{cmd}")
            else:
                results.append(f"{cmd} not found")
        return "\n".join(results), False

    def _cmd_type(self, args: list) -> tuple:
        results = []
        for cmd in args:
            if cmd in self._command_map:
                results.append(f"{cmd} is /usr/bin/{cmd}")
            else:
                results.append(f"bash: type: {cmd}: not found")
        return "\n".join(results), False

    def _cmd_wc(self, args: list) -> tuple:
        if not args:
            return "", False
        target = args[-1]
        content = self.vfs.read_file(target)
        lines = content.count("\n")
        words = len(content.split())
        chars = len(content)
        return f"  {lines}  {words} {chars} {target}", False

    def _cmd_netstat(self, args: list) -> tuple:
        return (
            "Active Internet connections (servers and established)\n"
            "Proto Recv-Q Send-Q Local Address           Foreign Address         State\n"
            "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\n"
            "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\n"
            "tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN\n"
            f"tcp        0     36 {FAKE_IP_ADDRESS}:22          10.0.0.1:54321          ESTABLISHED\n"
        ), False

    def _cmd_ss(self, args: list) -> tuple:
        return self._cmd_netstat(args)

    def _cmd_ping(self, args: list) -> tuple:
        if not args:
            return "ping: usage error: Destination address required", False
        host = args[-1]
        time_module.sleep(0.5)
        return (
            f"PING {host} ({host}) 56(84) bytes of data.\n"
            f"--- {host} ping statistics ---\n"
            f"3 packets transmitted, 0 received, 100% packet loss, time 2003ms\n"
        ), False

    def _cmd_crontab(self, args: list) -> tuple:
        if "-l" in args:
            return "no crontab for " + self.username, False
        return "", False

    def _cmd_service(self, args: list) -> tuple:
        if len(args) < 2:
            return "Usage: service <service> <action>", False
        return f" * {args[1]}ing {args[0]}...  [ OK ]", False

    def _cmd_systemctl(self, args: list) -> tuple:
        if len(args) < 2:
            return "Usage: systemctl <action> <service>", False
        action = args[0]
        service = args[1]
        if action == "status":
            return (
                f"● {service}.service - {service}\n"
                f"     Loaded: loaded (/lib/systemd/system/{service}.service; enabled)\n"
                f"     Active: active (running) since Mon 2024-01-15 10:28:33 UTC; "
                f"{FAKE_UPTIME_DAYS} days ago\n"
                f"   Main PID: 567 ({service})\n"
                f"      Tasks: 1 (limit: 4915)\n"
                f"     Memory: 4.5M\n"
                f"        CPU: 3.456s\n"
            ), False
        return "", False

    def _cmd_apt(self, args: list) -> tuple:
        if not args:
            return "Usage: apt [options] command", False
        if args[0] == "update":
            time_module.sleep(0.5)
            return (
                "Hit:1 http://archive.ubuntu.com/ubuntu jammy InRelease\n"
                "Hit:2 http://archive.ubuntu.com/ubuntu jammy-updates InRelease\n"
                "Hit:3 http://security.ubuntu.com/ubuntu jammy-security InRelease\n"
                "Reading package lists... Done\n"
                "Building dependency tree... Done\n"
                "All packages are up to date.\n"
            ), False
        if args[0] == "install":
            time_module.sleep(0.3)
            return "E: Could not open lock file - open (13: Permission denied)", False
        return "", False

    def _cmd_nmap(self, args: list) -> tuple:
        return "bash: nmap: command not found", False

    def _cmd_dd(self, args: list) -> tuple:
        return "dd: must specify input and output", False

    def _cmd_passwd(self, args: list) -> tuple:
        return "Changing password for root.\nNew password: ", False

    def _cmd_useradd(self, args: list) -> tuple:
        if not args:
            return "Usage: useradd [options] LOGIN", False
        return "", False

    def _cmd_su(self, args: list) -> tuple:
        return "", False

    def _cmd_sudo(self, args: list) -> tuple:
        if not args:
            return "usage: sudo [-h] command", False
        # Execute the sub-command
        return self.process(" ".join(args))
