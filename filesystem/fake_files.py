"""
LLMPot — Fake File Contents
Realistic content for common Linux system files.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from config import (FAKE_HOSTNAME, FAKE_OS_RELEASE, FAKE_KERNEL,
                    FAKE_ARCH, FAKE_IP_ADDRESS, FAKE_MAC_ADDRESS,
                    FAKE_UPTIME_DAYS)


def get_fake_content(path: str) -> str | None:
    """Return fake content for a known system file path."""
    contents = _get_all_contents()
    return contents.get(path)


def _get_all_contents() -> dict:
    """Build dictionary of all fake file contents."""
    return {
        "/etc/hostname": f"{FAKE_HOSTNAME}\n",

        "/etc/hosts": (
            f"127.0.0.1\tlocalhost\n"
            f"127.0.1.1\t{FAKE_HOSTNAME}\n"
            f"{FAKE_IP_ADDRESS}\t{FAKE_HOSTNAME}\n\n"
            f"# The following lines are desirable for IPv6 capable hosts\n"
            f"::1     ip6-localhost ip6-loopback\n"
            f"fe00::0 ip6-localnet\n"
            f"ff00::0 ip6-mcastprefix\n"
            f"ff02::1 ip6-allnodes\n"
            f"ff02::2 ip6-allrouters\n"
        ),

        "/etc/os-release": (
            f'PRETTY_NAME="{FAKE_OS_RELEASE}"\n'
            f'NAME="Ubuntu"\n'
            f'VERSION_ID="22.04"\n'
            f'VERSION="22.04.3 LTS (Jammy Jellyfish)"\n'
            f'VERSION_CODENAME=jammy\n'
            f'ID=ubuntu\n'
            f'ID_LIKE=debian\n'
            f'HOME_URL="https://www.ubuntu.com/"\n'
            f'SUPPORT_URL="https://help.ubuntu.com/"\n'
            f'BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"\n'
            f'PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"\n'
            f'UBUNTU_CODENAME=jammy\n'
        ),

        "/etc/passwd": (
            "root:x:0:0:root:/root:/bin/bash\n"
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
            "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
            "sync:x:4:65534:sync:/bin:/bin/sync\n"
            "games:x:5:60:games:/usr/games:/usr/sbin/nologin\n"
            "man:x:6:12:man:/var/cache/man:/usr/sbin/nologin\n"
            "lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\n"
            "mail:x:8:8:mail:/var/mail:/usr/sbin/nologin\n"
            "news:x:9:9:news:/var/spool/news:/usr/sbin/nologin\n"
            "uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin\n"
            "proxy:x:13:13:proxy:/bin:/usr/sbin/nologin\n"
            "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
            "backup:x:34:34:backup:/var/backups:/usr/sbin/nologin\n"
            "list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin\n"
            "irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin\n"
            "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
            "_apt:x:100:65534::/nonexistent:/usr/sbin/nologin\n"
            "systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin\n"
            "sshd:x:105:65534::/run/sshd:/usr/sbin/nologin\n"
            "admin:x:1000:1000:Server Admin:/home/admin:/bin/bash\n"
        ),

        "/etc/shadow": (
            "root:$6$rounds=656000$rANd0mSaLt$fakeHashThatLooksRealButIsNotReallyItJustNeedsToBeVeryLong:19700:0:99999:7:::\n"
            "daemon:*:19700:0:99999:7:::\n"
            "bin:*:19700:0:99999:7:::\n"
            "sys:*:19700:0:99999:7:::\n"
            "sync:*:19700:0:99999:7:::\n"
            "nobody:*:19700:0:99999:7:::\n"
            "sshd:*:19700:0:99999:7:::\n"
            "admin:$6$rounds=656000$aNoThErSaLt$anotherFakeHashThatShouldBeLongEnoughToLookRealistic:19700:0:99999:7:::\n"
        ),

        "/etc/group": (
            "root:x:0:\n"
            "daemon:x:1:\n"
            "bin:x:2:\n"
            "sys:x:3:\n"
            "adm:x:4:admin\n"
            "tty:x:5:\n"
            "disk:x:6:\n"
            "lp:x:7:\n"
            "mail:x:8:\n"
            "news:x:9:\n"
            "www-data:x:33:\n"
            "sudo:x:27:admin\n"
            "ssh:x:110:\n"
            "admin:x:1000:\n"
        ),

        "/etc/resolv.conf": (
            "# This file is managed by systemd-resolved\n"
            "nameserver 8.8.8.8\n"
            "nameserver 8.8.4.4\n"
            "search localdomain\n"
        ),

        "/etc/fstab": (
            "# /etc/fstab: static file system information.\n"
            "#\n"
            "# <file system>  <mount point>  <type>  <options>  <dump>  <pass>\n"
            "UUID=a1b2c3d4-e5f6-7890-abcd-ef1234567890 / ext4 errors=remount-ro 0 1\n"
            "/dev/sda2        /boot          ext4    defaults   0       2\n"
            "/dev/sda3        none           swap    sw         0       0\n"
            "tmpfs            /tmp           tmpfs   defaults,noexec,nosuid,nodev 0 0\n"
        ),

        "/etc/ssh/sshd_config": (
            "# OpenSSH Server Configuration\n"
            "Port 22\n"
            "AddressFamily any\n"
            "ListenAddress 0.0.0.0\n"
            "HostKey /etc/ssh/ssh_host_rsa_key\n"
            "HostKey /etc/ssh/ssh_host_ecdsa_key\n"
            "HostKey /etc/ssh/ssh_host_ed25519_key\n"
            "SyslogFacility AUTH\n"
            "LogLevel INFO\n"
            "LoginGraceTime 2m\n"
            "PermitRootLogin yes\n"
            "StrictModes yes\n"
            "MaxAuthTries 6\n"
            "PubkeyAuthentication yes\n"
            "PasswordAuthentication yes\n"
            "PermitEmptyPasswords no\n"
            "ChallengeResponseAuthentication no\n"
            "UsePAM yes\n"
            "X11Forwarding yes\n"
            "PrintMotd no\n"
            "AcceptEnv LANG LC_*\n"
            "Subsystem sftp /usr/lib/openssh/sftp-server\n"
        ),

        "/proc/cpuinfo": (
            "processor\t: 0\n"
            "vendor_id\t: GenuineIntel\n"
            "cpu family\t: 6\n"
            "model\t\t: 85\n"
            "model name\t: Intel(R) Xeon(R) Platinum 8175M CPU @ 2.50GHz\n"
            "stepping\t: 4\n"
            "microcode\t: 0x2006e05\n"
            "cpu MHz\t\t: 2499.998\n"
            "cache size\t: 33792 KB\n"
            "physical id\t: 0\n"
            "siblings\t: 2\n"
            "core id\t\t: 0\n"
            "cpu cores\t: 2\n"
            "apicid\t\t: 0\n"
            "fpu\t\t: yes\n"
            "fpu_exception\t: yes\n"
            "cpuid level\t: 13\n"
            "wp\t\t: yes\n"
            "bogomips\t: 4999.99\n"
            "clflush size\t: 64\n"
            "cache_alignment\t: 64\n"
            "address sizes\t: 46 bits physical, 48 bits virtual\n\n"
            "processor\t: 1\n"
            "vendor_id\t: GenuineIntel\n"
            "cpu family\t: 6\n"
            "model\t\t: 85\n"
            "model name\t: Intel(R) Xeon(R) Platinum 8175M CPU @ 2.50GHz\n"
            "stepping\t: 4\n"
            "microcode\t: 0x2006e05\n"
            "cpu MHz\t\t: 2499.998\n"
            "cache size\t: 33792 KB\n"
            "physical id\t: 0\n"
            "siblings\t: 2\n"
            "core id\t\t: 1\n"
            "cpu cores\t: 2\n"
            "bogomips\t: 4999.99\n"
        ),

        "/proc/meminfo": (
            "MemTotal:        4028440 kB\n"
            "MemFree:         1245320 kB\n"
            "MemAvailable:    2876544 kB\n"
            "Buffers:          234512 kB\n"
            "Cached:          1567892 kB\n"
            "SwapCached:            0 kB\n"
            "Active:          1789456 kB\n"
            "Inactive:         678432 kB\n"
            "SwapTotal:       2097148 kB\n"
            "SwapFree:        2097148 kB\n"
            "Dirty:                 0 kB\n"
            "Writeback:             0 kB\n"
            "AnonPages:        543216 kB\n"
            "Mapped:           234560 kB\n"
            "Shmem:             18976 kB\n"
        ),

        "/proc/version": (
            f"Linux version {FAKE_KERNEL} ({FAKE_HOSTNAME}) "
            f"(gcc version 11.4.0 (Ubuntu 11.4.0-1ubuntu1~22.04)) "
            f"#97-Ubuntu SMP PREEMPT_DYNAMIC Fri Jan 12 18:34:01 UTC 2024\n"
        ),

        "/proc/uptime": f"{FAKE_UPTIME_DAYS * 86400}.42 {FAKE_UPTIME_DAYS * 86400 * 0.85:.2f}\n",

        "/proc/loadavg": "0.08 0.12 0.15 1/234 12847\n",

        "/root/.bashrc": (
            "# ~/.bashrc: executed by bash(1) for non-login shells.\n\n"
            "# If not running interactively, don't do anything\n"
            "case $- in\n"
            "    *i*) ;;\n"
            "      *) return;;\n"
            "esac\n\n"
            "HISTCONTROL=ignoreboth\n"
            "HISTSIZE=1000\n"
            "HISTFILESIZE=2000\n"
            "shopt -s histappend\n"
            "shopt -s checkwinsize\n\n"
            'PS1=\'${debian_chroot:+($debian_chroot)}\\[\\033[01;31m\\]\\u@\\h\\[\\033[00m\\]:\\[\\033[01;34m\\]\\w\\[\\033[00m\\]\\# \'\n\n'
            "alias ls='ls --color=auto'\n"
            "alias ll='ls -alF'\n"
            "alias la='ls -A'\n"
            "alias l='ls -CF'\n"
        ),

        "/root/.bash_history": (
            "apt update\n"
            "apt upgrade -y\n"
            "systemctl status sshd\n"
            "tail -f /var/log/auth.log\n"
            "df -h\n"
            "free -m\n"
            "top\n"
            "netstat -tlnp\n"
            "iptables -L\n"
        ),

        "/home/admin/.bashrc": (
            "# ~/.bashrc: executed by bash(1) for non-login shells.\n\n"
            "case $- in\n"
            "    *i*) ;;\n"
            "      *) return;;\n"
            "esac\n\n"
            "HISTCONTROL=ignoreboth\n"
            'PS1=\'\\[\\033[01;32m\\]\\u@\\h\\[\\033[00m\\]:\\[\\033[01;34m\\]\\w\\[\\033[00m\\]\\$ \'\n\n'
            "alias ls='ls --color=auto'\n"
            "alias ll='ls -alF'\n"
        ),

        "/home/admin/.bash_history": (
            "cd /var/www/html\n"
            "ls -la\n"
            "sudo systemctl restart apache2\n"
            "cat /var/log/syslog\n"
            "df -h\n"
        ),

        "/home/admin/scripts/backup.sh": (
            "#!/bin/bash\n"
            "# Daily backup script\n"
            "BACKUP_DIR=/var/backups\n"
            "DATE=$(date +%Y%m%d)\n"
            "tar -czf $BACKUP_DIR/home_backup_$DATE.tar.gz /home/admin\n"
            "echo \"Backup completed: $DATE\"\n"
        ),

        "/home/admin/scripts/cleanup.sh": (
            "#!/bin/bash\n"
            "# Cleanup old logs\n"
            "find /var/log -name '*.gz' -mtime +30 -delete\n"
            "echo \"Cleanup completed\"\n"
        ),

        "/etc/crontab": (
            "# /etc/crontab: system-wide crontab\n"
            "SHELL=/bin/sh\n"
            "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n\n"
            "# m h dom mon dow user  command\n"
            "17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly\n"
            "25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )\n"
            "47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )\n"
            "52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )\n"
            "0  2    * * *   admin   /home/admin/scripts/backup.sh\n"
        ),

        "/var/log/auth.log": (
            "Jan 15 10:28:33 ubuntu-server sshd[1234]: Server listening on 0.0.0.0 port 22.\n"
            "Jan 15 10:28:33 ubuntu-server sshd[1234]: Server listening on :: port 22.\n"
            "Jan 15 10:30:12 ubuntu-server sshd[2345]: Accepted password for admin from 192.168.1.100 port 54321 ssh2\n"
            "Jan 15 10:30:12 ubuntu-server sshd[2345]: pam_unix(sshd:session): session opened for user admin\n"
            "Jan 15 10:45:01 ubuntu-server CRON[3456]: pam_unix(cron:session): session opened for user root\n"
            "Jan 15 11:02:33 ubuntu-server sshd[4567]: Failed password for invalid user test from 203.0.113.42 port 55432 ssh2\n"
            "Jan 15 11:02:35 ubuntu-server sshd[4567]: Failed password for invalid user admin from 203.0.113.42 port 55433 ssh2\n"
            "Jan 15 11:15:22 ubuntu-server sudo: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/usr/bin/apt update\n"
        ),

        "/var/log/syslog": (
            f"Jan 15 10:28:30 {FAKE_HOSTNAME} systemd[1]: Starting OpenBSD Secure Shell server...\n"
            f"Jan 15 10:28:33 {FAKE_HOSTNAME} systemd[1]: Started OpenBSD Secure Shell server.\n"
            f"Jan 15 10:28:33 {FAKE_HOSTNAME} systemd[1]: Reached target Multi-User System.\n"
            f"Jan 15 10:30:00 {FAKE_HOSTNAME} systemd[1]: Starting Daily apt download activities...\n"
            f"Jan 15 10:30:01 {FAKE_HOSTNAME} systemd[1]: Started Daily apt download activities.\n"
            f"Jan 15 10:45:01 {FAKE_HOSTNAME} CRON[3456]: (root) CMD (command -v debian-sa1 > /dev/null && debian-sa1 1 1)\n"
        ),

        "/var/www/html/index.html": (
            "<!DOCTYPE html>\n<html>\n<head>\n"
            "  <title>Apache2 Ubuntu Default Page</title>\n"
            "</head>\n<body>\n"
            "  <h1>Apache2 Ubuntu Default Page</h1>\n"
            "  <p>It works!</p>\n"
            "</body>\n</html>\n"
        ),

        "/etc/apt/sources.list": (
            "deb http://archive.ubuntu.com/ubuntu/ jammy main restricted\n"
            "deb http://archive.ubuntu.com/ubuntu/ jammy-updates main restricted\n"
            "deb http://archive.ubuntu.com/ubuntu/ jammy universe\n"
            "deb http://archive.ubuntu.com/ubuntu/ jammy-updates universe\n"
            "deb http://security.ubuntu.com/ubuntu jammy-security main restricted\n"
            "deb http://security.ubuntu.com/ubuntu jammy-security universe\n"
        ),

        "/etc/network/interfaces": (
            "# This file describes the network interfaces available on your system\n"
            "auto lo\n"
            "iface lo inet loopback\n\n"
            "auto eth0\n"
            "iface eth0 inet dhcp\n"
        ),

        "/run/sshd.pid": "1234\n",
    }
