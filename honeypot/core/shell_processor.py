"""
Shell Command Processor - Handles Linux shell commands for honeypot

Processes common Linux commands locally for fast, realistic responses.
Routes complex/unknown commands to LLM for dynamic generation.
"""

import re
import random
from typing import Dict, Tuple, Optional
from datetime import datetime
from core.fake_filesystem import get_filesystem, FakeFileSystem


class ShellProcessor:
    """
    Processes shell commands for the honeypot.
    
    Handles common Linux commands locally and routes unknown commands to LLM.
    """
    
    def __init__(self):
        self.command_history: Dict[str, list] = {}  # session_id -> [commands]
    
    def process_command(self, session_id: str, command: str, fs: Optional[FakeFileSystem] = None) -> Tuple[str, bool]:
        """
        Process a shell command.
        
        Returns:
            Tuple[str, bool]: (output, should_use_llm)
                - output: Command output or empty string if LLM should handle
                - should_use_llm: True if command should be routed to LLM
        """
        if not fs:
            fs = get_filesystem(session_id)
        
        # Add to history
        if session_id not in self.command_history:
            self.command_history[session_id] = []
        self.command_history[session_id].append(command)
        
        # Keep last 100 commands
        if len(self.command_history[session_id]) > 100:
            self.command_history[session_id] = self.command_history[session_id][-100:]
        
        command = command.strip()
        
        if not command:
            return "", False
        
        # Parse command and arguments
        parts = command.split()
        cmd = parts[0]
        args = parts[1:] if len(parts) > 1 else []
        
        # Route to appropriate handler
        handlers = {
            "ls": self._handle_ls,
            "cd": self._handle_cd,
            "pwd": self._handle_pwd,
            "cat": self._handle_cat,
            "whoami": self._handle_whoami,
            "hostname": self._handle_hostname,
            "uname": self._handle_uname,
            "id": self._handle_id,
            "echo": self._handle_echo,
            "clear": self._handle_clear,
            "history": self._handle_history,
            "env": self._handle_env,
            "printenv": self._handle_env,
            "ps": self._handle_ps,
            "top": self._handle_top,
            "netstat": self._handle_netstat,
            "ifconfig": self._handle_ifconfig,
            "ip": self._handle_ip,
            "find": self._handle_find,
            "grep": self._handle_grep,
            "head": self._handle_head,
            "tail": self._handle_tail,
            "touch": self._handle_touch,
            "mkdir": self._handle_mkdir,
            "rm": self._handle_rm,
            "cp": self._handle_cp,
            "mv": self._handle_mv,
            "wget": self._handle_wget,
            "curl": self._handle_curl,
            "ping": self._handle_ping,
            "sudo": self._handle_sudo,
            "su": self._handle_su,
        }
        
        if cmd in handlers:
            output = handlers[cmd](fs, args, session_id)
            return output, False
        
        # Unknown command - route to LLM
        return "", True
    
    def _handle_ls(self, fs: FakeFileSystem, args: list, session_id: str) -> str:
        """Handle ls command"""
        show_all = "-a" in args or "-la" in args or "-al" in args
        long_format = "-l" in args or "-la" in args or "-al" in args
        
        # Get path (last non-flag argument or current directory)
        path = "."
        for arg in args:
            if not arg.startswith("-"):
                path = arg
                break
        
        return fs.ls(path, show_all=show_all, long_format=long_format)
    
    def _handle_cd(self, fs: FakeFileSystem, args: list, session_id: str) -> str:
        """Handle cd command"""
        path = args[0] if args else "~"
        success, result = fs.cd(path)
        return "" if success else result
    
    def _handle_pwd(self, fs: FakeFileSystem, args: list, session_id: str) -> str:
        """Handle pwd command"""
        return fs.pwd()
    
    def _handle_cat(self, fs: FakeFileSystem, args: list, session_id: str) -> str:
        """Handle cat command"""
        if not args:
            return "cat: missing file operand"
        
        outputs = []
        for filename in args:
            outputs.append(fs.cat(filename))
        
        return "\n".join(outputs)
    
    def _handle_whoami(self, fs: FakeFileSystem, args: list, session_id: str) -> str:
        """Handle whoami command"""
        return fs.username
    
    def _handle_hostname(self, fs: FakeFileSystem, args: list, session_id: str) -> str:
        """Handle hostname command"""
        return fs.hostname
    
    def _handle_uname(self, fs: FakeFileSystem, args: list, session_id: str) -> str:
        """Handle uname command"""
        if "-a" in args or "--all" in args:
            return f"Linux {fs.hostname} 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux"
        elif "-r" in args:
            return "5.15.0-91-generic"
        elif "-s" in args or not args:
            return "Linux"
        elif "-n" in args:
            return fs.hostname
        elif "-m" in args:
            return "x86_64"
        else:
            return "Linux"
    
    def _handle_id(self, fs: FakeFileSystem, args: list, session_id: str) -> str:
        """Handle id command"""
        username = fs.username
        if username == "root":
            return "uid=0(root) gid=0(root) groups=0(root)"
        elif username == "admin":
            return "uid=1000(admin) gid=1000(admin) groups=1000(admin),27(sudo)"
        else:
            return f"uid=33({username}) gid=33({username}) groups=33({username})"
    
    def _handle_echo(self, fs: FakeFileSystem, args: list, session_id: str) -> str:
        """Handle echo command"""
        return " ".join(args)
    
    def _handle_clear(self, fs: FakeFileSystem, args: list, session_id: str) -> str:
        """Handle clear command"""
        return "\033[2J\033[H"  # ANSI escape codes to clear screen
    
    def _handle_history(self, fs: FakeFileSystem, args: list, session_id: str) -> str:
        """Handle history command"""
        if session_id not in self.command_history:
            return ""
        
        history = self.command_history[session_id]
        lines = []
        for i, cmd in enumerate(history, 1):
            lines.append(f"  {i}  {cmd}")
        
        return "\n".join(lines)
    
    def _handle_env(self, fs: FakeFileSystem, args: list, session_id: str) -> str:
        """Handle env/printenv command"""
        env_vars = {
            "USER": fs.username,
            "HOME": f"/home/{fs.username}" if fs.username != "root" else "/root",
            "SHELL": "/bin/bash",
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "PWD": fs.pwd(),
            "LANG": "en_US.UTF-8",
            "HOSTNAME": fs.hostname,
            "TERM": "xterm-256color",
        }
        
        lines = [f"{key}={value}" for key, value in env_vars.items()]
        return "\n".join(lines)
    
    def _handle_ps(self, fs: FakeFileSystem, args: list, session_id: str) -> str:
        """Handle ps command"""
        show_all = "aux" in " ".join(args) or "-e" in args or "-A" in args
        
        if show_all:
            return """USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.1 169564 13140 ?        Ss   Dec22   0:03 /sbin/init
root       123  0.0  0.0  12345  1234 ?        Ss   Dec22   0:00 /usr/sbin/sshd -D
www-data   456  0.5  2.3 456789 45678 ?        S    15:30   0:15 nginx: worker process
www-data   457  0.3  1.8 345678 34567 ?        S    15:30   0:10 php-fpm: pool www
mysql      789  1.2  5.4 987654 98765 ?        Ssl  Dec22   2:30 /usr/sbin/mysqld
root      1234  0.0  0.1  23456  2345 pts/0    Ss   16:00   0:00 -bash
www-data  5678  0.0  0.0  12345  1234 pts/0    R+   16:05   0:00 ps aux"""
        else:
            return """  PID TTY          TIME CMD
 1234 pts/0    00:00:00 bash
 5678 pts/0    00:00:00 ps"""
    
    def _handle_top(self, fs: FakeFileSystem, args: list, session_id: str) -> str:
        """Handle top command"""
        return """top - 16:05:23 up 1 day,  2:35,  1 user,  load average: 0.15, 0.20, 0.18
Tasks: 156 total,   1 running, 155 sleeping,   0 stopped,   0 zombie
%Cpu(s):  2.3 us,  1.1 sy,  0.0 ni, 96.2 id,  0.3 wa,  0.0 hi,  0.1 si,  0.0 st
MiB Mem :   7982.5 total,   1234.2 free,   3456.7 used,   3291.6 buff/cache
MiB Swap:   2048.0 total,   2048.0 free,      0.0 used.   4123.4 avail Mem

  PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND
  789 mysql     20   0  987654  98765  12345 S   1.2   5.4   2:30.45 mysqld
  456 www-data  20   0  456789  45678   8901 S   0.5   2.3   0:15.23 nginx
  457 www-data  20   0  345678  34567   7890 S   0.3   1.8   0:10.12 php-fpm"""
    
    def _handle_netstat(self, fs: FakeFileSystem, args: list, session_id: str) -> str:
        """Handle netstat command"""
        if "-tulpn" in " ".join(args) or "-tuln" in " ".join(args):
            return """Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      123/sshd
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      456/nginx
tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN      456/nginx
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      789/mysqld
tcp        0      0 127.0.0.1:6379          0.0.0.0:*               LISTEN      890/redis-server"""
        else:
            return """Active Internet connections
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN"""
    
    def _handle_ifconfig(self, fs: FakeFileSystem, args: list, session_id: str) -> str:
        """Handle ifconfig command"""
        return """eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 192.168.1.100  netmask 255.255.255.0  broadcast 192.168.1.255
        inet6 fe80::a00:27ff:fe4e:66a1  prefixlen 64  scopeid 0x20<link>
        ether 08:00:27:4e:66:a1  txqueuelen 1000  (Ethernet)
        RX packets 12345  bytes 1234567 (1.2 MB)
        TX packets 6789  bytes 987654 (987.6 KB)

lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)"""
    
    def _handle_ip(self, fs: FakeFileSystem, args: list, session_id: str) -> str:
        """Handle ip command"""
        if "addr" in args or "a" in args:
            return """1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    inet 127.0.0.1/8 scope host lo
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    inet 192.168.1.100/24 brd 192.168.1.255 scope global eth0"""
        else:
            return "Usage: ip [ OPTIONS ] OBJECT { COMMAND | help }"
    
    def _handle_find(self, fs: FakeFileSystem, args: list, session_id: str) -> str:
        """Handle find command"""
        path = "."
        name_pattern = "*"
        
        # Parse arguments
        for i, arg in enumerate(args):
            if arg == "-name" and i + 1 < len(args):
                name_pattern = args[i + 1].strip('"\'')
            elif not arg.startswith("-") and i == 0:
                path = arg
        
        return fs.find(path, name_pattern)
    
    def _handle_grep(self, fs: FakeFileSystem, args: list, session_id: str) -> str:
        """Handle grep command (simplified)"""
        if len(args) < 2:
            return "grep: missing operand"
        
        pattern = args[0]
        filename = args[1]
        
        content = fs.cat(filename)
        if "No such file" in content:
            return content
        
        # Simple grep - find lines containing pattern
        lines = content.split("\n")
        matches = [line for line in lines if pattern.lower() in line.lower()]
        
        return "\n".join(matches) if matches else ""
    
    def _handle_head(self, fs: FakeFileSystem, args: list, session_id: str) -> str:
        """Handle head command"""
        if not args:
            return "head: missing file operand"
        
        filename = args[-1]
        lines = 10
        
        if "-n" in args:
            idx = args.index("-n")
            if idx + 1 < len(args):
                try:
                    lines = int(args[idx + 1])
                except ValueError:
                    pass
        
        content = fs.cat(filename)
        if "No such file" in content:
            return content
        
        return "\n".join(content.split("\n")[:lines])
    
    def _handle_tail(self, fs: FakeFileSystem, args: list, session_id: str) -> str:
        """Handle tail command"""
        if not args:
            return "tail: missing file operand"
        
        filename = args[-1]
        lines = 10
        
        if "-n" in args:
            idx = args.index("-n")
            if idx + 1 < len(args):
                try:
                    lines = int(args[idx + 1])
                except ValueError:
                    pass
        
        content = fs.cat(filename)
        if "No such file" in content:
            return content
        
        return "\n".join(content.split("\n")[-lines:])
    
    def _handle_touch(self, fs: FakeFileSystem, args: list, session_id: str) -> str:
        """Handle touch command"""
        if not args:
            return "touch: missing file operand"
        
        return f"touch: cannot touch '{args[0]}': Permission denied"
    
    def _handle_mkdir(self, fs: FakeFileSystem, args: list, session_id: str) -> str:
        """Handle mkdir command"""
        if not args:
            return "mkdir: missing operand"
        
        return f"mkdir: cannot create directory '{args[0]}': Permission denied"
    
    def _handle_rm(self, fs: FakeFileSystem, args: list, session_id: str) -> str:
        """Handle rm command"""
        if not args:
            return "rm: missing operand"
        
        return f"rm: cannot remove '{args[-1]}': Permission denied"
    
    def _handle_cp(self, fs: FakeFileSystem, args: list, session_id: str) -> str:
        """Handle cp command"""
        if len(args) < 2:
            return "cp: missing destination file operand"
        
        return f"cp: cannot create regular file '{args[-1]}': Permission denied"
    
    def _handle_mv(self, fs: FakeFileSystem, args: list, session_id: str) -> str:
        """Handle mv command"""
        if len(args) < 2:
            return "mv: missing destination file operand"
        
        return f"mv: cannot move '{args[0]}' to '{args[-1]}': Permission denied"
    
    def _handle_wget(self, fs: FakeFileSystem, args: list, session_id: str) -> str:
        """Handle wget command"""
        if not args:
            return "wget: missing URL"
        
        url = args[0]
        filename = url.split("/")[-1] or "index.html"
        
        return f"""--{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}--  {url}
Resolving {url.split('/')[2]}... 93.184.216.34
Connecting to {url.split('/')[2]}|93.184.216.34|:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1256 (1.2K) [text/html]
Saving to: '{filename}'

{filename}          100%[===================>]   1.23K  --.-KB/s    in 0s

{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ({random.randint(100, 999)} KB/s) - '{filename}' saved [1256/1256]"""
    
    def _handle_curl(self, fs: FakeFileSystem, args: list, session_id: str) -> str:
        """Handle curl command"""
        if not args:
            return "curl: try 'curl --help' for more information"
        
        url = args[0]
        
        # Simulate HTTP response
        return f"""<!DOCTYPE html>
<html>
<head><title>Example Domain</title></head>
<body>
<h1>Example Domain</h1>
<p>This domain is for use in illustrative examples.</p>
</body>
</html>"""
    
    def _handle_ping(self, fs: FakeFileSystem, args: list, session_id: str) -> str:
        """Handle ping command"""
        if not args:
            return "ping: usage error: Destination address required"
        
        host = args[0]
        
        return f"""PING {host} (93.184.216.34) 56(84) bytes of data.
64 bytes from {host} (93.184.216.34): icmp_seq=1 ttl=56 time=12.3 ms
64 bytes from {host} (93.184.216.34): icmp_seq=2 ttl=56 time=11.8 ms
64 bytes from {host} (93.184.216.34): icmp_seq=3 ttl=56 time=12.1 ms

--- {host} ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms
rtt min/avg/max/mdev = 11.8/12.1/12.3/0.2 ms"""
    
    def _handle_sudo(self, fs: FakeFileSystem, args: list, session_id: str) -> str:
        """Handle sudo command"""
        if not args:
            return "sudo: a command must be specified"
        
        # Simulate sudo password prompt
        return f"[sudo] password for {fs.username}: \nSorry, try again.\n[sudo] password for {fs.username}: \nsudo: 3 incorrect password attempts"
    
    def _handle_su(self, fs: FakeFileSystem, args: list, session_id: str) -> str:
        """Handle su command"""
        target_user = args[0] if args else "root"
        return f"su: Authentication failure"
    
    def get_prompt(self, fs: FakeFileSystem) -> str:
        """Generate shell prompt"""
        username = fs.username
        hostname = fs.hostname
        cwd = fs.pwd()
        
        # Shorten home directory to ~
        if cwd.startswith(f"/home/{username}"):
            cwd = cwd.replace(f"/home/{username}", "~")
        
        # Root gets # prompt, others get $
        prompt_char = "#" if username == "root" else "$"
        
        return f"{username}@{hostname}:{cwd}{prompt_char} "


shell_processor = ShellProcessor()
