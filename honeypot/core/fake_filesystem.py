"""
Fake File System - Simulates a realistic Linux file system for honeypot

Provides an in-memory file system with realistic directories, files, and permissions.
Each session gets its own file system instance for isolation.
"""

import time
from typing import Dict, List, Optional, Tuple
from datetime import datetime


class FakeFile:
    """Represents a file in the fake file system"""
    
    def __init__(self, name: str, content: str = "", permissions: str = "-rw-r--r--", owner: str = "root"):
        self.name = name
        self.content = content
        self.permissions = permissions
        self.owner = owner
        self.group = "root"
        self.size = len(content)
        self.modified = datetime.now()
    
    def __repr__(self):
        return f"<File {self.name} ({self.size} bytes)>"


class FakeDirectory:
    """Represents a directory in the fake file system"""
    
    def __init__(self, name: str, permissions: str = "drwxr-xr-x", owner: str = "root"):
        self.name = name
        self.permissions = permissions
        self.owner = owner
        self.group = "root"
        self.files: Dict[str, FakeFile] = {}
        self.subdirs: Dict[str, 'FakeDirectory'] = {}
        self.modified = datetime.now()
    
    def add_file(self, file: FakeFile):
        """Add a file to this directory"""
        self.files[file.name] = file
        self.modified = datetime.now()
    
    def add_subdir(self, directory: 'FakeDirectory'):
        """Add a subdirectory"""
        self.subdirs[directory.name] = directory
        self.modified = datetime.now()
    
    def __repr__(self):
        return f"<Dir {self.name} ({len(self.files)} files, {len(self.subdirs)} dirs)>"


class FakeFileSystem:
    """
    Simulates a Linux file system with realistic structure and files.
    Each session gets its own instance.
    """
    
    def __init__(self, session_id: str):
        self.session_id = session_id
        self.root = FakeDirectory("/")
        self.current_path = "/"
        self.hostname = "techshop-prod-01"
        self.username = "www-data"
        self._initialize_filesystem()
    
    def _initialize_filesystem(self):
        """Create realistic Linux directory structure with fake sensitive files"""
        
        # /etc directory with config files
        etc = FakeDirectory("etc")
        etc.add_file(FakeFile("passwd", self._generate_passwd_file()))
        etc.add_file(FakeFile("shadow", self._generate_shadow_file(), permissions="-rw-------"))
        etc.add_file(FakeFile("hostname", f"{self.hostname}\n"))
        etc.add_file(FakeFile("hosts", "127.0.0.1\tlocalhost\n127.0.1.1\ttechshop-prod-01\n"))
        etc.add_file(FakeFile("resolv.conf", "nameserver 8.8.8.8\nnameserver 8.8.4.4\n"))
        
        # /etc/ssh
        ssh_dir = FakeDirectory("ssh")
        ssh_dir.add_file(FakeFile("sshd_config", self._generate_sshd_config()))
        ssh_dir.add_file(FakeFile("ssh_host_rsa_key", "-----BEGIN PRIVATE KEY-----\nFAKE_KEY_DATA\n-----END PRIVATE KEY-----\n", permissions="-rw-------"))
        etc.add_subdir(ssh_dir)
        
        self.root.add_subdir(etc)
        
        # /home directory with user files
        home = FakeDirectory("home")
        
        # /home/admin
        admin_home = FakeDirectory("admin", owner="admin")
        admin_home.add_file(FakeFile(".bash_history", "ls -la\ncd /var/www\nsudo systemctl restart nginx\n", owner="admin"))
        admin_home.add_file(FakeFile(".bashrc", "# .bashrc\nexport PATH=$PATH:/usr/local/bin\n", owner="admin"))
        
        # /home/admin/.ssh
        admin_ssh = FakeDirectory(".ssh", permissions="drwx------", owner="admin")
        admin_ssh.add_file(FakeFile("id_rsa", self._generate_fake_ssh_key(), permissions="-rw-------", owner="admin"))
        admin_ssh.add_file(FakeFile("id_rsa.pub", "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC... admin@techshop\n", owner="admin"))
        admin_ssh.add_file(FakeFile("authorized_keys", "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQD... deploy@ci-server\n", owner="admin"))
        admin_home.add_subdir(admin_ssh)
        
        home.add_subdir(admin_home)
        self.root.add_subdir(home)
        
        # /var directory
        var = FakeDirectory("var")
        
        # /var/www - web application files
        www = FakeDirectory("www", owner="www-data")
        
        # /var/www/html
        html = FakeDirectory("html", owner="www-data")
        html.add_file(FakeFile("index.html", "<html><body><h1>TechShop - E-Commerce Platform</h1></body></html>", owner="www-data"))
        www.add_subdir(html)
        
        # /var/www/techshop
        techshop = FakeDirectory("techshop", owner="www-data")
        techshop.add_file(FakeFile(".env", self._generate_env_file(), permissions="-rw-------", owner="www-data"))
        techshop.add_file(FakeFile("config.php", self._generate_config_php(), owner="www-data"))
        techshop.add_file(FakeFile("database.yml", self._generate_database_yml(), owner="www-data"))
        www.add_subdir(techshop)
        
        var.add_subdir(www)
        
        # /var/log
        log = FakeDirectory("log")
        log.add_file(FakeFile("auth.log", "Dec 23 15:30:12 techshop sshd[1234]: Accepted publickey for admin from 192.168.1.100\n"))
        log.add_file(FakeFile("nginx-access.log", "192.168.1.50 - - [23/Dec/2025:15:30:00 +0000] \"GET /products HTTP/1.1\" 200\n"))
        var.add_subdir(log)
        
        self.root.add_subdir(var)
        
        # /usr directory
        usr = FakeDirectory("usr")
        usr_bin = FakeDirectory("bin")
        usr_bin.add_file(FakeFile("python3", "[binary]", permissions="-rwxr-xr-x"))
        usr_bin.add_file(FakeFile("node", "[binary]", permissions="-rwxr-xr-x"))
        usr.add_subdir(usr_bin)
        self.root.add_subdir(usr)
        
        # /tmp directory
        tmp = FakeDirectory("tmp", permissions="drwxrwxrwt")
        self.root.add_subdir(tmp)
    
    def _generate_passwd_file(self) -> str:
        """Generate realistic /etc/passwd content"""
        return """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
admin:x:1000:1000:Admin User:/home/admin:/bin/bash
mysql:x:111:116:MySQL Server:/nonexistent:/bin/false
postgres:x:112:117:PostgreSQL:/var/lib/postgresql:/bin/bash
"""
    
    def _generate_shadow_file(self) -> str:
        """Generate realistic /etc/shadow content (fake hashes)"""
        return """root:$6$fake.hash.root:19000:0:99999:7:::
admin:$6$fake.hash.admin:19000:0:99999:7:::
www-data:*:19000:0:99999:7:::
"""
    
    def _generate_sshd_config(self) -> str:
        """Generate SSH daemon config"""
        return """Port 22
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
"""
    
    def _generate_fake_ssh_key(self) -> str:
        """Generate fake SSH private key"""
        return """-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEAyFAKE9fake_key_data_here_not_real
-----END OPENSSH PRIVATE KEY-----
"""
    
    def _generate_env_file(self) -> str:
        """Generate fake .env file with credentials"""
        return """# TechShop Environment Configuration
APP_ENV=production
APP_DEBUG=false
APP_KEY=base64:FakeKeyHere123456789==

DB_CONNECTION=mysql
DB_HOST=localhost
DB_PORT=3306
DB_DATABASE=techshop_prod
DB_USERNAME=techshop_user
DB_PASSWORD=Pr0d_P@ssw0rd_2025!

REDIS_HOST=127.0.0.1
REDIS_PASSWORD=R3d1s_S3cr3t!
REDIS_PORT=6379

MAIL_MAILER=smtp
MAIL_HOST=smtp.gmail.com
MAIL_PORT=587
MAIL_USERNAME=noreply@techshop.com
MAIL_PASSWORD=EmailP@ss123

AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_DEFAULT_REGION=us-east-1
"""
    
    def _generate_config_php(self) -> str:
        """Generate fake PHP config file"""
        return """<?php
define('DB_HOST', 'localhost');
define('DB_USER', 'techshop_user');
define('DB_PASS', 'Pr0d_P@ssw0rd_2025!');
define('DB_NAME', 'techshop_prod');

define('API_KEY', 'sk_live_51FakeApiKey123456789');
define('SECRET_KEY', 'whsec_FakeWebhookSecret987654321');
?>
"""
    
    def _generate_database_yml(self) -> str:
        """Generate fake database.yml"""
        return """production:
  adapter: postgresql
  encoding: unicode
  database: techshop_production
  pool: 5
  username: techshop
  password: Db_Pr0d_P@ss!
  host: localhost
"""
    
    def _resolve_path(self, path: str) -> str:
        """Resolve relative/absolute paths"""
        if path.startswith("/"):
            return path
        
        # Relative path
        if self.current_path == "/":
            return f"/{path}"
        return f"{self.current_path}/{path}"
    
    def _get_directory(self, path: str) -> Optional[FakeDirectory]:
        """Get directory object from path"""
        path = self._resolve_path(path)
        
        if path == "/":
            return self.root
        
        parts = [p for p in path.split("/") if p]
        current = self.root
        
        for part in parts:
            if part == "..":
                # Go up one level (simplified, doesn't handle properly)
                continue
            if part in current.subdirs:
                current = current.subdirs[part]
            else:
                return None
        
        return current
    
    def ls(self, path: str = ".", show_all: bool = False, long_format: bool = False) -> str:
        """List directory contents"""
        target_path = path if path != "." else self.current_path
        directory = self._get_directory(target_path)
        
        if not directory:
            return f"ls: cannot access '{path}': No such file or directory"
        
        items = []
        
        # Add subdirectories
        for name, subdir in sorted(directory.subdirs.items()):
            if not show_all and name.startswith("."):
                continue
            
            if long_format:
                items.append(f"{subdir.permissions}  2 {subdir.owner} {subdir.group}  4096 {subdir.modified.strftime('%b %d %H:%M')} {name}/")
            else:
                items.append(f"{name}/")
        
        # Add files
        for name, file in sorted(directory.files.items()):
            if not show_all and name.startswith("."):
                continue
            
            if long_format:
                items.append(f"{file.permissions}  1 {file.owner} {file.group}  {file.size:>5} {file.modified.strftime('%b %d %H:%M')} {name}")
            else:
                items.append(name)
        
        if not items:
            return ""
        
        if long_format:
            return "\n".join(items)
        else:
            # Multi-column output
            return "  ".join(items)
    
    def cd(self, path: str) -> Tuple[bool, str]:
        """Change directory"""
        if path == "~":
            path = f"/home/{self.username}"
        elif path == "..":
            if self.current_path != "/":
                self.current_path = "/".join(self.current_path.rstrip("/").split("/")[:-1]) or "/"
            return True, self.current_path
        
        target_path = self._resolve_path(path)
        directory = self._get_directory(target_path)
        
        if not directory:
            return False, f"cd: {path}: No such file or directory"
        
        self.current_path = target_path
        return True, self.current_path
    
    def pwd(self) -> str:
        """Print working directory"""
        return self.current_path
    
    def cat(self, filename: str) -> str:
        """Read file contents"""
        # Check if it's a path
        if "/" in filename:
            path_parts = filename.rsplit("/", 1)
            dir_path = path_parts[0] if path_parts[0] else "/"
            file_name = path_parts[1]
        else:
            dir_path = self.current_path
            file_name = filename
        
        directory = self._get_directory(dir_path)
        
        if not directory:
            return f"cat: {filename}: No such file or directory"
        
        if file_name in directory.files:
            return directory.files[file_name].content
        
        return f"cat: {filename}: No such file or directory"
    
    def find(self, path: str = ".", name_pattern: str = "*") -> str:
        """Find files matching pattern (simplified)"""
        results = []
        
        def search_dir(dir_obj: FakeDirectory, current_path: str):
            # Search files
            for fname in dir_obj.files:
                if name_pattern == "*" or name_pattern in fname:
                    results.append(f"{current_path}/{fname}")
            
            # Search subdirectories
            for dname, subdir in dir_obj.subdirs.items():
                new_path = f"{current_path}/{dname}"
                if name_pattern == "*" or name_pattern in dname:
                    results.append(new_path)
                search_dir(subdir, new_path)
        
        start_dir = self._get_directory(path)
        if start_dir:
            search_dir(start_dir, path if path != "." else self.current_path)
        
        return "\n".join(results) if results else ""
    
    def whoami(self) -> str:
        """Return current username"""
        return self.username
    
    def hostname(self) -> str:
        """Return hostname"""
        return self.hostname


# Session-based file system storage
_filesystems: Dict[str, FakeFileSystem] = {}


def get_filesystem(session_id: str) -> FakeFileSystem:
    """Get or create file system for session"""
    if session_id not in _filesystems:
        _filesystems[session_id] = FakeFileSystem(session_id)
    return _filesystems[session_id]
