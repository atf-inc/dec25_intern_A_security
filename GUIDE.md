# QuantumShield - Complete Setup Guide for Kali Linux

This guide will walk you through setting up QuantumShield from scratch on Kali Linux, including installation of all open-source security tools and dependencies.

---

## 📋 Table of Contents

1. [Prerequisites](#prerequisites)
2. [System Requirements](#system-requirements)
3. [Initial System Setup](#initial-system-setup)
4. [Installing Open-Source Security Tools](#installing-open-source-security-tools)
5. [Database Setup](#database-setup)
6. [Python Environment Setup](#python-environment-setup)
7. [QuantumShield Installation](#quantumshield-installation)
8. [Configuration](#configuration)
9. [Running QuantumShield](#running-quantumshield)
10. [Verification & Testing](#verification--testing)
11. [Troubleshooting](#troubleshooting)

---

## 🔧 Prerequisites

- **Operating System**: Kali Linux 2023.x or later
- **User**: Root or sudo access required
- **Internet**: Active internet connection
- **Disk Space**: Minimum 20GB free space
- **RAM**: Minimum 8GB (16GB recommended)
- **Network Interface**: At least one network interface for packet capture

---

## 💻 System Requirements

### Minimum Requirements
- **CPU**: 4 cores (8+ recommended)
- **RAM**: 8GB (16GB+ recommended for ML models)
- **Storage**: 50GB free space
- **Network**: 1Gbps network interface

### Recommended for Production
- **CPU**: 8+ cores
- **RAM**: 32GB+
- **Storage**: 200GB+ SSD
- **Network**: 10Gbps network interface
- **GPU**: NVIDIA GPU (optional, for ML acceleration)

---

## 🚀 Initial System Setup

### Step 1: Update Kali Linux

```bash
# Update package list
sudo apt update

# Upgrade system packages
sudo apt upgrade -y

# Install essential build tools
sudo apt install -y \
    build-essential \
    git \
    curl \
    wget \
    vim \
    net-tools \
    software-properties-common \
    apt-transport-https \
    ca-certificates \
    gnupg \
    lsb-release
```

### Step 2: Install System Dependencies

```bash
# Install network and packet capture tools
sudo apt install -y \
    tcpdump \
    libpcap-dev \
    libpcap0.8 \
    libnet1-dev \
    libnetfilter-queue-dev \
    libnfnetlink-dev \
    libnids-dev \
    libnids3.23 \
    libdumbnet-dev \
    libdumbnet1 \
    libdaq-dev \
    libdaq2 \
    libprelude-dev \
    libprelude2 \
    libluajit-5.1-dev \
    libyaml-dev \
    libjansson-dev \
    libmagic-dev \
    libgeoip-dev \
    libhiredis-dev \
    libpcre3-dev \
    libpcre2-dev \
    zlib1g-dev \
    libssl-dev \
    libffi-dev \
    libxml2-dev \
    libxslt1-dev \
    python3-dev \
    python3-pip \
    python3-venv \
    pkg-config \
    autoconf \
    automake \
    libtool \
    flex \
    bison \
    cmake \
    make \
    gcc \
    g++ \
    gdb
```

### Step 3: Install Database Dependencies

```bash
# Install PostgreSQL and TimescaleDB dependencies
sudo apt install -y \
    postgresql \
    postgresql-contrib \
    postgresql-server-dev-all \
    libpq-dev \
    redis-server \
    redis-tools

# Install TimescaleDB repository
sudo sh -c "echo 'deb https://packagecloud.io/timescale/timescaledb/debian/ $(lsb_release -c -s) main' > /etc/apt/sources.list.d/timescaledb.list"
wget --quiet -O - https://packagecloud.io/timescale/timescaledb/gpgkey | sudo apt-key add -
sudo apt update
sudo apt install -y timescaledb-2-postgresql-15
```

---

## 🛠️ Installing Open-Source Security Tools

### Tool 1: Suricata IDS/IPS

```bash
# Install Suricata dependencies
sudo apt install -y \
    libpcre3 \
    libpcre3-dbg \
    libpcre3-dev \
    build-essential \
    libpcap-dev \
    libnet1-dev \
    libyaml-0-2 \
    libyaml-dev \
    zlib1g \
    zlib1g-dev \
    libcap-ng-dev \
    libcap-ng0 \
    make \
    libmagic-dev \
    libjansson-dev \
    libnss3-dev \
    libgeoip-dev \
    liblua5.1-dev \
    libhiredis-dev \
    libevent-dev \
    python-yaml \
    rustc \
    cargo

# Download and compile Suricata
cd /tmp
wget https://www.openinfosecfoundation.org/download/suricata-7.0.0.tar.gz
tar -xzf suricata-7.0.0.tar.gz
cd suricata-7.0.0

# Configure and compile
./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var \
    --enable-nfqueue --enable-lua --enable-geoip --enable-hiredis

make
sudo make install
sudo make install-conf
sudo make install-rules

# Create necessary directories
sudo mkdir -p /var/log/suricata
sudo mkdir -p /etc/suricata/rules
sudo chown -R suricata:suricata /var/log/suricata

# Download rules
sudo suricata-update

# Verify installation
suricata -V
```

### Tool 2: Snort IDS/IPS

```bash
# Install Snort dependencies
sudo apt install -y \
    libpcap-dev \
    libpcre3-dev \
    libdumbnet-dev \
    zlib1g-dev \
    liblzma-dev \
    openssl \
    libssl-dev \
    libnghttp2-dev \
    libluajit-5.1-dev \
    libdnet \
    libdumbnet \
    libdaq-dev

# Download and compile Snort
cd /tmp
wget https://www.snort.org/downloads/snort/snort-2.9.20.tar.gz
tar -xzf snort-2.9.20.tar.gz
cd snort-2.9.20

# Configure and compile
./configure --enable-sourcefire
make
sudo make install

# Create directories
sudo mkdir -p /etc/snort/rules
sudo mkdir -p /var/log/snort

# Download rules (requires registration on snort.org)
# Or use community rules:
cd /tmp
wget https://www.snort.org/rules/community -O community-rules.tar.gz
tar -xzf community-rules.tar.gz
sudo cp community-rules/* /etc/snort/rules/

# Verify installation
snort -V
```

### Tool 3: Zeek (Bro) Network Security Monitor

```bash
# Install Zeek dependencies
sudo apt install -y \
    cmake \
    make \
    gcc \
    g++ \
    flex \
    bison \
    libpcap-dev \
    libssl-dev \
    python3-dev \
    swig \
    zlib1g-dev \
    libmaxminddb-dev \
    libcurl4-openssl-dev

# Download and compile Zeek
cd /opt
sudo git clone --recursive https://github.com/zeek/zeek.git
cd zeek
sudo ./configure --prefix=/opt/zeek
sudo make
sudo make install

# Add to PATH
echo 'export PATH=/opt/zeek/bin:$PATH' | sudo tee -a /etc/profile
source /etc/profile

# Create log directory
sudo mkdir -p /opt/zeek/logs
sudo chown -R $USER:$USER /opt/zeek/logs

# Verify installation
zeek --version
```

### Tool 4: OSSEC HIDS

```bash
# Install OSSEC dependencies
sudo apt install -y \
    build-essential \
    libssl-dev \
    libpcre2-dev \
    zlib1g-dev \
    make \
    gcc \
    inotify-tools

# Download and install OSSEC
cd /tmp
wget https://github.com/ossec/ossec-hids/releases/download/3.7.0/ossec-hids-3.7.0.tar.gz
tar -xzf ossec-hids-3.7.0.tar.gz
cd ossec-hids-3.7.0

# Install
sudo ./install.sh
# Follow the interactive installer:
# - Type: server
# - Installation path: /var/ossec
# - Email notification: your-email@example.com
# - Default settings for rest

# Start OSSEC
sudo /var/ossec/bin/ossec-control start

# Verify installation
sudo /var/ossec/bin/ossec-control status
```

### Tool 5: Fail2Ban

```bash
# Install Fail2Ban
sudo apt install -y fail2ban

# Create local configuration
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local

# Edit configuration (optional)
sudo nano /etc/fail2ban/jail.local

# Start and enable Fail2Ban
sudo systemctl enable fail2ban
sudo systemctl start fail2ban

# Verify installation
sudo fail2ban-client status
```

### Tool 6: ModSecurity WAF

```bash
# Install ModSecurity dependencies
sudo apt install -y \
    libapache2-mod-security2 \
    modsecurity-crs \
    apache2

# Enable ModSecurity
sudo a2enmod security2
sudo a2enmod rewrite
sudo a2enmod headers

# Configure ModSecurity
sudo cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf

# Download OWASP Core Rule Set
cd /tmp
sudo git clone https://github.com/coreruleset/coreruleset.git /etc/modsecurity/coreruleset
cd /etc/modsecurity/coreruleset
sudo cp crs-setup.conf.example /etc/modsecurity/crs-setup.conf

# Restart Apache
sudo systemctl restart apache2

# Verify installation
apache2ctl -M | grep security
```

### Tool 7: IPTables/NFTables

```bash
# IPTables is usually pre-installed on Kali Linux
# Verify installation
iptables --version

# Install NFTables (modern alternative)
sudo apt install -y nftables

# Verify installation
nft --version

# Note: IPTables is used by QuantumShield for blocking
# No additional configuration needed at this stage
```

### Tool 8: ClamAV Antivirus

```bash
# Install ClamAV
sudo apt install -y \
    clamav \
    clamav-daemon \
    clamav-freshclam \
    clamav-unofficial-sigs

# Update virus definitions
sudo freshclam

# Start ClamAV daemon
sudo systemctl enable clamav-daemon
sudo systemctl start clamav-daemon

# Verify installation
clamdscan --version
```

### Tool 9: nDPI (Deep Packet Inspection)

```bash
# Install nDPI dependencies
sudo apt install -y \
    libpcap-dev \
    libjson-c-dev \
    libgcrypt20-dev \
    libtool \
    autoconf \
    automake \
    make \
    gcc \
    g++

# Download and compile nDPI
cd /tmp
git clone https://github.com/ntop/nDPI.git
cd nDPI
./autogen.sh
./configure
make
sudo make install

# Update library cache
sudo ldconfig

# Verify installation
ndpiReader --help
```

### Tool 10: Wazuh SIEM

```bash
# Install Wazuh dependencies
sudo apt install -y \
    curl \
    apt-transport-https \
    lsb-release \
    gnupg2

# Add Wazuh repository
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --no-default-keyring --keyring /usr/share/keyrings/wazuh.gpg --import
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list

# Update and install Wazuh
sudo apt update
sudo apt install -y wazuh-manager

# Start Wazuh
sudo systemctl daemon-reload
sudo systemctl enable wazuh-manager
sudo systemctl start wazuh-manager

# Install Wazuh API (optional)
sudo apt install -y wazuh-api

# Verify installation
sudo systemctl status wazuh-manager
```

---

## 🗄️ Database Setup

### Step 1: Configure PostgreSQL

```bash
# Start PostgreSQL
sudo systemctl enable postgresql
sudo systemctl start postgresql

# Set password for postgres user
sudo -u postgres psql -c "ALTER USER postgres PASSWORD 'your_secure_password';"

# Create QuantumShield database
sudo -u postgres psql << EOF
CREATE DATABASE quantumshield;
CREATE USER quantum WITH PASSWORD 'quantum_password';
GRANT ALL PRIVILEGES ON DATABASE quantumshield TO quantum;
\q
EOF

# Configure TimescaleDB
sudo timescaledb-tune --quiet --yes
sudo systemctl restart postgresql
```

### Step 2: Configure TimescaleDB Extension

```bash
# Connect to database and enable TimescaleDB
sudo -u postgres psql -d quantumshield << EOF
CREATE EXTENSION IF NOT EXISTS timescaledb;
\q
EOF
```

### Step 3: Configure Redis

```bash
# Edit Redis configuration
sudo nano /etc/redis/redis.conf

# Set the following:
# bind 127.0.0.1
# requirepass your_redis_password

# Restart Redis
sudo systemctl restart redis-server

# Test Redis connection
redis-cli -a your_redis_password ping
```

---

## 🐍 Python Environment Setup

### Step 1: Create Virtual Environment

```bash
# Navigate to project directory
cd ~/Desktop/AITF_IPS/quantumshield

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Upgrade pip
pip install --upgrade pip setuptools wheel
```

### Step 2: Install Python Dependencies

```bash
# Install system-level dependencies for Python packages
sudo apt install -y \
    libpq-dev \
    python3-dev \
    libffi-dev \
    libssl-dev \
    libxml2-dev \
    libxslt1-dev \
    libjpeg-dev \
    zlib1g-dev \
    libblas-dev \
    liblapack-dev \
    libatlas-base-dev \
    gfortran

# Install Python packages
pip install -r requirements.txt

# If you encounter issues with specific packages, install them individually:
# pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cpu
# pip install tensorflow
```

### Step 3: Install Additional Python Packages for Tools

```bash
# Install packages for tool integrations
pip install \
    pcapy-ng \
    python-nfqueue \
    netifaces \
    python-whois \
    dnspython \
    cryptography \
    aiohttp \
    python-json-logger
```

---

## 📦 QuantumShield Installation

### Step 1: Clone/Setup Project

```bash
# If not already cloned, clone the repository
# cd ~/Desktop/AITF_IPS
# git clone <repository-url> quantumshield

# Navigate to project
cd ~/Desktop/AITF_IPS/quantumshield

# Make scripts executable
chmod +x scripts/*.sh
```

### Step 2: Create Project Structure

```bash
# Run structure creation script
./scripts/create_structure.sh

# Or manually create directories
mkdir -p logs models datasets/{raw,processed,labeled}
```

### Step 3: Install QuantumShield Package

```bash
# Activate virtual environment (if not already active)
source venv/bin/activate

# Install in development mode
pip install -e .

# Or install directly
pip install .
```

---

## ⚙️ Configuration

### Step 1: Create Environment File

```bash
# Copy example environment file
cp .env.example .env

# Edit environment file
nano .env
```

### Step 2: Configure Environment Variables

Edit `.env` with your settings:

```bash
# General Settings
ENVIRONMENT=development
LOG_LEVEL=INFO
DEBUG=false

# Network Interface (find your interface with: ip link show)
CAPTURE_INTERFACE=eth0
PROMISCUOUS_MODE=true

# Database Configuration
DB_HOST=localhost
DB_PORT=5432
DB_NAME=quantumshield
DB_USER=quantum
DB_PASSWORD=quantum_password

# Redis Configuration
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=your_redis_password
REDIS_DB=0

# ML Model Settings
ML_MODELS_DIR=./models
ML_DEVICE=cpu
ML_BATCH_SIZE=32
ML_ENABLE_GPU=false

# Security Tool Paths (verify these paths)
SURICATA_PATH=/usr/bin/suricata
SNORT_PATH=/usr/bin/snort
ZEEK_PATH=/opt/zeek/bin/zeek
OSSEC_PATH=/var/ossec
FAIL2BAN_PATH=/etc/fail2ban
MODSECURITY_PATH=/etc/modsecurity
CLAMAV_SOCKET=/var/run/clamav/clamd.ctl

# Detection Engines
ENABLE_SIGNATURE_DETECTION=true
ENABLE_ANOMALY_DETECTION=true
ENABLE_BEHAVIORAL_DETECTION=true
ENABLE_ML_DETECTION=true

# Response Settings
AUTO_BLOCK_ENABLED=true
RATE_LIMIT_ENABLED=true
ALERT_EMAIL_ENABLED=false
ALERT_WEBHOOK_ENABLED=false

# API Settings
API_HOST=0.0.0.0
API_PORT=8080
API_SECRET_KEY=$(openssl rand -hex 32)
API_ENABLE_AUTH=true
```

### Step 3: Configure Security Tools

#### Configure Suricata

```bash
# Edit Suricata configuration
sudo nano /etc/suricata/suricata.yaml

# Update interface name
# Change: interface: eth0
# To your interface name (check with: ip link show)

# Update rule paths
# default-rule-path: /etc/suricata/rules

# Test configuration
sudo suricata -T -c /etc/suricata/suricata.yaml
```

#### Configure Snort

```bash
# Edit Snort configuration
sudo nano /etc/snort/snort.conf

# Update network variables
# var HOME_NET any
# var EXTERNAL_NET !$HOME_NET

# Update rule paths
# var RULE_PATH /etc/snort/rules

# Test configuration
sudo snort -T -c /etc/snort/snort.conf
```

#### Configure Zeek

```bash
# Create Zeek configuration
sudo nano /opt/zeek/share/zeek/site/local.zeek

# Add custom configuration:
# @load frameworks/files/extract-all-files
# @load frameworks/communication/weird
# @load frameworks/communication/notice

# Test configuration
zeek -C -r /path/to/test.pcap
```

### Step 4: Initialize Database Schema

```bash
# Activate virtual environment
source venv/bin/activate

# Create database tables
python3 << EOF
from quantumshield.database.connection import get_engine
from quantumshield.database.models import Base

engine = get_engine()
Base.metadata.create_all(engine)
print("Database schema created successfully!")
EOF
```

---

## 🚀 Running QuantumShield

### Step 1: Verify Network Interface

```bash
# List network interfaces
ip link show

# Set interface to promiscuous mode (if needed)
sudo ip link set <interface> promisc on

# Verify interface is up
ip link set <interface> up
```

### Step 2: Start Required Services

```bash
# Start PostgreSQL
sudo systemctl start postgresql

# Start Redis
sudo systemctl start redis-server

# Start security tools (optional, if you want them running)
sudo systemctl start suricata
sudo systemctl start fail2ban
sudo systemctl start clamav-daemon
```

### Step 3: Run QuantumShield

#### Option A: Using CLI

```bash
# Activate virtual environment
source venv/bin/activate

# Start QuantumShield
python -m quantumshield.cli.main start

# Or use the quantumshield command (if installed)
quantumshield start
```

#### Option B: Using Python Directly

```bash
# Activate virtual environment
source venv/bin/activate

# Run the engine
python3 << EOF
import asyncio
from quantumshield.core.engine import QuantumShieldEngine
from quantumshield.config.settings import get_settings

async def main():
    settings = get_settings()
    engine = QuantumShieldEngine()
    await engine.start()

if __name__ == "__main__":
    asyncio.run(main())
EOF
```

#### Option C: Using Docker (if configured)

```bash
# Build Docker image
docker-compose build

# Start services
docker-compose up -d

# View logs
docker-compose logs -f quantumshield
```

### Step 4: Check Status

```bash
# Check if QuantumShield is running
python -m quantumshield.cli.main status

# View logs
tail -f logs/application.log
tail -f logs/security_events.log
```

---

## ✅ Verification & Testing

### Step 1: Test Packet Capture

```bash
# Generate test traffic
ping -c 5 8.8.8.8

# Check if packets are being captured
tail -f logs/application.log | grep "packet"
```

### Step 2: Test Detection Engines

```bash
# Create a test script
cat > test_detection.py << 'EOF'
import asyncio
from quantumshield.detection_engines.signature_engine import SignatureEngine
from quantumshield.core.traffic_processor import PacketInfo, ProtocolType

async def test():
    engine = SignatureEngine()
    await engine.initialize()
    
    # Create test packet
    packet = PacketInfo(
        timestamp=1234567890.0,
        src_ip="192.168.1.100",
        dst_ip="10.0.0.1",
        src_port=12345,
        dst_port=80,
        protocol=ProtocolType.TCP,
        ip_version=4,
        ttl=64,
        ip_len=100,
        payload_len=50,
        payload=b"SELECT * FROM users WHERE id=1 OR 1=1"
    )
    
    flow = {}
    result = await engine.analyze(packet, flow)
    print(f"Detection result: {result}")

asyncio.run(test())
EOF

python3 test_detection.py
```

### Step 3: Test API

```bash
# Start API server (in another terminal)
source venv/bin/activate
uvicorn quantumshield.api.rest_api:app --host 0.0.0.0 --port 8080

# Test API endpoints
curl http://localhost:8080/
curl http://localhost:8080/status
curl http://localhost:8080/alerts
```

### Step 4: Test Decision Making

```bash
# Create test script
cat > test_decision.py << 'EOF'
import asyncio
from quantumshield.core.decision_maker import DecisionMaker, create_threat_context, ThreatIndicator, ThreatLevel

async def test():
    dm = DecisionMaker()
    
    context = create_threat_context(
        source_ip='192.0.2.100',
        destination_ip='10.0.0.1',
        source_port=54321,
        destination_port=80,
        protocol='TCP'
    )
    
    context.add_indicator(ThreatIndicator(
        source='signature_engine',
        indicator_type='signature',
        severity=ThreatLevel.HIGH,
        confidence=0.95,
        description='SQL injection detected'
    ))
    
    decision = await dm.make_decision(context)
    print(f"Decision: {decision.action.name}")
    print(f"Threat Level: {decision.threat_level.name}")
    print(f"Reason: {decision.reason}")

asyncio.run(test())
EOF

python3 test_decision.py
```

---

## 🔍 Troubleshooting

### Issue 1: Permission Denied for Packet Capture

**Error**: `PermissionError: [Errno 1] Operation not permitted`

**Solution**:
```bash
# Grant CAP_NET_RAW capability
sudo setcap cap_net_raw,cap_net_admin=eip /path/to/python

# Or run with sudo (not recommended for production)
sudo python -m quantumshield.cli.main start
```

### Issue 2: Interface Not Found

**Error**: `Interface eth0 not found`

**Solution**:
```bash
# List available interfaces
ip link show

# Update .env file with correct interface name
nano .env
# Change CAPTURE_INTERFACE to your interface
```

### Issue 3: Database Connection Error

**Error**: `psycopg2.OperationalError: connection refused`

**Solution**:
```bash
# Check PostgreSQL status
sudo systemctl status postgresql

# Start PostgreSQL if not running
sudo systemctl start postgresql

# Verify connection
sudo -u postgres psql -c "SELECT version();"

# Check database exists
sudo -u postgres psql -l | grep quantumshield
```

### Issue 4: Redis Connection Error

**Error**: `Connection refused to Redis`

**Solution**:
```bash
# Check Redis status
sudo systemctl status redis-server

# Start Redis
sudo systemctl start redis-server

# Test connection
redis-cli ping
```

### Issue 5: Tool Not Found

**Error**: `FileNotFoundError: suricata not found`

**Solution**:
```bash
# Find tool location
which suricata
which snort
which zeek

# Update .env file with correct paths
nano .env
```

### Issue 6: Import Errors

**Error**: `ModuleNotFoundError: No module named 'X'`

**Solution**:
```bash
# Activate virtual environment
source venv/bin/activate

# Install missing module
pip install <module-name>

# Or reinstall all requirements
pip install -r requirements.txt
```

### Issue 7: ML Model Errors

**Error**: `CUDA/GPU related errors`

**Solution**:
```bash
# Disable GPU in .env
ML_ENABLE_GPU=false
ML_DEVICE=cpu

# Or install CPU-only PyTorch
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cpu
```

### Issue 8: IPTables Permission Denied

**Error**: `Permission denied when adding iptables rules`

**Solution**:
```bash
# Run with sudo (for testing)
sudo python -m quantumshield.cli.main start

# Or configure sudoers for specific commands
sudo visudo
# Add: your_user ALL=(ALL) NOPASSWD: /sbin/iptables
```

---

## 📊 Monitoring & Maintenance

### View Logs

```bash
# Application logs
tail -f logs/application.log

# Security events
tail -f logs/security_events.log

# Performance logs
tail -f logs/performance.log

# Errors
tail -f logs/errors.log
```

### Check System Status

```bash
# Check all services
sudo systemctl status postgresql
sudo systemctl status redis-server
sudo systemctl status suricata
sudo systemctl status fail2ban

# Check QuantumShield status
python -m quantumshield.cli.main status
```

### Update Security Tool Rules

```bash
# Update Suricata rules
sudo suricata-update

# Update Snort rules (if using paid rules)
# Download from snort.org and place in /etc/snort/rules/

# Update ClamAV definitions
sudo freshclam
```

### Backup Configuration

```bash
# Backup configuration files
tar -czf quantumshield-backup-$(date +%Y%m%d).tar.gz \
    config/ \
    .env \
    logs/

# Backup database
sudo -u postgres pg_dump quantumshield > quantumshield-db-backup.sql
```

---

## 🎯 Quick Start Summary

For experienced users, here's the quick start:

```bash
# 1. Update system
sudo apt update && sudo apt upgrade -y

# 2. Install dependencies
sudo apt install -y $(cat scripts/install_dependencies.sh | grep apt-get | cut -d' ' -f4- | tr -d '\\')

# 3. Setup databases
sudo systemctl start postgresql redis-server
sudo -u postgres createdb quantumshield

# 4. Setup Python environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 5. Configure
cp .env.example .env
nano .env  # Edit with your settings

# 6. Run
python -m quantumshield.cli.main start
```

---

## 📚 Additional Resources

- **Suricata Documentation**: https://suricata.readthedocs.io/
- **Snort Documentation**: https://www.snort.org/documents
- **Zeek Documentation**: https://docs.zeek.org/
- **OSSEC Documentation**: https://www.ossec.net/docs/
- **Fail2Ban Documentation**: https://www.fail2ban.org/
- **ModSecurity Documentation**: https://github.com/SpiderLabs/ModSecurity/wiki

---

## ⚠️ Important Notes

1. **Root Access**: Some operations require root/sudo access for packet capture and firewall rules
2. **Network Interface**: Ensure your network interface is in promiscuous mode for packet capture
3. **Firewall Rules**: QuantumShield will modify iptables rules - review before production use
4. **Performance**: ML models can be CPU-intensive; monitor system resources
5. **Legal Compliance**: Ensure you have permission to monitor network traffic
6. **Testing**: Test in a controlled environment before production deployment

---

## 🆘 Getting Help

- Check logs in `logs/` directory
- Review error messages in console output
- Verify all services are running
- Check network interface configuration
- Review configuration files in `config/`

---

## ✅ Verification Checklist

Before running in production, verify:

- [ ] All security tools installed and configured
- [ ] Database (PostgreSQL + TimescaleDB) running
- [ ] Redis running
- [ ] Network interface configured correctly
- [ ] Environment variables set in `.env`
- [ ] Python dependencies installed
- [ ] Logs directory writable
- [ ] Sufficient disk space
- [ ] Firewall rules reviewed
- [ ] Backup strategy in place

---

**Congratulations!** You've successfully set up QuantumShield on Kali Linux. The system is now ready to monitor and protect your network.

