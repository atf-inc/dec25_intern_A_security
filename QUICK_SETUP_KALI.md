# Quick Setup Guide for Kali Linux

This is a condensed version of the full setup guide. For detailed instructions, see `GUIDE.md`.

## 🚀 Quick Installation (30 minutes)

### Step 1: System Update (5 min)

```bash
sudo apt update && sudo apt upgrade -y
```

### Step 2: Install Dependencies (10 min)

```bash
cd ~/Desktop/AITF_IPS/quantumshield
sudo ./scripts/install_dependencies.sh
```

### Step 3: Setup Databases (5 min)

```bash
sudo ./scripts/setup_databases.sh
# Follow prompts to set passwords
```

### Step 4: Install Security Tools (Optional, 10 min)

```bash
sudo ./scripts/install_security_tools.sh
# Select option 1 to install all tools
```

### Step 5: Python Environment (5 min)

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install Python packages
pip install --upgrade pip
pip install -r requirements.txt
```

### Step 6: Configure (5 min)

```bash
# Copy and edit environment file
cp .env.example .env
nano .env

# Update these key settings:
# - CAPTURE_INTERFACE (use: ip link show to find)
# - Database passwords
# - Tool paths
```

### Step 7: Initialize Database

```bash
# Activate venv
source venv/bin/activate

# Create database schema
python3 << EOF
from quantumshield.database.connection import get_engine
from quantumshield.database.models import Base
engine = get_engine()
Base.metadata.create_all(engine)
print("Database initialized!")
EOF
```

### Step 8: Run QuantumShield

```bash
# Activate venv
source venv/bin/activate

# Start QuantumShield
python -m quantumshield.cli.main start
```

## ✅ Verify Installation

```bash
# Check services
sudo systemctl status postgresql
sudo systemctl status redis-server

# Check tools
suricata -V
snort -V
zeek --version

# Check Python packages
pip list | grep quantumshield
```

## 🎯 Minimal Setup (Without Security Tools)

If you just want to test QuantumShield without installing all security tools:

```bash
# 1. Install basic dependencies
sudo apt install -y python3 python3-pip python3-venv postgresql redis-server

# 2. Setup databases
sudo systemctl start postgresql redis-server
sudo -u postgres createdb quantumshield

# 3. Python environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 4. Configure
cp .env.example .env
# Edit .env and disable security tools:
# SURICATA_ENABLED=false
# SNORT_ENABLED=false
# etc.

# 5. Run
python -m quantumshield.cli.main start
```

## 📝 Common Issues

**Permission denied for packet capture:**
```bash
sudo setcap cap_net_raw,cap_net_admin=eip $(which python3)
```

**Database connection error:**
```bash
sudo systemctl start postgresql
sudo -u postgres psql -c "CREATE DATABASE quantumshield;"
```

**Import errors:**
```bash
source venv/bin/activate
pip install -r requirements.txt
```

For more details, see the full `GUIDE.md`.

