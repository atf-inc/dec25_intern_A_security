#!/bin/bash
# Install system dependencies for QuantumShield on Kali Linux

set -e

echo "=========================================="
echo "QuantumShield Dependency Installation"
echo "=========================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if running as root or with sudo
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Please run as root or with sudo${NC}"
    exit 1
fi

echo -e "${GREEN}Step 1: Updating package list...${NC}"
apt-get update

echo -e "${GREEN}Step 2: Installing essential build tools...${NC}"
apt-get install -y \
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

echo -e "${GREEN}Step 3: Installing network and packet capture tools...${NC}"
apt-get install -y \
    tcpdump \
    libpcap-dev \
    libpcap0.8 \
    libnet1-dev \
    libnetfilter-queue-dev \
    libnfnetlink-dev \
    libnids-dev \
    libdumbnet-dev \
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

echo -e "${GREEN}Step 4: Installing database dependencies...${NC}"
apt-get install -y \
    postgresql \
    postgresql-contrib \
    postgresql-server-dev-all \
    libpq-dev \
    redis-server \
    redis-tools

echo -e "${GREEN}Step 5: Installing TimescaleDB...${NC}"
# Add TimescaleDB repository
sh -c "echo 'deb https://packagecloud.io/timescale/timescaledb/debian/ $(lsb_release -c -s) main' > /etc/apt/sources.list.d/timescaledb.list"
wget --quiet -O - https://packagecloud.io/timescale/timescaledb/gpgkey | apt-key add -
apt-get update
apt-get install -y timescaledb-2-postgresql-15

echo -e "${GREEN}Step 6: Installing additional dependencies...${NC}"
apt-get install -y \
    libpq-dev \
    libffi-dev \
    libssl-dev \
    libxml2-dev \
    libxslt1-dev \
    libjpeg-dev \
    zlib1g-dev \
    libblas-dev \
    liblapack-dev \
    libatlas-base-dev \
    gfortran \
    netifaces \
    inotify-tools

echo -e "${GREEN}Step 7: Installing Rust (for Suricata)...${NC}"
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source $HOME/.cargo/env

echo -e "${GREEN}=========================================="
echo "Dependencies installed successfully!"
echo "==========================================${NC}"

echo -e "${YELLOW}Next steps:${NC}"
echo "1. Install security tools (see GUIDE.md)"
echo "2. Setup databases (PostgreSQL, Redis)"
echo "3. Create Python virtual environment"
echo "4. Install Python packages: pip install -r requirements.txt"
echo "5. Configure .env file"
echo "6. Run: python -m quantumshield.cli.main start"
