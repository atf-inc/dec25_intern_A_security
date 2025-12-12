#!/bin/bash
# Setup databases for QuantumShield

set -e

echo "=========================================="
echo "QuantumShield Database Setup"
echo "=========================================="

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Check if running as root or with sudo
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root or with sudo"
    exit 1
fi

echo -e "${GREEN}Step 1: Starting PostgreSQL...${NC}"
systemctl enable postgresql
systemctl start postgresql

echo -e "${GREEN}Step 2: Configuring PostgreSQL...${NC}"
# Set postgres password
read -sp "Enter password for postgres user: " POSTGRES_PASSWORD
echo
sudo -u postgres psql -c "ALTER USER postgres PASSWORD '$POSTGRES_PASSWORD';"

# Create database and user
read -sp "Enter password for quantum user: " QUANTUM_PASSWORD
echo

sudo -u postgres psql << EOF
CREATE DATABASE quantumshield;
CREATE USER quantum WITH PASSWORD '$QUANTUM_PASSWORD';
GRANT ALL PRIVILEGES ON DATABASE quantumshield TO quantum;
\q
EOF

echo -e "${GREEN}Step 3: Configuring TimescaleDB...${NC}"
sudo timescaledb-tune --quiet --yes
systemctl restart postgresql

# Enable TimescaleDB extension
sudo -u postgres psql -d quantumshield << EOF
CREATE EXTENSION IF NOT EXISTS timescaledb;
\q
EOF

echo -e "${GREEN}Step 4: Configuring Redis...${NC}"
systemctl enable redis-server
systemctl start redis-server

read -sp "Enter Redis password (or press Enter for no password): " REDIS_PASSWORD
echo

if [ ! -z "$REDIS_PASSWORD" ]; then
    # Update Redis config
    sed -i "s/# requirepass foobared/requirepass $REDIS_PASSWORD/" /etc/redis/redis.conf
    systemctl restart redis-server
    echo "Redis password set"
else
    echo "Redis running without password"
fi

echo -e "${GREEN}=========================================="
echo "Database setup complete!"
echo "==========================================${NC}"

echo -e "${YELLOW}Database credentials:${NC}"
echo "PostgreSQL:"
echo "  Host: localhost"
echo "  Port: 5432"
echo "  Database: quantumshield"
echo "  User: quantum"
echo "  Password: [your password]"
echo ""
echo "Redis:"
echo "  Host: localhost"
echo "  Port: 6379"
echo "  Password: [your password or none]"
echo ""
echo "Update these in your .env file!"

