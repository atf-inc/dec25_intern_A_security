#!/bin/bash
# Install all open-source security tools for QuantumShield

set -e

echo "=========================================="
echo "QuantumShield Security Tools Installation"
echo "=========================================="

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Please run as root or with sudo${NC}"
    exit 1
fi

INSTALL_DIR="/tmp/quantumshield_install"
mkdir -p $INSTALL_DIR
cd $INSTALL_DIR

# Function to install Suricata
install_suricata() {
    echo -e "${GREEN}Installing Suricata...${NC}"
    
    apt-get install -y \
        libpcre3 libpcre3-dbg libpcre3-dev \
        libpcap-dev libnet1-dev \
        libyaml-0-2 libyaml-dev \
        zlib1g zlib1g-dev \
        libcap-ng-dev libcap-ng0 \
        libmagic-dev libjansson-dev \
        libnss3-dev libgeoip-dev \
        liblua5.1-dev libhiredis-dev \
        libevent-dev python-yaml \
        rustc cargo
    
    cd $INSTALL_DIR
    wget -q https://www.openinfosecfoundation.org/download/suricata-7.0.0.tar.gz
    tar -xzf suricata-7.0.0.tar.gz
    cd suricata-7.0.0
    
    ./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var \
        --enable-nfqueue --enable-lua --enable-geoip --enable-hiredis
    
    make -j$(nproc)
    make install
    make install-conf
    make install-rules
    
    mkdir -p /var/log/suricata /etc/suricata/rules
    suricata-update
    
    echo -e "${GREEN}Suricata installed successfully${NC}"
}

# Function to install Snort
install_snort() {
    echo -e "${GREEN}Installing Snort...${NC}"
    
    apt-get install -y \
        libpcap-dev libpcre3-dev libdumbnet-dev \
        zlib1g-dev liblzma-dev \
        openssl libssl-dev \
        libnghttp2-dev libluajit-5.1-dev \
        libdnet libdumbnet libdaq-dev
    
    cd $INSTALL_DIR
    wget -q https://www.snort.org/downloads/snort/snort-2.9.20.tar.gz
    tar -xzf snort-2.9.20.tar.gz
    cd snort-2.9.20
    
    ./configure --enable-sourcefire
    make -j$(nproc)
    make install
    
    mkdir -p /etc/snort/rules /var/log/snort
    
    echo -e "${GREEN}Snort installed successfully${NC}"
}

# Function to install Zeek
install_zeek() {
    echo -e "${GREEN}Installing Zeek...${NC}"
    
    apt-get install -y \
        cmake make gcc g++ flex bison \
        libpcap-dev libssl-dev python3-dev \
        swig zlib1g-dev libmaxminddb-dev \
        libcurl4-openssl-dev
    
    cd /opt
    git clone --recursive https://github.com/zeek/zeek.git
    cd zeek
    ./configure --prefix=/opt/zeek
    make -j$(nproc)
    make install
    
    echo 'export PATH=/opt/zeek/bin:$PATH' >> /etc/profile
    mkdir -p /opt/zeek/logs
    
    echo -e "${GREEN}Zeek installed successfully${NC}"
}

# Function to install OSSEC
install_ossec() {
    echo -e "${GREEN}Installing OSSEC...${NC}"
    
    apt-get install -y \
        build-essential libssl-dev libpcre2-dev \
        zlib1g-dev make gcc inotify-tools
    
    cd $INSTALL_DIR
    wget -q https://github.com/ossec/ossec-hids/releases/download/3.7.0/ossec-hids-3.7.0.tar.gz
    tar -xzf ossec-hids-3.7.0.tar.gz
    cd ossec-hids-3.7.0
    
    # Non-interactive installation
    echo "server" | ./install.sh
    
    echo -e "${GREEN}OSSEC installed successfully${NC}"
}

# Function to install Fail2Ban
install_fail2ban() {
    echo -e "${GREEN}Installing Fail2Ban...${NC}"
    
    apt-get install -y fail2ban
    
    if [ ! -f /etc/fail2ban/jail.local ]; then
        cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
    fi
    
    systemctl enable fail2ban
    systemctl start fail2ban
    
    echo -e "${GREEN}Fail2Ban installed successfully${NC}"
}

# Function to install ModSecurity
install_modsecurity() {
    echo -e "${GREEN}Installing ModSecurity...${NC}"
    
    apt-get install -y \
        libapache2-mod-security2 \
        modsecurity-crs apache2
    
    a2enmod security2 rewrite headers
    
    if [ ! -f /etc/modsecurity/modsecurity.conf ]; then
        cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf
    fi
    
    cd /tmp
    git clone https://github.com/coreruleset/coreruleset.git /etc/modsecurity/coreruleset
    cd /etc/modsecurity/coreruleset
    cp crs-setup.conf.example /etc/modsecurity/crs-setup.conf
    
    systemctl restart apache2
    
    echo -e "${GREEN}ModSecurity installed successfully${NC}"
}

# Function to install ClamAV
install_clamav() {
    echo -e "${GREEN}Installing ClamAV...${NC}"
    
    apt-get install -y \
        clamav clamav-daemon clamav-freshclam \
        clamav-unofficial-sigs
    
    freshclam
    systemctl enable clamav-daemon
    systemctl start clamav-daemon
    
    echo -e "${GREEN}ClamAV installed successfully${NC}"
}

# Function to install nDPI
install_ndpi() {
    echo -e "${GREEN}Installing nDPI...${NC}"
    
    apt-get install -y \
        libpcap-dev libjson-c-dev libgcrypt20-dev \
        libtool autoconf automake make gcc g++
    
    cd $INSTALL_DIR
    git clone https://github.com/ntop/nDPI.git
    cd nDPI
    ./autogen.sh
    ./configure
    make -j$(nproc)
    make install
    ldconfig
    
    echo -e "${GREEN}nDPI installed successfully${NC}"
}

# Function to install Wazuh
install_wazuh() {
    echo -e "${GREEN}Installing Wazuh...${NC}"
    
    curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring /usr/share/keyrings/wazuh.gpg --import
    echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list
    
    apt-get update
    apt-get install -y wazuh-manager
    
    systemctl daemon-reload
    systemctl enable wazuh-manager
    systemctl start wazuh-manager
    
    echo -e "${GREEN}Wazuh installed successfully${NC}"
}

# Main installation menu
echo "Select tools to install:"
echo "1) All tools"
echo "2) Suricata"
echo "3) Snort"
echo "4) Zeek"
echo "5) OSSEC"
echo "6) Fail2Ban"
echo "7) ModSecurity"
echo "8) ClamAV"
echo "9) nDPI"
echo "10) Wazuh"
echo ""
read -p "Enter selection (1-10): " choice

case $choice in
    1)
        install_suricata
        install_snort
        install_zeek
        install_ossec
        install_fail2ban
        install_modsecurity
        install_clamav
        install_ndpi
        install_wazuh
        ;;
    2) install_suricata ;;
    3) install_snort ;;
    4) install_zeek ;;
    5) install_ossec ;;
    6) install_fail2ban ;;
    7) install_modsecurity ;;
    8) install_clamav ;;
    9) install_ndpi ;;
    10) install_wazuh ;;
    *)
        echo -e "${RED}Invalid selection${NC}"
        exit 1
        ;;
esac

echo -e "${GREEN}=========================================="
echo "Installation complete!"
echo "==========================================${NC}"

# Cleanup
cd /
rm -rf $INSTALL_DIR

echo -e "${YELLOW}Next steps:${NC}"
echo "1. Configure each tool (see GUIDE.md)"
echo "2. Update .env file with tool paths"
echo "3. Test each tool individually"
echo "4. Start QuantumShield"

