# QuantumShield Quick Start Guide

## 🚀 Quick Setup (5 minutes)

### 1. Install Dependencies

```bash
# Install system dependencies
sudo ./scripts/install_dependencies.sh

# Install Python packages
pip install -r requirements.txt
```

### 2. Configure

```bash
# Copy environment template
cp .env.example .env

# Edit .env with your settings
# At minimum, set:
# - CAPTURE_INTERFACE (e.g., eth0, enp0s3)
# - DATABASE_URL (PostgreSQL connection string)
```

### 3. Initialize Database

```bash
# Create database (PostgreSQL must be running)
createdb quantumshield

# Or use Docker
docker-compose up -d postgres
```

### 4. Start QuantumShield

```bash
# Using CLI
python -m quantumshield.cli.main start

# Or using Docker
docker-compose up -d
```

### 5. Verify

```bash
# Check status
python -m quantumshield.cli.main status

# View logs
tail -f logs/application.log
```

## 📋 Basic Usage

### Start the Engine

```bash
python -m quantumshield.cli.main start
```

### View Status

```bash
python -m quantumshield.cli.main status
```

### Access API

```bash
curl http://localhost:8080/status
```

## ⚙️ Configuration

Key settings in `.env`:

- `CAPTURE_INTERFACE`: Network interface to monitor
- `SIGNATURE_ENGINE_ENABLED`: Enable signature detection
- `ANOMALY_ENGINE_ENABLED`: Enable anomaly detection
- `AUTO_BLOCK_ENABLED`: Enable automatic IP blocking

## 🔧 Troubleshooting

### Permission Denied
- Run with sudo/administrator privileges for packet capture
- Ensure user has CAP_NET_RAW capability

### No Packets Captured
- Check interface name: `ip link show`
- Verify interface is up: `ip link set <interface> up`
- Check firewall rules aren't blocking

### Database Connection Error
- Verify PostgreSQL is running
- Check DATABASE_URL in .env
- Ensure database exists

## 📚 Next Steps

- Read [Installation Guide](docs/installation.md)
- Review [Configuration Guide](docs/configuration.md)
- Explore [API Reference](docs/api_reference.md)
- Check [Architecture](docs/architecture.md)

## 🆘 Support

- Check logs in `logs/` directory
- Review documentation in `docs/`
- Open an issue on GitHub

