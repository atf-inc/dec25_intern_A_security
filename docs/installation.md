# Installation Guide

## Prerequisites

- Python 3.10 or higher
- Linux-based OS (Ubuntu 20.04+ recommended)
- Root/Administrator privileges
- 8GB+ RAM
- GPU optional but recommended for ML inference

## Installation Steps

1. Clone the repository
2. Install system dependencies: `sudo ./scripts/install_dependencies.sh`
3. Install Python dependencies: `pip install -r requirements.txt`
4. Configure environment: `cp .env.example .env`
5. Initialize database: `python -m quantumshield.database.connection init`
6. Start QuantumShield: `python -m quantumshield.cli.main start`

## Docker Installation

```bash
docker-compose up -d
```

## Verification

Check system status:
```bash
python -m quantumshield.cli.main status
```

