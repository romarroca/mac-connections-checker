# Mac Connections Checker

This tool monitors outgoing internet connections from your macOS system and provides detailed information about each connection, including:
- Process information (name, executable path, command line)
- DNS information (reverse lookup)
- WHOIS information about the remote IP
- Connection details (ports, timestamps)

## Requirements

- Python 3.7+
- Required packages (install using `pip install -r requirements.txt`):
  - psutil
  - python-whois
  - dnspython
  - requests

## Installation

1. Clone this repository:
```bash
git clone https://github.com/romarroca/mac-connections-checker.git
cd mac-connections-checker
```

2. Install the required packages:
```bash
pip install -r requirements.txt
```

## Usage

### Monitor Connections

To start monitoring connections:

```bash
sudo python connection_monitor.py
```

Note: `sudo` is required to access process information for all connections.

This will:
- Create a `logs` directory if it doesn't exist
- Monitor all outgoing connections
- Log detailed information about new connections to JSON files
- Display real-time notifications about new connections

### Analyze Connections

To analyze the logged connections:

```bash
python analyze_connections.py [log_file_path]
```

If no log file is specified, it will analyze today's log file by default.

The analysis includes:
- Total number of connections
- Number of unique IP addresses
- Top 10 processes making connections
- Top 10 domains contacted
- Top 10 organizations (from WHOIS data)

## Log Files

Log files are stored in the `logs` directory with the naming format `connections_YYYYMMDD.json`. Each log file contains detailed information about the connections detected on that day.

## Note

- The script requires root/administrator privileges to access process information
- WHOIS lookups might be rate-limited depending on the service
- Some connections might not have complete information due to various factors (permissions, DNS failures, etc.)

## License

MIT License