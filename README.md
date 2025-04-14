# Universal CLI Utility

A unified command-line interface that simplifies system management through custom commands, automation, and security monitoring.

## Overview

Universal CLI Utility provides a powerful yet user-friendly command-line interface that unifies basic system operations, enhances productivity, automates tasks, improves system security, and supports cross-platform usage.

## Features

- **File Management**: Copy, find, and manage files with simple commands
- **Process Management**: Monitor and control system processes
- **Network Utilities**: Ping hosts, scan ports, and monitor network connections
- **Security Checks**: Perform basic and advanced security scans
- **Task Automation**: Schedule and manage automated tasks
- **Remote Execution**: Execute commands remotely via SSH

## Installation

### Prerequisites

- Python 3.6+
- pip (Python package manager)

### Installation Steps

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/universal-cli.git
   cd universal-cli
   ```

2. Install the package:
   ```
   pip install -e .
   ```

## Usage

### Basic Usage

```
ucli <command> [options]
```

### Available Commands

- `file`: File operations
  - `copy`: Copy files or directories
  - `find`: Find files by pattern

- `process`: Process management
  - `list`: List running processes
  - `kill`: Kill a process

- `network`: Network utilities
  - `ping`: Ping a host
  - `scan`: Scan ports on a host

- `security`: Security monitoring
  - `scan`: Perform a security scan

- `automate`: Task automation
  - `schedule`: Schedule a task
  - `list_tasks`: List scheduled tasks
  - `remove`: Remove a scheduled task

- `remote`: Remote execution
  - `ssh`: Execute command via SSH
  - `scp`: Copy file via SCP

### Examples

#### File Operations
```
# Copy a file
ucli file copy source.txt destination.txt

# Copy a directory recursively
ucli file copy source_dir destination_dir -r

# Find files by pattern
ucli file find "*.py" -p /path/to/search
```

#### Process Management
```
# List processes sorted by CPU usage
ucli process list -s cpu

# List all processes
ucli process list -a

# Kill a process
ucli process kill 1234
```

#### Network Utilities
```
# Ping a host
ucli network ping example.com -c 5

# Scan ports on a host
ucli network scan example.com -p 80,443,8080
```

#### Security Checks
```
# Perform a basic security scan
ucli security scan

# Perform an advanced security scan
ucli security scan -l advanced
```

#### Task Automation
```
# Schedule a task
ucli automate schedule "ucli security scan" "0 0 * * *"

# List scheduled tasks
ucli automate list_tasks

# Remove a scheduled task
ucli automate remove task_20230101000000
```

#### Remote Execution
```
# Execute a command via SSH
ucli remote ssh example.com "ls -la" -u username

# Copy a file via SCP
ucli remote scp file.txt username@example.com:/path/to/destination
```

## Project Structure

```
universal-cli/
├── main.py                 # Entry point
├── modules/                # Core functionality modules
│   ├── __init__.py
│   ├── file_ops.py         # File operations
│   ├── process_mgmt.py     # Process management
│   ├── network_utils.py    # Network utilities
│   ├── security_checks.py  # Security monitoring
│   ├── automation.py       # Task automation
│   └── remote_exec.py      # Remote execution
├── utils/                  # Helper functions
│   ├── __init__.py
│   ├── command_parser.py   # Command parsing
│   ├── logging_utils.py    # Logging functionality
│   └── db_manager.py       # Database operations
├── config/                 # Configuration files
│   └── settings.py         # Default settings
├── tests/                  # Unit tests
│   └── __init__.py
└── docs/                   # Documentation
    └── user_guide.md       # User manual
```

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Commit your changes: `git commit -am 'Add feature'`
4. Push to the branch: `git push origin feature-name`
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Authors

- Anmol Raturi (Team Lead)
- Khushi Mamgain
- Gaurav Singh
- Abhay Bhatt
