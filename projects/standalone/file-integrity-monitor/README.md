# File Integrity Monitor (FIM)

Monitors file integrity by calculating SHA256 hashes and detecting changes in real-time.

## Purpose

This tool is part of my cybersecurity homelab portfolio. It demonstrates:

- File system monitoring
- Cryptographic hashing (SHA256)
- Database storage (SQLite)
- Real-time event detection

## Technologies

- Python 3.14+
- Watchdog
- SQLite
- hashlib (SHA256)

## Installation

git clone https://github.com/felix-meow/homelab.git
cd homelab/projects/standalone/file-integrity-monitor

pip install -r requirements.txt

## Usage

Initialize the database:
python3 fim.py -d /path/to/directory --init

Monitor a directory in real-time:
python3 fim.py -d /path/to/directory

### Options

| Option | Description |
|--------|-------------|
| -d, --directory | Directory to monitor (required) |
| --db | Database file path (default: database/fim.db) |
| --init | Initialize database with current state |
| --verify | Compare current state against the baseline (no changes made) |
| --report | Generate a JSON summary report of the baseline |
| -e, --exclude | Regex pattern for paths to exclude (repeatable) |

## Example Output

[INIT] Checking integrity of /home/roby/test_fim...
[CREATED] /home/roby/test_fim/file1.txt
[CREATED] /home/roby/test_fim/file2.txt
[INIT] Initialized 2 files in database

[MONITOR] Watching /home/roby/test_fim...
[MODIFIED] /home/roby/test_fim/file2.txt
[DELETED] /home/roby/test_fim/file1.txt

## Testing

Terminal 1 - Monitor:
python3 fim.py -d ~/test_fim

Terminal 2 - Generate changes:
cd ~/test_fim
echo "test" > file1.txt
echo "test2" > file2.txt
rm file1.txt
echo "modified" > file2.txt

## Implemented

- Baseline reports (`--report`) — schedule with cron for weekly reports
- Regex-based exclusions (`-e/--exclude`)
- Hash comparison with database (`--verify`)

## Future Improvements

- Email alerts via n8n
- Wazuh SIEM integration
- Web interface (Flask)

## Author

Robert Mircea
GitHub: felix-meow
LinkedIn: robert-mircea