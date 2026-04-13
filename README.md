# SOC Log Analysis Project

A Python script that:
- Reads log files
- Detects suspicious activity (failed logins, brute-force patterns)
- Outputs alerts to the console

## Files

- `soc_log_analyzer.py` - main analyzer script

## Usage

```bash
python soc_log_analyzer.py <path_to_log_file>
```

### Optional arguments

- `--threshold` : Number of failed attempts from one IP to trigger brute-force alert (default: `5`)
- `--window-minutes` : Time window for brute-force detection (default: `5`)
- `--only-high` : Show only HIGH severity alerts

Example:

```bash
python soc_log_analyzer.py auth.log --threshold 4 --window-minutes 10
```

## Example log lines supported

```text
2026-04-13 10:01:12 Failed password for admin from 192.168.1.10 port 22 ssh2
2026-04-13 10:01:50 Failed password for root from 192.168.1.10 port 22 ssh2
2026-04-13 10:02:30 Failed password for user1 from 192.168.1.10 port 22 ssh2
2026-04-13 10:03:01 Accepted password for admin from 192.168.1.10 port 22 ssh2
```

## Output format

```text
[SEVERITY] ALERT_TYPE | time=<timestamp> | ip=<source_ip> | user=<user> | line=<line_number> | <details>
```
