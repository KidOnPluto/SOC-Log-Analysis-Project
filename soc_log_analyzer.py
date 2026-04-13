#!/usr/bin/env python3
"""
SOC Log Analyzer

Reads log files, detects suspicious activity, and outputs alerts.
Current detections:
- Failed login attempts
- Brute-force patterns (multiple failed logins from same source in time window)
"""

from __future__ import annotations

import argparse
import re
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Deque, Dict, Iterable, List, Optional


TIMESTAMP_PATTERNS = [
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
    "%b %d %H:%M:%S",  # Syslog style (no year)
]


FAILED_PATTERNS = [
    re.compile(r"failed password", re.IGNORECASE),
    re.compile(r"login failed", re.IGNORECASE),
    re.compile(r"authentication failure", re.IGNORECASE),
]

SUCCESS_PATTERNS = [
    re.compile(r"accepted password", re.IGNORECASE),
    re.compile(r"login successful", re.IGNORECASE),
]

IP_PATTERN = re.compile(
    r"\b(?:from|src|source)\s+(\d{1,3}(?:\.\d{1,3}){3})\b|\b(\d{1,3}(?:\.\d{1,3}){3})\b"
)

USER_PATTERNS = [
    re.compile(r"user(?:name)?\s*[=:]\s*([\w.@-]+)", re.IGNORECASE),
    re.compile(r"for\s+(?:invalid user\s+)?([\w.@-]+)", re.IGNORECASE),
]


@dataclass
class Alert:
    alert_type: str
    severity: str
    timestamp: Optional[datetime]
    source_ip: str
    user: str
    details: str
    line_number: int

    def as_text(self) -> str:
        ts = self.timestamp.isoformat(sep=" ") if self.timestamp else "N/A"
        return (
            f"[{self.severity}] {self.alert_type} | time={ts} | "
            f"ip={self.source_ip} | user={self.user} | line={self.line_number} | {self.details}"
        )


def parse_timestamp(line: str) -> Optional[datetime]:
    """Try parsing a timestamp from the beginning of the log line."""
    head = line[:32].strip()
    for fmt in TIMESTAMP_PATTERNS:
        try:
            dt = datetime.strptime(head[: len(datetime.now().strftime(fmt))], fmt)
            if fmt == "%b %d %H:%M:%S":
                dt = dt.replace(year=datetime.now().year)
            return dt
        except ValueError:
            continue

    # Fallback: scan for common timestamp fragments
    fallback_patterns = [
        re.compile(r"(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})"),
        re.compile(r"([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"),
    ]
    for pattern in fallback_patterns:
        match = pattern.search(line)
        if not match:
            continue
        token = match.group(1)
        for fmt in TIMESTAMP_PATTERNS:
            try:
                dt = datetime.strptime(token, fmt)
                if fmt == "%b %d %H:%M:%S":
                    dt = dt.replace(year=datetime.now().year)
                return dt
            except ValueError:
                continue
    return None


def extract_ip(line: str) -> str:
    match = IP_PATTERN.search(line)
    if not match:
        return "unknown"
    return match.group(1) or match.group(2) or "unknown"


def extract_user(line: str) -> str:
    for pattern in USER_PATTERNS:
        match = pattern.search(line)
        if match:
            return match.group(1)
    return "unknown"


def is_failed_login(line: str) -> bool:
    return any(pattern.search(line) for pattern in FAILED_PATTERNS)


def is_success_login(line: str) -> bool:
    return any(pattern.search(line) for pattern in SUCCESS_PATTERNS)


def read_lines(path: Path) -> Iterable[str]:
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            yield line.rstrip("\n")


def analyze_log(
    path: Path,
    brute_force_threshold: int,
    window_minutes: int,
) -> List[Alert]:
    alerts: List[Alert] = []

    # Track failures per IP in a rolling time window.
    failed_attempts_by_ip: Dict[str, Deque[datetime]] = defaultdict(deque)

    # If timestamps are missing, we still track counts by order with synthetic time.
    synthetic_time = datetime.now()
    synthetic_step = timedelta(seconds=1)

    for idx, line in enumerate(read_lines(path), start=1):
        ts = parse_timestamp(line)
        if ts is None:
            synthetic_time += synthetic_step
            ts = synthetic_time

        ip = extract_ip(line)
        user = extract_user(line)

        if is_failed_login(line):
            alerts.append(
                Alert(
                    alert_type="FAILED_LOGIN",
                    severity="MEDIUM",
                    timestamp=ts,
                    source_ip=ip,
                    user=user,
                    details="Failed authentication attempt detected",
                    line_number=idx,
                )
            )

            attempts = failed_attempts_by_ip[ip]
            attempts.append(ts)
            window_start = ts - timedelta(minutes=window_minutes)

            while attempts and attempts[0] < window_start:
                attempts.popleft()

            if len(attempts) >= brute_force_threshold:
                alerts.append(
                    Alert(
                        alert_type="BRUTE_FORCE_SUSPECTED",
                        severity="HIGH",
                        timestamp=ts,
                        source_ip=ip,
                        user=user,
                        details=(
                            f"{len(attempts)} failed logins within {window_minutes} "
                            f"minutes (threshold={brute_force_threshold})"
                        ),
                        line_number=idx,
                    )
                )

        elif is_success_login(line):
            # Optional context alert when a success follows failures from same IP.
            prior_attempts = len(failed_attempts_by_ip.get(ip, []))
            if prior_attempts >= max(1, brute_force_threshold // 2):
                alerts.append(
                    Alert(
                        alert_type="SUCCESS_AFTER_FAILURES",
                        severity="MEDIUM",
                        timestamp=ts,
                        source_ip=ip,
                        user=user,
                        details=f"Successful login after {prior_attempts} recent failures",
                        line_number=idx,
                    )
                )

    return alerts


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Analyze logs for suspicious authentication activity")
    parser.add_argument("log_file", type=Path, help="Path to log file")
    parser.add_argument(
        "--threshold",
        type=int,
        default=5,
        help="Failed attempts threshold to trigger brute-force alert (default: 5)",
    )
    parser.add_argument(
        "--window-minutes",
        type=int,
        default=5,
        help="Time window for brute-force detection in minutes (default: 5)",
    )
    parser.add_argument(
        "--only-high",
        action="store_true",
        help="Only print HIGH severity alerts",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()

    if not args.log_file.exists():
        print(f"ERROR: log file not found: {args.log_file}")
        return 1

    alerts = analyze_log(
        path=args.log_file,
        brute_force_threshold=max(1, args.threshold),
        window_minutes=max(1, args.window_minutes),
    )

    if args.only_high:
        alerts = [a for a in alerts if a.severity == "HIGH"]

    if not alerts:
        print("No suspicious activity detected.")
        return 0

    print(f"Detected {len(alerts)} alert(s):")
    for alert in alerts:
        print(alert.as_text())

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
