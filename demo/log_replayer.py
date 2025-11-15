#!/usr/bin/env python3
"""
Replay Suricata JSON events into a target eve.json file.

Useful for simulating real-time events when Suricata isn't producing logs.
"""

import argparse
import json
import time
from pathlib import Path
from typing import Iterator


def iter_events(source: Path) -> Iterator[str]:
    """Yield non-empty JSON lines from the source file."""
    with source.open("r", encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.strip()
            if not line:
                continue
            # Validate JSON structure so we don't write invalid entries
            try:
                json.loads(line)
            except json.JSONDecodeError:
                raise ValueError(f"Invalid JSON line in {source}: {line[:80]}...")
            yield line


def append_event(target: Path, event_line: str) -> None:
    """Append a JSON line to the target log file."""
    with target.open("a", encoding="utf-8") as handle:
        handle.write(event_line.rstrip("\n") + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Replay Suricata events into a target eve.json file"
    )
    parser.add_argument(
        "source",
        type=Path,
        help="Path to a JSONL file (one Suricata event per line)",
    )
    parser.add_argument(
        "--target",
        type=Path,
        default=Path(r"C:\Program Files\Suricata\log\eve.json"),
        help="Target eve.json file to append to "
        "(default: C:\\Program Files\\Suricata\\log\\eve.json)",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=1.0,
        help="Seconds to wait between events (default: 1.0)",
    )
    parser.add_argument(
        "--loop",
        action="store_true",
        help="Loop through the source file indefinitely",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress per-event console output",
    )
    args = parser.parse_args()

    if not args.source.exists():
        raise FileNotFoundError(f"Source file not found: {args.source}")

    args.target.parent.mkdir(parents=True, exist_ok=True)

    try:
        while True:
            for event_line in iter_events(args.source):
                append_event(args.target, event_line)
                if not args.quiet:
                    print(
                        f"[log-replayer] Wrote event to {args.target} "
                        f"(delay={args.interval:.2f}s)"
                    )
                time.sleep(max(args.interval, 0))
            if not args.loop:
                break
    except KeyboardInterrupt:
        print("\n[log-replayer] Interrupted by user")


if __name__ == "__main__":
    main()

