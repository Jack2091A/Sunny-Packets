#!/usr/bin/env python3
"""
exposure_score.py

Parse normal (-oN) or terminal-copied Nmap TCP/UDP scan output and calculate:

    TCP Score = max(0, 7.5 - 0.75 × number_of_exposed_TCP_ports)
    UDP Score = max(0, 7.5 - 0.75 × number_of_exposed_UDP_ports)

By default, both "open" and "open|filtered" ports are treated as exposed.
Use --strict-open to count only ports whose state is exactly "open".
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


PORT_LINE_RE = re.compile(
    r"^\s*(?P<port>\d+)\/(?P<protocol>tcp|udp)\s+"
    r"(?P<state>\S+)"
    r"(?:\s+(?P<service>\S+))?"
    r"(?:\s+(?P<version>.*))?\s*$",
    re.IGNORECASE,
)

DEFAULT_BASE_SCORE = 7.5
DEFAULT_PENALTY = 0.75


@dataclass(frozen=True)
class PortRecord:
    port: int
    protocol: str
    state: str
    service: str = ""
    version: str = ""


def parse_nmap_text(text: str) -> list[PortRecord]:
    """Extract TCP/UDP port rows from Nmap text output."""
    records: list[PortRecord] = []

    for line in text.splitlines():
        match = PORT_LINE_RE.match(line)
        if not match:
            continue

        records.append(
            PortRecord(
                port=int(match.group("port")),
                protocol=match.group("protocol").lower(),
                state=match.group("state").lower(),
                service=(match.group("service") or "").strip(),
                version=(match.group("version") or "").strip(),
            )
        )

    return records


def exposed_records(
    records: Iterable[PortRecord],
    *,
    count_open_filtered: bool = True,
) -> list[PortRecord]:
    """Return records considered externally exposed."""
    exposed_states = {"open"}
    if count_open_filtered:
        exposed_states.add("open|filtered")

    return [record for record in records if record.state in exposed_states]


def calculate_score(
    exposed_port_count: int,
    *,
    base_score: float = DEFAULT_BASE_SCORE,
    penalty: float = DEFAULT_PENALTY,
) -> float:
    """Calculate the bounded network exposure score."""
    return max(0.0, base_score - penalty * exposed_port_count)


def format_port(record: PortRecord) -> str:
    details = f"{record.port}/{record.protocol}  {record.state}"
    if record.service:
        details += f"  {record.service}"
    if record.version:
        details += f"  {record.version}"
    return details


def analyse_file(
    path: Path,
    *,
    count_open_filtered: bool,
    base_score: float,
    penalty: float,
) -> dict[str, object]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise RuntimeError(f"Could not read '{path}': {exc}") from exc

    records = parse_nmap_text(text)
    exposed = exposed_records(
        records,
        count_open_filtered=count_open_filtered,
    )

    result: dict[str, object] = {
        "file": str(path),
        "records": records,
        "exposed": exposed,
        "scores": {},
    }

    scores: dict[str, dict[str, float | int]] = {}
    for protocol in ("tcp", "udp"):
        protocol_ports = [r for r in exposed if r.protocol == protocol]
        if protocol_ports:
            scores[protocol] = {
                "exposed_count": len(protocol_ports),
                "score": calculate_score(
                    len(protocol_ports),
                    base_score=base_score,
                    penalty=penalty,
                ),
            }

    result["scores"] = scores
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Calculate TCP and UDP network exposure scores from Nmap text output."
    )
    parser.add_argument(
        "files",
        nargs="+",
        type=Path,
        help="One or more .txt files containing Nmap output.",
    )
    parser.add_argument(
        "--strict-open",
        action="store_true",
        help='Count only ports with state "open"; ignore "open|filtered".',
    )
    parser.add_argument(
        "--base-score",
        type=float,
        default=DEFAULT_BASE_SCORE,
        help=f"Starting score before penalties (default: {DEFAULT_BASE_SCORE}).",
    )
    parser.add_argument(
        "--penalty",
        type=float,
        default=DEFAULT_PENALTY,
        help=f"Penalty per exposed port (default: {DEFAULT_PENALTY}).",
    )
    parser.add_argument(
        "--summary-only",
        action="store_true",
        help="Do not list individual exposed ports.",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()

    if args.base_score < 0:
        print("Error: --base-score cannot be negative.", file=sys.stderr)
        return 2
    if args.penalty < 0:
        print("Error: --penalty cannot be negative.", file=sys.stderr)
        return 2

    count_open_filtered = not args.strict_open
    combined_exposed: dict[str, set[int]] = {"tcp": set(), "udp": set()}
    successful_files = 0

    for path in args.files:
        try:
            result = analyse_file(
                path,
                count_open_filtered=count_open_filtered,
                base_score=args.base_score,
                penalty=args.penalty,
            )
        except RuntimeError as exc:
            print(f"Error: {exc}", file=sys.stderr)
            continue

        successful_files += 1
        records = result["records"]
        exposed = result["exposed"]
        scores = result["scores"]

        print(f"\nFile: {path}")
        if not records:
            print("  No Nmap TCP/UDP port-table rows were found.")
            continue

        for record in exposed:
            combined_exposed[record.protocol].add(record.port)

        for protocol in ("tcp", "udp"):
            protocol_exposed = [r for r in exposed if r.protocol == protocol]
            if not protocol_exposed:
                continue

            score_data = scores[protocol]
            print(
                f"  {protocol.upper()} exposed ports: "
                f"{score_data['exposed_count']}"
            )
            print(
                f"  {protocol.upper()} score: "
                f"max(0, {args.base_score:g} - {args.penalty:g} × "
                f"{score_data['exposed_count']}) = {score_data['score']:.2f}/10"
            )

            if not args.summary_only:
                for record in protocol_exposed:
                    print(f"    - {format_port(record)}")

    if successful_files == 0:
        return 1

    if len(args.files) > 1:
        print("\nCombined unique-port summary:")
        for protocol in ("tcp", "udp"):
            count = len(combined_exposed[protocol])
            if count == 0:
                continue
            score = calculate_score(
                count,
                base_score=args.base_score,
                penalty=args.penalty,
            )
            print(
                f"  {protocol.upper()}: {count} exposed unique port(s), "
                f"score = {score:.2f}/10"
            )

     # Overall percentage (out of 15)
    tcp_score = calculate_score(len(combined_exposed["tcp"]),
                                base_score=args.base_score,
                                penalty=args.penalty)
    udp_score = calculate_score(len(combined_exposed["udp"]),
                                base_score=args.base_score,
                                penalty=args.penalty)

    combined_percentage = ((tcp_score + udp_score) / (2 * args.base_score)) * 100
    print(f"\nCombined Percentage: {combined_percentage:.2f}%")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())