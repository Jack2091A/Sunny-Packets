#!/usr/bin/env python3
"""
PCAP Data Sovereignty Analyser

Scores a device's network traffic as:
  100 - all observed public-IP communications are domestic
   50 - at least one overseas connection attempt, but no confirmed overseas data exchange
    0 - at least one successful overseas data transmission or exchange

The device is identified by MAC address. Public peer IP addresses are geolocated
using a local MaxMind GeoLite2 Country database.
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import geoip2.database
import geoip2.errors
import pycountry
from scapy.all import IP, IPv6, TCP, UDP, Ether, PcapReader, Raw


TCP_SYN = 0x02
TCP_ACK = 0x10
TCP_RST = 0x04
TCP_FIN = 0x01


@dataclass
class EndpointEvidence:
    ip: str
    country_code: Optional[str]
    country_name: str
    outbound_packets: int = 0
    inbound_packets: int = 0
    outbound_bytes: int = 0
    inbound_bytes: int = 0
    outbound_payload_bytes: int = 0
    inbound_payload_bytes: int = 0
    outbound_syn: int = 0
    inbound_syn_ack: int = 0
    inbound_responses: int = 0
    protocols: set[str] = field(default_factory=set)
    ports: set[str] = field(default_factory=set)

    @property
    def successful_exchange(self) -> bool:
        """
        Conservative evidence that overseas data passed:
        - application payload left the device; or
        - the peer replied; or
        - a TCP SYN-ACK was observed.

        An isolated outbound TCP SYN with no reply and no payload is treated as
        an unsuccessful attempt.
        """
        return (
            self.outbound_payload_bytes > 0
            or self.inbound_payload_bytes > 0
            or self.inbound_responses > 0
            or self.inbound_syn_ack > 0
        )

    @property
    def attempted_only(self) -> bool:
        return self.outbound_packets > 0 and not self.successful_exchange


def normalise_mac(mac: str) -> str:
    cleaned = mac.strip().lower().replace("-", ":")
    parts = cleaned.split(":")
    if len(parts) != 6 or any(len(p) != 2 for p in parts):
        raise ValueError(f"Invalid MAC address: {mac}")
    try:
        int("".join(parts), 16)
    except ValueError as exc:
        raise ValueError(f"Invalid MAC address: {mac}") from exc
    return cleaned


def country_to_iso(value: str) -> str:
    value = value.strip()
    if len(value) == 2 and value.isalpha():
        result = pycountry.countries.get(alpha_2=value.upper())
    elif len(value) == 3 and value.isalpha():
        result = pycountry.countries.get(alpha_3=value.upper())
    else:
        try:
            result = pycountry.countries.lookup(value)
        except LookupError:
            result = None

    if result is None:
        raise ValueError(
            f"Unknown target country '{value}'. Use a country name or ISO code, "
            "for example Australia or AU."
        )
    return result.alpha_2


def is_public_peer(ip_text: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_text)
    except ValueError:
        return False

    # Exclude addresses that cannot represent an Internet destination.
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_unspecified
        or ip.is_reserved
    )


def packet_payload_length(packet) -> int:
    """
    Count application payload where Scapy exposes Raw data.
    This avoids treating TCP/IP headers as transmitted application data.
    """
    if Raw in packet:
        try:
            return len(bytes(packet[Raw].load))
        except Exception:
            return 0
    return 0


def protocol_and_ports(packet, direction: str) -> tuple[str, Optional[str]]:
    if TCP in packet:
        tcp = packet[TCP]
        peer_port = tcp.dport if direction == "outbound" else tcp.sport
        return "TCP", f"TCP/{peer_port}"
    if UDP in packet:
        udp = packet[UDP]
        peer_port = udp.dport if direction == "outbound" else udp.sport
        return "UDP", f"UDP/{peer_port}"

    if IP in packet:
        return f"IP/{packet[IP].proto}", None
    if IPv6 in packet:
        return f"IPv6/{packet[IPv6].nh}", None
    return "Other", None


def geolocate(reader: geoip2.database.Reader, ip_text: str) -> tuple[Optional[str], str]:
    try:
        response = reader.country(ip_text)
        code = response.country.iso_code
        name = response.country.name or "Unknown"
        return code, name
    except (geoip2.errors.AddressNotFoundError, ValueError):
        return None, "Unknown"


def analyse_pcap(
    pcap_path: Path,
    device_mac: str,
    target_country: str,
    database_path: Path,
) -> tuple[int, str, dict[str, EndpointEvidence], dict[str, int]]:
    evidence: dict[str, EndpointEvidence] = {}
    counters = defaultdict(int)

    with geoip2.database.Reader(str(database_path)) as geo_reader:
        with PcapReader(str(pcap_path)) as packets:
            for packet in packets:
                counters["total_packets"] += 1

                if Ether not in packet:
                    counters["non_ethernet_packets"] += 1
                    continue

                src_mac = packet[Ether].src.lower()
                dst_mac = packet[Ether].dst.lower()

                if src_mac == device_mac:
                    direction = "outbound"
                elif dst_mac == device_mac:
                    direction = "inbound"
                else:
                    continue

                counters["device_packets"] += 1

                if IP in packet:
                    src_ip, dst_ip = packet[IP].src, packet[IP].dst
                elif IPv6 in packet:
                    src_ip, dst_ip = packet[IPv6].src, packet[IPv6].dst
                else:
                    counters["device_non_ip_packets"] += 1
                    continue

                peer_ip = dst_ip if direction == "outbound" else src_ip

                if not is_public_peer(peer_ip):
                    counters["local_or_special_ip_packets"] += 1
                    continue

                counters["public_peer_packets"] += 1

                if peer_ip not in evidence:
                    code, name = geolocate(geo_reader, peer_ip)
                    evidence[peer_ip] = EndpointEvidence(
                        ip=peer_ip,
                        country_code=code,
                        country_name=name,
                    )

                item = evidence[peer_ip]
                packet_len = len(packet)
                payload_len = packet_payload_length(packet)
                protocol, port = protocol_and_ports(packet, direction)
                item.protocols.add(protocol)
                if port:
                    item.ports.add(port)

                if direction == "outbound":
                    item.outbound_packets += 1
                    item.outbound_bytes += packet_len
                    item.outbound_payload_bytes += payload_len

                    if TCP in packet:
                        flags = int(packet[TCP].flags)
                        if flags & TCP_SYN and not flags & TCP_ACK:
                            item.outbound_syn += 1
                else:
                    item.inbound_packets += 1
                    item.inbound_bytes += packet_len
                    item.inbound_payload_bytes += payload_len
                    item.inbound_responses += 1

                    if TCP in packet:
                        flags = int(packet[TCP].flags)
                        if flags & TCP_SYN and flags & TCP_ACK:
                            item.inbound_syn_ack += 1

    overseas = [
        item for item in evidence.values()
        if item.country_code is not None and item.country_code != target_country
    ]
    unknown = [item for item in evidence.values() if item.country_code is None]

    successful_overseas = [item for item in overseas if item.successful_exchange]
    attempted_overseas = [item for item in overseas if item.attempted_only]

    if successful_overseas:
        score = 0
        status = "WARNING: successful overseas data transmission or exchange detected"
    elif attempted_overseas:
        score = 50
        status = "WARNING: unsuccessful overseas connection attempt detected"
    else:
        score = 100
        status = "PASS: no overseas communication detected"

    counters["unique_public_endpoints"] = len(evidence)
    counters["overseas_endpoints"] = len(overseas)
    counters["successful_overseas_endpoints"] = len(successful_overseas)
    counters["attempted_overseas_endpoints"] = len(attempted_overseas)
    counters["unknown_location_endpoints"] = len(unknown)

    return score, status, evidence, dict(counters)


def write_csv(
    output_path: Path,
    evidence: dict[str, EndpointEvidence],
    target_country: str,
) -> None:
    fieldnames = [
        "peer_ip",
        "country_code",
        "country_name",
        "classification",
        "evidence",
        "outbound_packets",
        "inbound_packets",
        "outbound_bytes",
        "inbound_bytes",
        "outbound_payload_bytes",
        "inbound_payload_bytes",
        "protocols",
        "peer_ports",
    ]

    with output_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()

        for item in sorted(evidence.values(), key=lambda x: (x.country_name, x.ip)):
            if item.country_code is None:
                classification = "Unknown location"
            elif item.country_code == target_country:
                classification = "Domestic"
            else:
                classification = "Overseas"

            if item.successful_exchange:
                observed = "Successful exchange/data observed"
            elif item.attempted_only:
                observed = "Attempt only"
            else:
                observed = "Observed"

            writer.writerow({
                "peer_ip": item.ip,
                "country_code": item.country_code or "",
                "country_name": item.country_name,
                "classification": classification,
                "evidence": observed,
                "outbound_packets": item.outbound_packets,
                "inbound_packets": item.inbound_packets,
                "outbound_bytes": item.outbound_bytes,
                "inbound_bytes": item.inbound_bytes,
                "outbound_payload_bytes": item.outbound_payload_bytes,
                "inbound_payload_bytes": item.inbound_payload_bytes,
                "protocols": ", ".join(sorted(item.protocols)),
                "peer_ports": ", ".join(sorted(item.ports)),
            })


def print_report(
    score: int,
    status: str,
    evidence: dict[str, EndpointEvidence],
    counters: dict[str, int],
    target_country: str,
) -> None:
    target_name = pycountry.countries.get(alpha_2=target_country).name

    print("=" * 72)
    print("DATA SOVEREIGNTY ANALYSIS")
    print("=" * 72)
    print(f"Target country : {target_name} ({target_country})")
    print(f"Score          : {score}/100")
    print(f"Result         : {status}")
    print()

    print("Capture summary")
    print(f"  Total packets scanned       : {counters.get('total_packets', 0)}")
    print(f"  Packets involving device    : {counters.get('device_packets', 0)}")
    print(f"  Public-IP packets            : {counters.get('public_peer_packets', 0)}")
    print(f"  Unique public endpoints      : {counters.get('unique_public_endpoints', 0)}")
    print(f"  Overseas endpoints           : {counters.get('overseas_endpoints', 0)}")
    print(f"  Unknown-location endpoints   : {counters.get('unknown_location_endpoints', 0)}")
    print()

    if not evidence:
        print("No public Internet endpoints were found for the selected MAC address.")
        print("Check that the capture interface can see the device's original Ethernet MAC.")
        return

    print("Endpoints")
    for item in sorted(evidence.values(), key=lambda x: (x.country_name, x.ip)):
        if item.country_code is None:
            location = "UNKNOWN"
            marker = "?"
        elif item.country_code == target_country:
            location = f"{item.country_name} ({item.country_code})"
            marker = "DOMESTIC"
        else:
            location = f"{item.country_name} ({item.country_code})"
            marker = "OVERSEAS"

        if item.successful_exchange:
            outcome = "successful exchange/data"
        elif item.attempted_only:
            outcome = "attempt only"
        else:
            outcome = "observed"

        print(
            f"  [{marker:8}] {item.ip:39} {location:28} {outcome}"
        )
        print(
            f"             out={item.outbound_packets} pkts/"
            f"{item.outbound_payload_bytes} payload bytes, "
            f"in={item.inbound_packets} pkts/"
            f"{item.inbound_payload_bytes} payload bytes, "
            f"ports={', '.join(sorted(item.ports)) or '-'}"
        )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Score device data sovereignty from a PCAP capture."
    )
    parser.add_argument("pcap", type=Path, help="Input .pcap or .pcapng file")
    parser.add_argument(
        "--mac",
        required=True,
        help="MAC address of the device to track, e.g. 00:11:22:33:44:55",
    )
    parser.add_argument(
        "--target-country",
        required=True,
        help="Expected country name or ISO code, e.g. Australia or AU",
    )
    parser.add_argument(
        "--geoip-db",
        required=True,
        type=Path,
        help="Path to GeoLite2-Country.mmdb",
    )
    parser.add_argument(
        "--csv",
        type=Path,
        help="Optional CSV report path",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()

    try:
        device_mac = normalise_mac(args.mac)
        target_country = country_to_iso(args.target_country)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    if not args.pcap.is_file():
        print(f"Error: PCAP file not found: {args.pcap}", file=sys.stderr)
        return 2
    if not args.geoip_db.is_file():
        print(f"Error: GeoIP database not found: {args.geoip_db}", file=sys.stderr)
        return 2

    try:
        score, status, evidence, counters = analyse_pcap(
            args.pcap,
            device_mac,
            target_country,
            args.geoip_db,
        )
    except Exception as exc:
        print(f"Analysis failed: {exc}", file=sys.stderr)
        return 1

    print_report(score, status, evidence, counters, target_country)

    if args.csv:
        write_csv(args.csv, evidence, target_country)
        print(f"\nCSV report written to: {args.csv}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
