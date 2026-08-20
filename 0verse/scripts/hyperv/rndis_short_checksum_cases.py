#!/usr/bin/env python3
"""Build inert RNDIS packet-message fixtures for the held vmSwitch candidate.

This module only serializes bytes.  It has no VMBus, socket, ioctl, module-load,
or network-send path, so generating fixtures cannot exercise a Hyper-V host.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from dataclasses import asdict, dataclass
from pathlib import Path

RNDIS_MSG_PACKET = 0x00000001
RNDIS_HEADER_SIZE = 8
RNDIS_PACKET_SIZE = 36
RNDIS_PPI_SIZE = 12
NDIS_CSUM_INFO_SIZE = 4
NDIS_CSUM_PPI_SIZE = RNDIS_PPI_SIZE + NDIS_CSUM_INFO_SIZE
TCPIP_CHKSUM_PKTINFO = 0

# ndis_tcp_ip_checksum_info.transmit bit positions from Linux hyperv_net.h.
NDIS_TX_IS_IPV4 = 1 << 0
NDIS_TX_IP_HEADER_CHECKSUM = 1 << 4


@dataclass(frozen=True)
class Case:
    name: str
    data_len: int
    checksum_metadata: bool
    purpose: str


CASES = (
    Case("target-len0-ipv4-checksum", 0, True, "minimum wrapped-length target"),
    Case("target-len13-ipv4-checksum", 13, True, "boundary wrapped-length target"),
    Case("control-len13-no-checksum", 13, False, "metadata-matched negative control"),
    Case("control-len14-ipv4-checksum", 14, True, "non-wrapping length control"),
    Case("control-len64-ipv4-checksum", 64, True, "ordinary-length control"),
)


def build_packet(data_len: int, checksum_metadata: bool) -> bytes:
    """Return one little-endian RNDIS packet message with deterministic data."""
    if not 0 <= data_len <= 0xFFFFFFFF:
        raise ValueError("data_len must fit in u32")

    ppi = b""
    if checksum_metadata:
        checksum = NDIS_TX_IS_IPV4 | NDIS_TX_IP_HEADER_CHECKSUM
        ppi = struct.pack(
            "<IIII",
            NDIS_CSUM_PPI_SIZE,
            TCPIP_CHKSUM_PKTINFO,
            RNDIS_PPI_SIZE,
            checksum,
        )

    data_offset = RNDIS_PACKET_SIZE + len(ppi)
    message_len = RNDIS_HEADER_SIZE + RNDIS_PACKET_SIZE + len(ppi) + data_len
    packet = struct.pack(
        "<IIIIIIIII",
        data_offset,
        data_len,
        0,
        0,
        0,
        RNDIS_PACKET_SIZE if ppi else 0,
        len(ppi),
        0,
        0,
    )
    # A deterministic zero body intentionally avoids pretending that a short
    # input is a valid Ethernet/IP frame; parser acceptance is the experiment.
    return struct.pack("<II", RNDIS_MSG_PACKET, message_len) + packet + ppi + bytes(data_len)


def describe(case: Case, blob: bytes) -> dict[str, object]:
    return {
        **asdict(case),
        "message_len": len(blob),
        "sha256": hashlib.sha256(blob).hexdigest(),
        "hex": blob.hex(),
    }


def write_fixture_set(output: Path) -> list[dict[str, object]]:
    output.mkdir(parents=True, exist_ok=True)
    manifest: list[dict[str, object]] = []
    for case in CASES:
        blob = build_packet(case.data_len, case.checksum_metadata)
        (output / f"{case.name}.rndis").write_bytes(blob)
        manifest.append(describe(case, blob))
    (output / "manifest.json").write_text(
        json.dumps({"format": "0verse-rndis-fixtures-v1", "cases": manifest}, indent=2)
        + "\n",
        encoding="utf-8",
    )
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="write inert fixtures and manifest")
    parser.add_argument("--list", action="store_true", help="print the deterministic manifest")
    args = parser.parse_args()
    if bool(args.output) == bool(args.list):
        parser.error("choose exactly one of --output or --list")
    if args.output:
        manifest = write_fixture_set(args.output)
    else:
        manifest = [describe(case, build_packet(case.data_len, case.checksum_metadata)) for case in CASES]
    print(json.dumps({"format": "0verse-rndis-fixtures-v1", "cases": manifest}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
