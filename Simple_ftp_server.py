#!/usr/bin/env python3
import sys
import socket
import struct
import random
from typing import Tuple

# Packet types
DATA_TYPE = 0x5555  # 0101010101010101
ACK_TYPE  = 0xAAAA  # 1010101010101010

HEADER_FORMAT = "!IHH"  # seq_num (4B), checksum (2B), type (2B)
HEADER_SIZE = 8


def udp_checksum(data: bytes) -> int:
    """
    Compute 16-bit UDP-style one's complement checksum over data.
    Same as client: only data part (no pseudo-header).
    """
    if len(data) % 2 == 1:
        data += b'\x00'

    checksum = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        checksum += word
        checksum = (checksum & 0xFFFF) + (checksum >> 16)

    checksum = ~checksum & 0xFFFF
    return checksum


def parse_data_packet(packet: bytes) -> Tuple[int, int, int, bytes]:
    """
    Parse a data packet into (seq_num, checksum_field, type_field, payload).
    Raises ValueError if packet is too short.
    """
    if len(packet) < HEADER_SIZE:
        raise ValueError("Received packet too short")

    seq_num, checksum_field, pkt_type = struct.unpack(
        HEADER_FORMAT, packet[:HEADER_SIZE]
    )
    payload = packet[HEADER_SIZE:]
    return seq_num, checksum_field, pkt_type, payload


def make_ack_packet(seq_num: int) -> bytes:
    """
    Build an ACK packet:
    [seq_num (4B), zero_field (2B, all zeros), type (2B = ACK_TYPE)]
    """
    zero_field = 0
    header = struct.pack(HEADER_FORMAT, seq_num, zero_field, ACK_TYPE)
    return header  # no payload


def main():
    if len(sys.argv) != 4:
        print("Usage: python Simple_ftp_server.py port file-name p")
        sys.exit(1)

    port = int(sys.argv[1])
    out_filename = sys.argv[2]
    loss_prob = float(sys.argv[3])  # 0 < p < 1

    if not (0.0 < loss_prob < 1.0):
        print("Error: p must be in (0, 1)")
        sys.exit(1)

    # Seed random generator (optional, but nice to have)
    random.seed()

    # Prepare UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("", port))  # listen on all interfaces

    print(f"Simple-FTP server listening on port {port}")
    print(f"Writing received data to file: {out_filename}")
    print(f"Packet loss probability p = {loss_prob}")

    # Open output file for writing (wb: overwrite each run)
    with open(out_filename, "wb") as outfile:
        expected_seq_num = 0

        while True:
            # Receive a packet (blocking)
            packet, client_addr = sock.recvfrom(65535)  # large enough buffer

            # Try to parse header to know sequence number,
            # even if we end up discarding by probabilistic loss.
            try:
                seq_num, checksum_field, pkt_type, payload = parse_data_packet(packet)
            except ValueError:
                # Malformed packet; ignore
                continue

            # Only care about DATA packets for loss simulation
            if pkt_type != DATA_TYPE:
                # Not a data packet: ignore silently
                continue

            # Probabilistic loss
            r = random.random()  # r in [0.0, 1.0)
            if r <= loss_prob:
                # Simulate loss: drop packet, print message, and do nothing else
                print(f"Packet loss, sequence number = {seq_num}")
                continue

            # Now apply Go-back-N receiver logic

            # 1) Check checksum
            computed_csum = udp_checksum(payload)
            if computed_csum != checksum_field:
                # Corrupted packet: ignore (no ACK)
                # (Spec: "If ... checksum is incorrect, it does nothing.")
                continue

            # 2) Check if in-sequence
            if seq_num == expected_seq_num:
                # In-sequence packet: accept
                outfile.write(payload)
                outfile.flush()

                # Send ACK
                ack_packet = make_ack_packet(seq_num)
                sock.sendto(ack_packet, client_addr)

                # Move window forward
                expected_seq_num += 1
            else:
                # Out-of-sequence packet: ignore, no ACK (per spec)
                # ("If the packet received is out-of-sequence ... it does nothing.")
                continue


if __name__ == "__main__":
    main()
