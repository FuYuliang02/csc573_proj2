#!/usr/bin/env python3
import sys
import socket
import struct
import time
from typing import List, Tuple

# Constants for packet types
DATA_TYPE = 0x5555  # 0101010101010101
ACK_TYPE  = 0xAAAA  # 1010101010101010

# Timeout in seconds
TIMEOUT_INTERVAL = 0.5


def udp_checksum(data: bytes) -> int:
    """
    Compute 16-bit UDP-style one's complement checksum over the given data.
    Only the data field is included (no pseudo-header etc., per assignment).
    """
    if len(data) % 2 == 1:
        data += b'\x00'

    checksum = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        checksum += word
        # Wrap around carry
        checksum = (checksum & 0xFFFF) + (checksum >> 16)

    # One's complement
    checksum = ~checksum & 0xFFFF
    return checksum


def make_data_packet(seq_num: int, payload: bytes) -> bytes:
    """
    Build a data packet: [seq_num (4B), checksum (2B), type (2B)] + payload
    """
    csum = udp_checksum(payload)
    # ! = network byte order, I = uint32, H = uint16
    header = struct.pack("!IHH", seq_num, csum, DATA_TYPE)
    return header + payload


def parse_ack_packet(packet: bytes) -> Tuple[int, int, int]:
    """
    Parse ACK packet header.
    Returns (seq_num, checksum_field, type_field).
    For ACK packets, checksum_field should be 0 and type_field == ACK_TYPE.
    """
    if len(packet) < 8:
        raise ValueError("ACK packet too short")

    seq_num, zero_field, pkt_type = struct.unpack("!IHH", packet[:8])
    return seq_num, zero_field, pkt_type


def read_file_segments(filename: str, MSS: int) -> List[bytes]:
    """
    Read the entire file and break it into MSS-sized chunks.
    """
    with open(filename, "rb") as f:
        data = f.read()

    segments = []
    for i in range(0, len(data), MSS):
        segments.append(data[i:i + MSS])

    # Edge case: empty file -> still send a single empty segment?
    # Many assignments don't require that, but we just return [] here.
    return segments


def gbn_send_file(
    server_addr: Tuple[str, int],
    filename: str,
    N: int,
    MSS: int
) -> None:
    """
    Implement Go-back-N sender:
    - Read file, build data packets.
    - Send with window size N over UDP to server_addr.
    - Handle ACKs and retransmissions on timeout.
    """
    segments = read_file_segments(filename, MSS)
    num_segments = len(segments)

    # Pre-build all packets with sequence numbers starting at 0
    packets: List[bytes] = []
    for seq, payload in enumerate(segments):
        packets.append(make_data_packet(seq, payload))

    # If file is empty, nothing to send; we could still send a special marker,
    # but assignment usually doesn't require that. We'll just return.
    if num_segments == 0:
        print("File is empty; nothing to send.")
        return

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT_INTERVAL)

    base = 0              # sequence number of oldest unACKed packet
    next_seq_num = 0      # sequence number of next packet to send

    # Start sending / receiving
    while base < num_segments:
        # Send packets within window
        while next_seq_num < base + N and next_seq_num < num_segments:
            sock.sendto(packets[next_seq_num], server_addr)
            # Start timer when we send the base packet
            if base == next_seq_num:
                # Reset the socket timeout timer implicitly
                sock.settimeout(TIMEOUT_INTERVAL)
            next_seq_num += 1

        try:
            # Wait for ACK
            ack_packet, _ = sock.recvfrom(1024)
            ack_seq, zero_field, pkt_type = parse_ack_packet(ack_packet)

            # Basic validation of ACK
            if pkt_type != ACK_TYPE:
                # Not an ACK packet; ignore
                continue

            # Go-back-N: if ACK for something in the window
            if base <= ack_seq < next_seq_num:
                # Advance base to ack_seq + 1
                base = ack_seq + 1

                # If all packets are ACKed, stop timer by disabling timeout
                if base == next_seq_num:
                    sock.settimeout(None)
                else:
                    # Still unACKed packets; keep timer running
                    sock.settimeout(TIMEOUT_INTERVAL)

            # Else: ACK is for a packet we've already fully processed; ignore

        except socket.timeout:
            # Timeout occurred: retransmit all unACKed packets
            # Y is the sequence number of the earliest unACKed packet (base)
            print(f"Timeout, sequence number = {base}")

            for seq in range(base, next_seq_num):
                sock.sendto(packets[seq], server_addr)

            # Restart timer (socket timeout already set)
            sock.settimeout(TIMEOUT_INTERVAL)

    sock.close()


def main():
    if len(sys.argv) != 6:
        print("Usage: python Simple_ftp_client.py "
              "server-host-name server-port file-name N MSS")
        sys.exit(1)

    server_host = sys.argv[1]
    server_port = int(sys.argv[2])
    filename    = sys.argv[3]
    N           = int(sys.argv[4])  # window size
    MSS         = int(sys.argv[5])  # max segment size in bytes

    server_addr = (server_host, server_port)

    gbn_send_file(server_addr, filename, N, MSS)


if __name__ == "__main__":
    main()
