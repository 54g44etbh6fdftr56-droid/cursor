#!/usr/bin/env python3
import socket
import sys
import time
import binascii
from typing import Tuple, List, Set

HOST = ("94.237.49.106", 45383)

MENU_PROMPT = b"Your option: "
ENTER_PLAINTEXT = b"Enter plaintext: "
ENTER_CIPHERTEXT = b"Enter ciphertext: "

ALL_VALUES = set(range(256))


def recv_until(sock: socket.socket, token: bytes, timeout: float = 10.0) -> bytes:
    sock.settimeout(timeout)
    data = bytearray()
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data.extend(chunk)
        if token in data:
            break
    return bytes(data)


def recv_line(sock: socket.socket, timeout: float = 10.0) -> bytes:
    sock.settimeout(timeout)
    data = bytearray()
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data.extend(chunk)
        if data.endswith(b"\n"):
            break
    return bytes(data).rstrip(b"\n")


class Remote:
    def __init__(self, host: Tuple[str, int]):
        self.sock = socket.socket()
        self.sock.settimeout(10)
        self.sock.connect(host)
        _ = recv_until(self.sock, MENU_PROMPT)

    def get_flag_ct(self) -> bytes:
        self.sock.sendall(b"1\n")
        line = recv_line(self.sock, timeout=10)
        _ = recv_until(self.sock, MENU_PROMPT)
        return bytes.fromhex(line.decode().strip())

    def encrypt(self, pt_bytes: bytes) -> bytes:
        self.sock.sendall(b"2\n")
        _ = recv_until(self.sock, ENTER_PLAINTEXT)
        self.sock.sendall(binascii.hexlify(pt_bytes) + b"\n")
        line = recv_line(self.sock, timeout=10)
        _ = recv_until(self.sock, MENU_PROMPT)
        return bytes.fromhex(line.decode().strip())

    def close(self) -> None:
        try:
            self.sock.close()
        except Exception:
            pass


def try_recover(iterations: int = 3000) -> None:
    r = Remote(HOST)
    try:
        flag_ct = r.get_flag_ct()
        length = len(flag_ct)
        print(f"Flag length: {length} bytes", flush=True)

        obs_enc: List[Set[int]] = [set() for _ in range(length)]
        obs_flag: List[Set[int]] = [set() for _ in range(length)]

        for i in range(iterations):
            # sample flag ciphertext
            cflag = r.get_flag_ct()
            if len(cflag) != length:
                # length mismatch implies new key/iv/otp session; restart accumulation
                length = len(cflag)
                obs_enc = [set() for _ in range(length)]
                obs_flag = [set() for _ in range(length)]
            for j, b in enumerate(cflag):
                obs_flag[j].add(b)

            # sample encryption of zero bytes
            c0 = r.encrypt(b"\x00" * length)
            if len(c0) != length:
                # align to latest length
                length = len(c0)
                obs_enc = [set() for _ in range(length)]
                obs_flag = [set() for _ in range(length)]
            for j, b in enumerate(c0):
                obs_enc[j].add(b)

            if (i + 1) % 50 == 0:
                s_ready = sum(1 for j in range(length) if len(ALL_VALUES - obs_enc[j]) == 1)
                fs_ready = sum(1 for j in range(length) if len(ALL_VALUES - obs_flag[j]) == 1)
                print(f"iter {i+1}: S ready {s_ready}/{length}, F^S ready {fs_ready}/{length}", flush=True)
                # early exit if done
                if s_ready == length and fs_ready == length:
                    break

        miss_s = [list(ALL_VALUES - obs_enc[j]) for j in range(length)]
        miss_f = [list(ALL_VALUES - obs_flag[j]) for j in range(length)]

        if not all(len(m) == 1 for m in miss_s) or not all(len(m) == 1 for m in miss_f):
            unresolved_s = [idx for idx, m in enumerate(miss_s) if len(m) != 1]
            unresolved_f = [idx for idx, m in enumerate(miss_f) if len(m) != 1]
            print(f"Unresolved S positions: {unresolved_s}")
            print(f"Unresolved F^S positions: {unresolved_f}")

        S = bytes(m[0] if m else 0 for m in miss_s)
        FS = bytes(m[0] if m else 0 for m in miss_f)
        flag = bytes(FS[i] ^ S[i] for i in range(length))
        print("Recovered flag:", flag)
        try:
            print("Recovered flag (utf-8):", flag.decode())
        except Exception:
            pass
    finally:
        r.close()


if __name__ == "__main__":
    iters = int(sys.argv[1]) if len(sys.argv) > 1 else 2000
    try_recover(iters)