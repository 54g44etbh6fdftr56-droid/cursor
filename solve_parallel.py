#!/usr/bin/env python3
import socket
import threading
import binascii
import time
import sys
from typing import Tuple, List

HOST = ("94.237.49.106", 45383)
MENU_PROMPT = b"Your option: "
ENTER_PLAINTEXT = b"Enter plaintext: "

NUM_THREADS = int(sys.argv[1]) if len(sys.argv) > 1 else 8
MAX_ITERS_PER_THREAD = int(sys.argv[2]) if len(sys.argv) > 2 else 2000
PROGRESS_EVERY = 100

ALL_VALUES = 256

print_lock = threading.Lock()
state_lock = threading.Lock()


class Remote:
    def __init__(self, host: Tuple[str, int]):
        self.host = host
        self.sock = None
        self.connect()

    def connect(self):
        self.close()
        self.sock = socket.socket()
        self.sock.settimeout(10)
        self.sock.connect(self.host)
        self._recv_until(MENU_PROMPT)

    def _recv_until(self, token: bytes, timeout: float = 10.0) -> bytes:
        self.sock.settimeout(timeout)
        data = bytearray()
        while True:
            chunk = self.sock.recv(4096)
            if not chunk:
                break
            data.extend(chunk)
            if token in data:
                break
        return bytes(data)

    def _recv_line(self, timeout: float = 10.0) -> bytes:
        self.sock.settimeout(timeout)
        data = bytearray()
        while True:
            chunk = self.sock.recv(4096)
            if not chunk:
                break
            data.extend(chunk)
            if data.endswith(b"\n"):
                break
        return bytes(data).rstrip(b"\n")

    def get_flag_ct(self) -> bytes:
        try:
            self.sock.sendall(b"1\n")
            line = self._recv_line()
            _ = self._recv_until(MENU_PROMPT)
            return bytes.fromhex(line.decode().strip())
        except Exception:
            self.connect()
            return self.get_flag_ct()

    def encrypt_zero(self, length: int) -> bytes:
        try:
            self.sock.sendall(b"2\n")
            _ = self._recv_until(ENTER_PLAINTEXT)
            self.sock.sendall(binascii.hexlify(b"\x00" * length) + b"\n")
            line = self._recv_line()
            _ = self._recv_until(MENU_PROMPT)
            return bytes.fromhex(line.decode().strip())
        except Exception:
            self.connect()
            return self.encrypt_zero(length)

    def close(self):
        try:
            if self.sock:
                self.sock.close()
        except Exception:
            pass
        finally:
            self.sock = None


def worker(thread_id: int, length: int, obs_flag: List[List[bool]], obs_enc: List[List[bool]], ready_flag: List[bool], ready_enc: List[bool], done_evt: threading.Event):
    r = Remote(HOST)
    try:
        for i in range(MAX_ITERS_PER_THREAD):
            if done_evt.is_set():
                break
            cflag = r.get_flag_ct()
            if len(cflag) != length:
                # if server restarts, refresh length and reset local records in a safe way
                with state_lock:
                    # Clear observations
                    for j in range(min(length, len(cflag))):
                        pass
                # Restart connection and continue
                length = len(cflag)
            c0 = r.encrypt_zero(length)

            with state_lock:
                for j, b in enumerate(cflag):
                    if not ready_flag[j]:
                        obs_flag[j][b] = True
                for j, b in enumerate(c0):
                    if not ready_enc[j]:
                        obs_enc[j][b] = True

                # Check readiness
                changed = False
                for j in range(length):
                    if not ready_flag[j]:
                        # flag^kstr missing value is the only False among 256
                        if sum(obs_flag[j]) == 255:
                            ready_flag[j] = True
                            changed = True
                    if not ready_enc[j]:
                        if sum(obs_enc[j]) == 255:
                            ready_enc[j] = True
                            changed = True

                if (i + 1) % PROGRESS_EVERY == 0 or changed:
                    s_ready = sum(1 for j in range(length) if ready_enc[j])
                    f_ready = sum(1 for j in range(length) if ready_flag[j])
                    with print_lock:
                        print(f"[T{thread_id}] iter {i+1}: S {s_ready}/{length}, F^S {f_ready}/{length}")
                        sys.stdout.flush()

                if all(ready_flag) and all(ready_enc):
                    done_evt.set()
                    break
    finally:
        r.close()


def reconstruct(length: int, obs_flag: List[List[bool]], obs_enc: List[List[bool]]):
    # Missing value per position is the index where value is False
    fs = bytes([next(v for v in range(256) if not obs_flag[j][v]) for j in range(length)])
    s = bytes([next(v for v in range(256) if not obs_enc[j][v]) for j in range(length)])
    flag = bytes([fs[i] ^ s[i] for i in range(length)])
    return flag, fs, s


def main():
    # Determine flag length quickly
    r = Remote(HOST)
    ct = r.get_flag_ct()
    length = len(ct)
    r.close()

    obs_flag = [[False] * 256 for _ in range(length)]
    obs_enc = [[False] * 256 for _ in range(length)]
    ready_flag = [False] * length
    ready_enc = [False] * length

    done_evt = threading.Event()

    threads = []
    for t in range(NUM_THREADS):
        th = threading.Thread(target=worker, args=(t, length, obs_flag, obs_enc, ready_flag, ready_enc, done_evt), daemon=True)
        th.start()
        threads.append(th)

    # Wait with periodic progress and try to reconstruct if done
    start = time.time()
    try:
        while not done_evt.is_set():
            time.sleep(1.0)
            s_ready = sum(1 for j in range(length) if ready_enc[j])
            f_ready = sum(1 for j in range(length) if ready_flag[j])
            with print_lock:
                print(f"[Main] progress: S {s_ready}/{length}, F^S {f_ready}/{length}, elapsed {time.time()-start:.1f}s")
                sys.stdout.flush()
            if s_ready == length and f_ready == length:
                done_evt.set()
                break
    except KeyboardInterrupt:
        pass

    # Join threads briefly
    for th in threads:
        th.join(timeout=1.0)

    flag, fs, s = reconstruct(length, obs_flag, obs_enc)
    print("Recovered flag bytes:", flag)
    try:
        print("Recovered flag:", flag.decode())
    except Exception:
        pass


if __name__ == "__main__":
    main()