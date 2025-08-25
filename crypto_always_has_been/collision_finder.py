#!/usr/bin/python3
"""
Collision finder - maybe ANY 32-byte input that produces the target hash is valid
"""

import random
import time

KEY_SBOX = [170, 89, 81, 162, 65, 178, 186, 73, 97, 146, 154, 105, 138, 121, 113, 130, 33, 210, 218, 41, 202, 57, 49, 194, 234, 25, 17, 226, 1, 242, 250, 9, 161, 82, 90, 169, 74, 185, 177, 66, 106, 153, 145, 98, 129, 114, 122, 137, 42, 217, 209, 34, 193, 50, 58, 201, 225, 18, 26, 233, 10, 249, 241, 2, 188, 79, 71, 180, 87, 164, 172, 95, 119, 132, 140, 127, 156, 111, 103, 148, 55, 196, 204, 63, 220, 47, 39, 212, 252, 15, 7, 244, 23, 228, 236, 31, 183, 68, 76, 191, 92, 175, 167, 84, 124, 143, 135, 116, 151, 100, 108, 159, 60, 207, 199, 52, 215, 36, 44, 223, 247, 4, 12, 255, 28, 239, 231, 20, 134, 117, 125, 142, 109, 158, 150, 101, 77, 190, 182, 69, 166, 85, 93, 174, 13, 254, 246, 5, 230, 21, 29, 238, 198, 53, 61, 206, 45, 222, 214, 37, 141, 126, 118, 133, 102, 149, 157, 110, 70, 181, 189, 78, 173, 94, 86, 165, 6, 245, 253, 14, 237, 30, 22, 229, 205, 62, 54, 197, 38, 213, 221, 46, 144, 99, 107, 152, 123, 136, 128, 115, 91, 168, 160, 83, 176, 67, 75, 184, 27, 232, 224, 19, 240, 3, 11, 248, 208, 35, 43, 216, 59, 200, 192, 51, 155, 104, 96, 147, 112, 131, 139, 120, 80, 163, 171, 88, 187, 72, 64, 179, 16, 227, 235, 24, 251, 8, 0, 243, 219, 40, 32, 211, 48, 195, 203, 56]
PBOX = [59, 82, 101, 135, 189, 153, 105, 14, 179, 71, 167, 33, 160, 198, 218, 104, 66, 37, 216, 199, 132, 214, 217, 42, 231, 221, 236, 233, 203, 24, 220, 120, 158, 240, 84, 81, 152, 201, 57, 253, 249, 169, 79, 234, 136, 12, 40, 209, 29, 224, 17, 77, 60, 102, 195, 8, 212, 95, 147, 190, 138, 213, 98, 10, 4, 243, 1, 128, 145, 58, 241, 119, 88, 211, 110, 157, 3, 188, 19, 208, 44, 244, 122, 92, 109, 69, 134, 22, 90, 61, 202, 193, 141, 183, 133, 75, 144, 116, 191, 39, 207, 140, 192, 247, 83, 43, 121, 99, 254, 226, 177, 26, 9, 173, 78, 176, 223, 210, 156, 16, 227, 125, 93, 54, 76, 150, 5, 36, 185, 65, 72, 246, 131, 41, 106, 248, 151, 182, 204, 225, 229, 70, 7, 250, 115, 85, 163, 124, 184, 130, 239, 196, 15, 100, 252, 25, 171, 143, 0, 67, 222, 96, 165, 180, 46, 232, 117, 48, 38, 161, 50, 35, 73, 18, 154, 114, 175, 146, 148, 89, 80, 112, 228, 49, 172, 63, 123, 86, 149, 103, 230, 64, 28, 27, 166, 111, 170, 55, 47, 20, 51, 215, 32, 13, 118, 11, 53, 205, 238, 91, 6, 94, 200, 181, 162, 178, 194, 126, 164, 2, 255, 137, 242, 23, 74, 197, 142, 108, 52, 187, 129, 186, 155, 97, 107, 34, 245, 68, 56, 127, 21, 219, 159, 62, 113, 237, 206, 45, 251, 168, 87, 31, 30, 235, 174, 139]
BLOCK_SIZE = 32

target = bytes.fromhex("61b5649e894a15a053276c0dc828ee64ec2336f809e2dd7d2912c61c8ef02c26")

def xor(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])

class SecureCipher:
    def __init__(self, key):
        self.sbox = [KEY_SBOX[i] ^ key[0] for i in range(256)]
        self.key = key
    
    def substitute(self, data):
        return bytes([self.sbox[b] for b in data])
    
    def permute(self, data):
        out = [0]*32
        for num in range(256):
            outnum = PBOX[num]
            inbyte = num // 8
            inbit = 7 - (num % 8)
            outbyte = outnum // 8
            outbit = 7 - (outnum % 8)
            
            if data[inbyte] & (1 << inbit):
                out[outbyte] |= (1 << outbit)
        return bytes(out)
    
    def encrypt(self, data):
        blocks = [data[i:i+BLOCK_SIZE] for i in range(0, len(data), BLOCK_SIZE)]
        out = b''
        for block in blocks:
            for _ in range(100):
                block = self.substitute(block)
                block = self.permute(block)
                block = xor(block, self.key)
            out += block
        return out

class SecureHash:
    def __init__(self, data=None):
        self.state = b"\x00"*32
        if data:
            self.update(data)
    
    def update(self, data):
        blocks = [data[i:i+BLOCK_SIZE] for i in range(0, len(data), BLOCK_SIZE)]
        for block in blocks:
            c = SecureCipher(block)
            self.state = xor(self.state, c.encrypt(block))
    
    def digest(self):
        return self.state

print("🎲 COLLISION FINDER")
print("="*50)
print("Theory: Maybe the challenge accepts ANY valid collision")
print(f"Target: {target.hex()}\n")

# Strategy 1: Random search with ASCII bias
print("[*] Strategy 1: Random ASCII-biased search...")
start_time = time.time()
attempts = 0

for i in range(10000):
    # Generate random 32-byte string with ASCII bias
    if i % 2 == 0:
        # Pure ASCII attempt
        chars = []
        for _ in range(32):
            if random.random() < 0.7:
                # Printable ASCII
                chars.append(random.choice(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_!@#$%^&*()-=+[]{}|;:,.<>?/"))
            else:
                # Any byte
                chars.append(random.randint(0, 255))
        candidate = bytes(chars)
    else:
        # Pure random
        candidate = bytes([random.randint(0, 255) for _ in range(32)])
    
    h = SecureHash(candidate).digest()
    attempts += 1
    
    if h == target:
        print(f"\n✅ COLLISION FOUND after {attempts} attempts!")
        print(f"Input: {candidate}")
        print(f"Hex: {candidate.hex()}")
        try:
            print(f"ASCII: {candidate.decode('ascii', errors='replace')}")
        except:
            pass
        exit(0)
    
    if attempts % 1000 == 0:
        elapsed = time.time() - start_time
        rate = attempts / elapsed
        print(f"[*] Attempts: {attempts}, Rate: {rate:.0f}/s")

# Strategy 2: Check if there's a pattern in "easy" inputs
print("\n[*] Strategy 2: Testing structured patterns...")

# Test repeated patterns
for byte_val in range(256):
    # All same byte
    candidate = bytes([byte_val]) * 32
    h = SecureHash(candidate).digest()
    if h == target:
        print(f"\n✅ FOUND! All bytes = {byte_val:02x}")
        exit(0)

# Test counting patterns
for start in range(256):
    candidate = bytes([(start + i) % 256 for i in range(32)])
    h = SecureHash(candidate).digest()
    if h == target:
        print(f"\n✅ FOUND! Counting from {start}")
        exit(0)

# Final thought: What if the flag is literally in the challenge description?
print("\n[*] Strategy 3: Testing literal interpretations...")

# "rolling your own crypto has always been pretty easy"
literal_tests = [
    b"rolling your own crypto has alwa",  # 32 chars
    b"HTB{pr3tty_34sy_****************}",  # "pretty easy" hint
    b"HTB{2_34sy_2_cr4ck_************}",   # "too easy to crack"
    b"HTB{34sy_p34sy_l3m0n_5qu33zy***}",   # "easy peasy lemon squeezy"
]

for test in literal_tests:
    if len(test) == 32:
        h = SecureHash(test).digest()
        if h == target:
            print(f"\n✅ FOUND: {test}")
            exit(0)

print(f"\n❌ No collision found after {attempts} random attempts")
print("The flag must be something very specific...")