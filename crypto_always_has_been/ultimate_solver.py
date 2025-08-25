#!/usr/bin/python3
"""
Ultimate solver - combining all approaches with deep mathematical insight
"""

import struct
import itertools

# Constants
KEY_SBOX = [170, 89, 81, 162, 65, 178, 186, 73, 97, 146, 154, 105, 138, 121, 113, 130, 33, 210, 218, 41, 202, 57, 49, 194, 234, 25, 17, 226, 1, 242, 250, 9, 161, 82, 90, 169, 74, 185, 177, 66, 106, 153, 145, 98, 129, 114, 122, 137, 42, 217, 209, 34, 193, 50, 58, 201, 225, 18, 26, 233, 10, 249, 241, 2, 188, 79, 71, 180, 87, 164, 172, 95, 119, 132, 140, 127, 156, 111, 103, 148, 55, 196, 204, 63, 220, 47, 39, 212, 252, 15, 7, 244, 23, 228, 236, 31, 183, 68, 76, 191, 92, 175, 167, 84, 124, 143, 135, 116, 151, 100, 108, 159, 60, 207, 199, 52, 215, 36, 44, 223, 247, 4, 12, 255, 28, 239, 231, 20, 134, 117, 125, 142, 109, 158, 150, 101, 77, 190, 182, 69, 166, 85, 93, 174, 13, 254, 246, 5, 230, 21, 29, 238, 198, 53, 61, 206, 45, 222, 214, 37, 141, 126, 118, 133, 102, 149, 157, 110, 70, 181, 189, 78, 173, 94, 86, 165, 6, 245, 253, 14, 237, 30, 22, 229, 205, 62, 54, 197, 38, 213, 221, 46, 144, 99, 107, 152, 123, 136, 128, 115, 91, 168, 160, 83, 176, 67, 75, 184, 27, 232, 224, 19, 240, 3, 11, 248, 208, 35, 43, 216, 59, 200, 192, 51, 155, 104, 96, 147, 112, 131, 139, 120, 80, 163, 171, 88, 187, 72, 64, 179, 16, 227, 235, 24, 251, 8, 0, 243, 219, 40, 32, 211, 48, 195, 203, 56]
PBOX = [59, 82, 101, 135, 189, 153, 105, 14, 179, 71, 167, 33, 160, 198, 218, 104, 66, 37, 216, 199, 132, 214, 217, 42, 231, 221, 236, 233, 203, 24, 220, 120, 158, 240, 84, 81, 152, 201, 57, 253, 249, 169, 79, 234, 136, 12, 40, 209, 29, 224, 17, 77, 60, 102, 195, 8, 212, 95, 147, 190, 138, 213, 98, 10, 4, 243, 1, 128, 145, 58, 241, 119, 88, 211, 110, 157, 3, 188, 19, 208, 44, 244, 122, 92, 109, 69, 134, 22, 90, 61, 202, 193, 141, 183, 133, 75, 144, 116, 191, 39, 207, 140, 192, 247, 83, 43, 121, 99, 254, 226, 177, 26, 9, 173, 78, 176, 223, 210, 156, 16, 227, 125, 93, 54, 76, 150, 5, 36, 185, 65, 72, 246, 131, 41, 106, 248, 151, 182, 204, 225, 229, 70, 7, 250, 115, 85, 163, 124, 184, 130, 239, 196, 15, 100, 252, 25, 171, 143, 0, 67, 222, 96, 165, 180, 46, 232, 117, 48, 38, 161, 50, 35, 73, 18, 154, 114, 175, 146, 148, 89, 80, 112, 228, 49, 172, 63, 123, 86, 149, 103, 230, 64, 28, 27, 166, 111, 170, 55, 47, 20, 51, 215, 32, 13, 118, 11, 53, 205, 238, 91, 6, 94, 200, 181, 162, 178, 194, 126, 164, 2, 255, 137, 242, 23, 74, 197, 142, 108, 52, 187, 129, 186, 155, 97, 107, 34, 245, 68, 56, 127, 21, 219, 159, 62, 113, 237, 206, 45, 251, 168, 87, 31, 30, 235, 174, 139]
BLOCK_SIZE = 32

# Target
target_hex = "61b5649e894a15a053276c0dc828ee64ec2336f809e2dd7d2912c61c8ef02c26"
target = bytes.fromhex(target_hex)

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
    
    def pad(self, data):
        if len(data) % BLOCK_SIZE == 0:
            return data
        else:
            bound = (len(data) // BLOCK_SIZE + 1) * BLOCK_SIZE
            diff = bound - len(data)
            return data + bytes([diff])*diff
    
    def update(self, data):
        data = self.pad(data)
        blocks = [data[i:i+BLOCK_SIZE] for i in range(0, len(data), BLOCK_SIZE)]
        for block in blocks:
            c = SecureCipher(block)
            self.state = xor(self.state, c.encrypt(block))
    
    def digest(self):
        return self.state

print("="*60)
print("ULTIMATE CRYPTOGRAPHIC SOLVER")
print("="*60)
print(f"[*] Target: {target_hex}")

# INSIGHT PROFUNDO: El nombre "Always Has Been" sugiere que la respuesta es obvia
# Probemos las variaciones más comunes del meme

test_cases = [
    # Variaciones directas del meme
    b"HTB{4lw4y5_h45_b33n_________}",
    b"HTB{always_has_been__________}",
    b"HTB{Always_Has_Been__________}",
    b"HTB{ALWAYS_HAS_BEEN__________}",
    b"HTB{AlwaysHasBeen____________}",
    b"HTB{alwayshasbeen____________}",
    b"HTB{4lways_h4s_b33n__________}",
    b"HTB{alw4ys_h4s_b33n__________}",
    b"HTB{4lw4y5_h4s_b33n__________}",
    b"HTB{always_h4s_b33n__________}",
    b"HTB{4lw4ys_has_been__________}",
    b"HTB{alw4y5_h45_b33n__________}",
    b"HTB{41w4y5_h45_b33n__________}",
    b"HTB{a1way5_ha5_b33n__________}",
    b"HTB{alw@ys_h@s_b33n__________}",
    b"HTB{@lw@y5_h@5_b33n__________}",
    
    # Padding variations
    b"HTB{always_has_been!!!!!!!!!!}",
    b"HTB{always_has_been0000000000}",
    b"HTB{always_has_been..........}",
    b"HTB{always_has_been----------}",
    b"HTB{always_has_been__________}",
    
    # Sin padding
    b"HTB{always_has_been}" + b"\x00" * 12,
    b"HTB{4lw4y5_h45_b33n}" + b"\x00" * 12,
    
    # Variaciones temáticas
    b"HTB{n3v3r_r0ll_y0ur_0wn_crypt}",
    b"HTB{roll_your_own_crypto_bad_}",
    b"HTB{bad_crypto_implementation}",
    b"HTB{weak_crypto_always_broken}",
]

print(f"\n[*] Testing {len(test_cases)} prepared cases...")

for i, flag in enumerate(test_cases):
    if len(flag) != 32:
        print(f"[-] Skipping invalid length: {len(flag)}")
        continue
        
    h = SecureHash(flag).digest()
    if h == target:
        print(f"\n[+] FLAG FOUND!")
        print(f"[+] Flag: {flag}")
        print(f"[+] Decoded: {flag.decode().rstrip('\\x00')}")
        exit(0)

# Método sistemático: generar todas las variaciones posibles con padding
print("\n[*] Systematic generation of 'always has been' variations...")

base_patterns = [
    "always_has_been",
    "4lw4y5_h45_b33n",
    "alw4ys_h4s_b33n", 
    "4lways_h4s_been",
    "always_h4s_b33n",
    "4lw4ys_has_been",
    "alw4y5_h45_b33n",
]

# Caracteres de padding comunes
pad_chars = ['_', '!', '0', '.', '-', ' ', 'x', '#', '@', '$', '%', '^', '&', '*']

for pattern in base_patterns:
    for pad_char in pad_chars:
        content = pattern
        padding_needed = 27 - len(content)
        
        if padding_needed > 0:
            # Diferentes estrategias de padding
            padded_versions = [
                content + pad_char * padding_needed,  # al final
                pad_char * padding_needed + content,  # al inicio
                content[:len(content)//2] + pad_char * padding_needed + content[len(content)//2:],  # en medio
            ]
            
            for padded in padded_versions:
                if len(padded) == 27:
                    flag = b"HTB{" + padded.encode() + b"}"
                    if len(flag) == 32:
                        h = SecureHash(flag).digest()
                        if h == target:
                            print(f"\n[+] FLAG FOUND!")
                            print(f"[+] Flag: {flag}")
                            print(f"[+] Decoded: {flag.decode()}")
                            exit(0)

# Probar sin HTB{} wrapper
print("\n[*] Testing without HTB{} wrapper...")
for pattern in ["always_has_been", "4lw4y5_h45_b33n"]:
    for pad_char in ['', '\x00', '_', '!']:
        test = pattern.encode()
        if pad_char:
            test = test + pad_char.encode() * (32 - len(test))
        
        if len(test) == 32:
            h = SecureHash(test).digest()
            if h == target:
                print(f"\n[+] FLAG FOUND (no wrapper)!")
                print(f"[+] Flag: {test}")
                exit(0)

# Último intento: fuerza bruta inteligente
print("\n[*] Smart brute force on character substitutions...")

base = "always_has_been"
substitutions = {
    'a': ['a', '4', '@'],
    'l': ['l', '1', '!'],
    'w': ['w', 'vv'],
    'y': ['y', 'j'],
    's': ['s', '5', '$', 'z'],
    'h': ['h', '#'],
    'e': ['e', '3'],
    'n': ['n', 'N'],
    '_': ['_', '-', '.', ' '],
}

def generate_variants(word):
    if not word:
        yield ""
        return
    
    first_char = word[0]
    rest = word[1:]
    
    for variant in generate_variants(rest):
        if first_char in substitutions:
            for sub in substitutions[first_char]:
                yield sub + variant
        else:
            yield first_char + variant

count = 0
for variant in generate_variants(base):
    count += 1
    if count % 1000 == 0:
        print(f"[*] Tested {count} variants...")
    
    if len(variant) <= 27:
        for pad_len in range(0, 28 - len(variant)):
            for pad_char in ['_', '!', '0', '']:
                if pad_char:
                    test_content = variant + pad_char * pad_len
                else:
                    test_content = variant
                
                if len(test_content) == 27:
                    flag = b"HTB{" + test_content.encode() + b"}"
                    h = SecureHash(flag).digest()
                    if h == target:
                        print(f"\n[+] FLAG FOUND!")
                        print(f"[+] Flag: {flag}")
                        print(f"[+] Decoded: {flag.decode()}")
                        exit(0)

print(f"\n[*] Tested {count} total variants")
print("[-] Flag not found. Need different approach...")