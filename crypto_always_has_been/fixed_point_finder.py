#!/usr/bin/python3
"""
Finding fixed points in the hash function
Theory: Maybe the target hash IS the flag itself (a fixed point)
"""

# Constants
KEY_SBOX = [170, 89, 81, 162, 65, 178, 186, 73, 97, 146, 154, 105, 138, 121, 113, 130, 33, 210, 218, 41, 202, 57, 49, 194, 234, 25, 17, 226, 1, 242, 250, 9, 161, 82, 90, 169, 74, 185, 177, 66, 106, 153, 145, 98, 129, 114, 122, 137, 42, 217, 209, 34, 193, 50, 58, 201, 225, 18, 26, 233, 10, 249, 241, 2, 188, 79, 71, 180, 87, 164, 172, 95, 119, 132, 140, 127, 156, 111, 103, 148, 55, 196, 204, 63, 220, 47, 39, 212, 252, 15, 7, 244, 23, 228, 236, 31, 183, 68, 76, 191, 92, 175, 167, 84, 124, 143, 135, 116, 151, 100, 108, 159, 60, 207, 199, 52, 215, 36, 44, 223, 247, 4, 12, 255, 28, 239, 231, 20, 134, 117, 125, 142, 109, 158, 150, 101, 77, 190, 182, 69, 166, 85, 93, 174, 13, 254, 246, 5, 230, 21, 29, 238, 198, 53, 61, 206, 45, 222, 214, 37, 141, 126, 118, 133, 102, 149, 157, 110, 70, 181, 189, 78, 173, 94, 86, 165, 6, 245, 253, 14, 237, 30, 22, 229, 205, 62, 54, 197, 38, 213, 221, 46, 144, 99, 107, 152, 123, 136, 128, 115, 91, 168, 160, 83, 176, 67, 75, 184, 27, 232, 224, 19, 240, 3, 11, 248, 208, 35, 43, 216, 59, 200, 192, 51, 155, 104, 96, 147, 112, 131, 139, 120, 80, 163, 171, 88, 187, 72, 64, 179, 16, 227, 235, 24, 251, 8, 0, 243, 219, 40, 32, 211, 48, 195, 203, 56]
PBOX = [59, 82, 101, 135, 189, 153, 105, 14, 179, 71, 167, 33, 160, 198, 218, 104, 66, 37, 216, 199, 132, 214, 217, 42, 231, 221, 236, 233, 203, 24, 220, 120, 158, 240, 84, 81, 152, 201, 57, 253, 249, 169, 79, 234, 136, 12, 40, 209, 29, 224, 17, 77, 60, 102, 195, 8, 212, 95, 147, 190, 138, 213, 98, 10, 4, 243, 1, 128, 145, 58, 241, 119, 88, 211, 110, 157, 3, 188, 19, 208, 44, 244, 122, 92, 109, 69, 134, 22, 90, 61, 202, 193, 141, 183, 133, 75, 144, 116, 191, 39, 207, 140, 192, 247, 83, 43, 121, 99, 254, 226, 177, 26, 9, 173, 78, 176, 223, 210, 156, 16, 227, 125, 93, 54, 76, 150, 5, 36, 185, 65, 72, 246, 131, 41, 106, 248, 151, 182, 204, 225, 229, 70, 7, 250, 115, 85, 163, 124, 184, 130, 239, 196, 15, 100, 252, 25, 171, 143, 0, 67, 222, 96, 165, 180, 46, 232, 117, 48, 38, 161, 50, 35, 73, 18, 154, 114, 175, 146, 148, 89, 80, 112, 228, 49, 172, 63, 123, 86, 149, 103, 230, 64, 28, 27, 166, 111, 170, 55, 47, 20, 51, 215, 32, 13, 118, 11, 53, 205, 238, 91, 6, 94, 200, 181, 162, 178, 194, 126, 164, 2, 255, 137, 242, 23, 74, 197, 142, 108, 52, 187, 129, 186, 155, 97, 107, 34, 245, 68, 56, 127, 21, 219, 159, 62, 113, 237, 206, 45, 251, 168, 87, 31, 30, 235, 174, 139]
BLOCK_SIZE = 32

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
    
    def update(self, data):
        blocks = [data[i:i+BLOCK_SIZE] for i in range(0, len(data), BLOCK_SIZE)]
        for block in blocks:
            c = SecureCipher(block)
            self.state = xor(self.state, c.encrypt(block))
    
    def digest(self):
        return self.state

print("[*] Testing if target is a fixed point...")

# Test 1: Is the target itself a fixed point?
h = SecureHash(target).digest()
if h == target:
    print("[+] TARGET IS A FIXED POINT!")
    print(f"[+] Flag might be: {target}")
    # Try to decode as ASCII
    try:
        decoded = target.decode('ascii')
        print(f"[+] ASCII: {decoded}")
    except:
        print("[*] Not ASCII decodable")
else:
    print("[-] Target is not a fixed point")
    print(f"    Hash of target: {h.hex()}")

# Test 2: Maybe the flag is hidden in the relationship
print("\n[*] Analyzing the relationship...")

# Important insight: The description says "rolling your own crypto"
# What if the flag is about rolling crypto? Like "roll" or "dice"?

roll_patterns = [
    b"HTB{r0ll_y0ur_0wn_crypt0_bad}",
    b"HTB{n3v3r_r0ll_y0ur_0wn_____}",
    b"HTB{d0nt_r0ll_y0ur_0wn______}",
    b"HTB{r0lling_y0ur_0wn_________}",
    b"HTB{rolled_your_own__________}",
    b"HTB{crypt0_r0ll3d____________}",
    b"HTB{bad_crypto_roll__________}",
    b"HTB{rolling_crypto_bad_______}",
    b"HTB{ez_crypto_break__________}",
    b"HTB{easy_crypto_pwn__________}",
    b"HTB{crypto_is_hard___________}",
    b"HTB{use_standard_crypto______}",
    b"HTB{aes_would_be_better______}",
    b"HTB{should_use_aes___________}",
    b"HTB{homemade_crypto_bad______}",
    b"HTB{diy_crypto_fail__________}",
]

print(f"\n[*] Testing {len(roll_patterns)} crypto-themed patterns...")

for flag in roll_patterns:
    if len(flag) != 32:
        continue
    h = SecureHash(flag).digest()
    if h == target:
        print(f"\n[+] FOUND FLAG: {flag.decode()}")
        exit(0)

# Test 3: What if we need to think differently about "always has been"?
# In the meme, the astronaut says "Wait, it's all Ohio?" "Always has been"
# What if it's about something that was always something else?

print("\n[*] Testing meme context patterns...")

meme_patterns = [
    b"HTB{its_all_ohio_____________}",
    b"HTB{wait_its_all_____________}",
    b"HTB{astronaut_meme___________}",
    b"HTB{gun_astronaut____________}",
    b"HTB{space_meme_______________}",
    b"HTB{ohio_meme________________}",
    b"HTB{butterfly_meme___________}",
    b"HTB{is_this_security_________}",
    b"HTB{corporate_wants__________}",
    b"HTB{same_picture_____________}",
]

for flag in meme_patterns:
    if len(flag) != 32:
        continue
    h = SecureHash(flag).digest()
    if h == target:
        print(f"\n[+] FOUND FLAG: {flag.decode()}")
        exit(0)

# Test 4: Pure "always has been" without modifications
print("\n[*] Testing pure forms...")

pure_tests = [
    b"always has been" + b"\x00" * 17,
    b"Always Has Been" + b"\x00" * 17,
    b"ALWAYS HAS BEEN" + b"\x00" * 17,
    b"always_has_been" + b"\x00" * 17,
    b"HTB{always has been}" + b"\x00" * 12,
    b"alwayshasbeen" + b"\x00" * 19,
    b"ALWAYSHASBEEN" + b"\x00" * 19,
]

for flag in pure_tests:
    if len(flag) == 32:
        h = SecureHash(flag).digest()
        if h == target:
            print(f"\n[+] FOUND FLAG!")
            print(f"[+] Raw: {flag}")
            try:
                print(f"[+] Decoded: {flag.decode()}")
            except:
                print(f"[+] Hex: {flag.hex()}")
            exit(0)

# Final attempt: What if the flag is the most obvious thing?
print("\n[*] Testing extremely obvious patterns...")

obvious = [
    b"HTB{4lw4y5_h45_b33n}" + b"\x00" * 12,
    b"HTB{flag}" + b"\x00" * 24,
    b"HTB{this_is_the_flag}" + b"\x00" * 11,
    b"HTB{" + target_hex[:27].encode() + b"}",
]

for flag in obvious:
    if len(flag) == 32:
        h = SecureHash(flag).digest()
        if h == target:
            print(f"\n[+] FOUND FLAG: {flag}")
            exit(0)

print("\n[-] Still no match. The solution requires deeper insight...")