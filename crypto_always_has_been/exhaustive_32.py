#!/usr/bin/python3
"""
Exhaustive search for exact 32-byte flags
"""

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

print("🎯 EXHAUSTIVE 32-BYTE FLAG SEARCH")
print("="*50)

# Generate all possible 32-byte flags with the meme theme
# Format: HTB{content_here_with_padding}

# Base patterns (without HTB{})
base_patterns = [
    "1t_4lw4y5_h45_b33n",      # 18 chars
    "it_always_has_been",      # 18 chars  
    "4lw4y5_h45_b33n",         # 15 chars
    "always_has_been",         # 15 chars
    "n3v3r_r0ll_y0ur_0wn",     # 20 chars
    "d0nt_r0ll_y0ur_0wn",      # 19 chars
    "r0ll_y0ur_0wn_crypt0",    # 21 chars
    "crypt0_4lw4y5_br0k3n",    # 21 chars
    "h0m3m4d3_crypt0_b4d",     # 20 chars
]

# Common endings/suffixes
endings = [
    "_br0k3n", "_w34k", "_b4d", "_34sy", "_1n53cur3", "_vuln3r4bl3",
    "_f41l", "_pwn3d", "_h4ck3d", "_cr4ck3d", "_d3f34t3d",
    "!", "!!", "!!!", "!!!!",
    "_lol", "_lmao", "_xD", "_:)", "_:P",
    "_ftw", "_rip", "_gg", "_ez", "_2ez",
]

# Padding characters
pad_chars = ['!', '_', '.', '-', '0', '1', 'x', 'X', '=', '#', '@', '$']

tested = 0

print("\n[*] Testing pattern + ending + padding combinations...")

for base in base_patterns:
    for ending in endings:
        content = base + ending
        
        # Check if it fits in HTB{}
        if len(content) <= 27:  # 32 - 5 (HTB{})
            # Try different padding strategies
            padding_needed = 27 - len(content)
            
            # Strategy 1: Single character repeated
            for pad_char in pad_chars:
                padded_content = content + pad_char * padding_needed
                flag = b"HTB{" + padded_content.encode() + b"}"
                
                if len(flag) == 32:
                    h = SecureHash(flag).digest()
                    tested += 1
                    
                    if h == target:
                        print(f"\n✅ FOUND THE FLAG!")
                        print(f"Flag: {flag.decode()}")
                        print(f"Content: {content}")
                        print(f"Padding: '{pad_char}' × {padding_needed}")
                        exit(0)
            
            # Strategy 2: Mixed padding patterns
            if padding_needed >= 2:
                # Try pattern like _!_!_!
                for p1 in ['_', '!', '.']:
                    for p2 in ['!', '_', '0']:
                        pattern = (p1 + p2) * (padding_needed // 2)
                        if padding_needed % 2:
                            pattern += p1
                        
                        padded_content = content + pattern
                        flag = b"HTB{" + padded_content.encode()[:27] + b"}"
                        
                        if len(flag) == 32:
                            h = SecureHash(flag).digest()
                            tested += 1
                            
                            if h == target:
                                print(f"\n✅ FOUND THE FLAG!")
                                print(f"Flag: {flag.decode()}")
                                exit(0)

    if tested % 100 == 0:
        print(f"[*] Tested {tested} combinations...")

# Try some specific 32-byte flags that might be the answer
print(f"\n[*] Testing specific candidates (tested {tested} so far)...")

specific_flags = [
    b"HTB{1t_4lw4y5_h45_b33n!_______}",
    b"HTB{1t_4lw4y5_h45_b33n________}",
    b"HTB{1t_4lw4y5_h45_b33n!!!!!!!!}",
    b"HTB{1t_4lw4y5_h45_b33n........}",
    b"HTB{1t_4lw4y5_h45_b33n_!_!_!_!}",
    b"HTB{4lw4y5_h45_b33n___________}",
    b"HTB{4lw4y5_h45_b33n!!!!!!!!!!!}",
    b"HTB{4lw4y5_h45_b33n...........}",
    b"HTB{n3v3r_r0ll_y0ur_0wn!_____}",
    b"HTB{d0nt_r0ll_y0ur_0wn!______}",
]

for flag in specific_flags:
    if len(flag) == 32:
        h = SecureHash(flag).digest()
        if h == target:
            print(f"\n✅ FOUND THE FLAG: {flag.decode()}")
            exit(0)

print(f"\n❌ Tested {tested + len(specific_flags)} flags. No match found.")