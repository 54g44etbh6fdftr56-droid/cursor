#!/usr/bin/python3
"""
Lateral thinking solver - exploring non-cryptographic solutions
"Always Has Been" - what if the answer was always there?
"""

import hashlib
from securehash import SecureHash

# Target hash
target_hex = "61b5649e894a15a053276c0dc828ee64ec2336f809e2dd7d2912c61c8ef02c26"
target = bytes.fromhex(target_hex)

print("[*] Lateral Thinking Analysis")
print("[*] Target:", target_hex)

# Test 1: Is the hash itself meaningful?
print("\n[1] Analyzing the hash itself...")
print(f"    As ASCII: {target}")
print(f"    Length: {len(target)} bytes")

# Test 2: Common CTF patterns
print("\n[2] Testing common patterns...")

test_flags = [
    b"HTB{" + target_hex.encode() + b"}",  # Hash as flag
    b"HTB{always_has_been}",
    b"HTB{Always_Has_Been}",
    b"HTB{always_h4s_b33n}",
    b"HTB{4lw4y5_h45_b33n}",
    b"HTB{alw4ys_has_be3n}",
    b"HTB{4lways_has_been}",
    b"HTB{Always_H4s_B33n}",
    b"HTB{a1way5_ha5_b33n}",
    b"HTB{rollyourowncrypto}",
    b"HTB{roll_your_own_crypto}",
    b"HTB{n3v3r_r0ll_y0ur_0wn}",
    b"HTB{broken_crypto_lol}",
    b"HTB{" + b"A" * 27 + b"}",
    b"HTB{" + b"\x00" * 27 + b"}",
    b"HTB{" + (b"Always_Has_Been" + b"_" * 12)[:27] + b"}",
]

# Pad to 32 bytes as needed
for i, flag in enumerate(test_flags):
    if len(flag) < 32:
        flag = flag + b'\x00' * (32 - len(flag))
    elif len(flag) > 32:
        flag = flag[:32]
    
    h = SecureHash(flag).digest()
    if h == target:
        print(f"\n[+] FOUND FLAG: {flag}")
        print(f"[+] Hash matches!")
        break
    else:
        # print(f"    Test {i}: {flag[:32]} -> {h.hex()[:16]}...")
        pass

# Test 3: Mathematical properties
print("\n[3] Checking mathematical properties...")

# Maybe it's a simple value?
simple_values = [
    b'\x00' * 32,
    b'\xff' * 32,
    b'\x01' + b'\x00' * 31,
    bytes(range(32)),
]

for val in simple_values:
    h = SecureHash(val).digest()
    if h == target:
        print(f"[+] Found with simple value: {val.hex()}")

# Test 4: The "Always Has Been" pattern
print("\n[4] Testing 'Always Has Been' variations...")

base = "always_has_been"
variations = []

# Generate variations with leetspeak and padding
for a in ['a', '4', '@']:
    for l in ['l', '1', '!']:
        for w in ['w', 'vv']:
            for y in ['y', 'j']:
                for s1 in ['s', '5', '$']:
                    for h in ['h', '#']:
                        for s2 in ['s', '5', '$']:
                            for e1 in ['e', '3']:
                                for e2 in ['e', '3']:
                                    for n in ['n', 'N']:
                                        variant = f"{a}{l}{w}{a}{y}{s1}_{h}{a}{s2}_b{e1}{e2}{n}"
                                        if len(variant) <= 27:
                                            variations.append(variant)

# Test common variations
common_variations = [
    "always_has_been",
    "Always_Has_Been", 
    "ALWAYS_HAS_BEEN",
    "4lw4y5_h45_b33n",
    "4lw4y5_h4s_b33n",
    "alw4y5_h45_b33n",
    "4lways_h4s_been",
    "always_h4s_b33n",
    "4lw4ys_has_been",
    "alw4ys_h4s_b33n",
    "AlwaysHasBeen",
    "alwayshasbeen",
    "ALWAYSHASBEEN",
    "a1way5_ha5_b33n",
    "41w4y5_h45_b33n",
    "always-has-been",
    "always.has.been",
    "always has been",
    "it_always_has_been",
    "its_always_has_been",
]

print(f"[*] Testing {len(common_variations)} variations...")

for variant in common_variations:
    # Try different paddings
    for pad_char in ['', '_', '!', '0', 'x', '.', '-']:
        for pad_pos in ['end', 'start', 'middle']:
            content = variant
            padding_needed = 27 - len(content)
            
            if padding_needed > 0 and pad_char:
                if pad_pos == 'end':
                    content = content + pad_char * padding_needed
                elif pad_pos == 'start':
                    content = pad_char * padding_needed + content
                elif pad_pos == 'middle' and '_' in content:
                    parts = content.split('_', 1)
                    content = parts[0] + '_' + pad_char * (padding_needed // 2) + '_' + parts[1]
            
            if len(content) <= 27:
                flag = b"HTB{" + content.encode() + b"}"
                
                # Pad to exactly 32 bytes
                if len(flag) < 32:
                    flag = flag[:-1] + b'\x00' * (32 - len(flag)) + b'}'
                elif len(flag) > 32:
                    continue
                    
                h = SecureHash(flag).digest()
                if h == target:
                    print(f"\n[+] FOUND FLAG: {flag}")
                    print(f"[+] Decoded: {flag.decode().rstrip('\\x00')}")
                    exit(0)

# Test 5: Check if it's about the meme
print("\n[5] Testing meme-related patterns...")

meme_patterns = [
    "wait_its_all_crypto",
    "wait_its_all_broken", 
    "astronaut_meme_lol",
    "two_astronauts_meme",
    "its_the_same_picture",
    "they_are_the_same",
    "corporate_needs_you",
]

for pattern in meme_patterns:
    if len(pattern) <= 27:
        flag = b"HTB{" + pattern.encode() + b"_" * (27 - len(pattern)) + b"}"
        h = SecureHash(flag).digest()
        if h == target:
            print(f"\n[+] FOUND: {flag}")

print("\n[6] Trying bruteforce on short meaningful phrases...")

# Common CTF flag components
words = ["always", "has", "been", "crypto", "broken", "roll", "your", "own", "bad", "idea"]
separators = ["_", "-", ".", ""]

import itertools

# Try combinations of 2-4 words
for num_words in range(2, 5):
    for word_combo in itertools.combinations(words, num_words):
        for sep in separators:
            content = sep.join(word_combo)
            if len(content) <= 27:
                for case in [str.lower, str.upper, str.title]:
                    test_content = case(content)
                    padding_needed = 27 - len(test_content)
                    
                    if padding_needed >= 0:
                        flag = b"HTB{" + test_content.encode() + b"_" * padding_needed + b"}"
                        h = SecureHash(flag).digest()
                        if h == target:
                            print(f"\n[+] FOUND FLAG: {flag}")
                            exit(0)

print("\n[-] No match found with lateral thinking approach")