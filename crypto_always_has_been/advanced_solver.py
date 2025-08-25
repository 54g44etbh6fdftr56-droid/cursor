#!/usr/bin/python3
"""
Advanced cryptanalysis solver using fixed-point iteration and algebraic analysis
Based on the observation that the S-Box only depends on key[0]
"""

import struct
import sys

# Constants from securehash.py
KEY_SBOX = [170, 89, 81, 162, 65, 178, 186, 73, 97, 146, 154, 105, 138, 121, 113, 130, 33, 210, 218, 41, 202, 57, 49, 194, 234, 25, 17, 226, 1, 242, 250, 9, 161, 82, 90, 169, 74, 185, 177, 66, 106, 153, 145, 98, 129, 114, 122, 137, 42, 217, 209, 34, 193, 50, 58, 201, 225, 18, 26, 233, 10, 249, 241, 2, 188, 79, 71, 180, 87, 164, 172, 95, 119, 132, 140, 127, 156, 111, 103, 148, 55, 196, 204, 63, 220, 47, 39, 212, 252, 15, 7, 244, 23, 228, 236, 31, 183, 68, 76, 191, 92, 175, 167, 84, 124, 143, 135, 116, 151, 100, 108, 159, 60, 207, 199, 52, 215, 36, 44, 223, 247, 4, 12, 255, 28, 239, 231, 20, 134, 117, 125, 142, 109, 158, 150, 101, 77, 190, 182, 69, 166, 85, 93, 174, 13, 254, 246, 5, 230, 21, 29, 238, 198, 53, 61, 206, 45, 222, 214, 37, 141, 126, 118, 133, 102, 149, 157, 110, 70, 181, 189, 78, 173, 94, 86, 165, 6, 245, 253, 14, 237, 30, 22, 229, 205, 62, 54, 197, 38, 213, 221, 46, 144, 99, 107, 152, 123, 136, 128, 115, 91, 168, 160, 83, 176, 67, 75, 184, 27, 232, 224, 19, 240, 3, 11, 248, 208, 35, 43, 216, 59, 200, 192, 51, 155, 104, 96, 147, 112, 131, 139, 120, 80, 163, 171, 88, 187, 72, 64, 179, 16, 227, 235, 24, 251, 8, 0, 243, 219, 40, 32, 211, 48, 195, 203, 56]
PBOX = [59, 82, 101, 135, 189, 153, 105, 14, 179, 71, 167, 33, 160, 198, 218, 104, 66, 37, 216, 199, 132, 214, 217, 42, 231, 221, 236, 233, 203, 24, 220, 120, 158, 240, 84, 81, 152, 201, 57, 253, 249, 169, 79, 234, 136, 12, 40, 209, 29, 224, 17, 77, 60, 102, 195, 8, 212, 95, 147, 190, 138, 213, 98, 10, 4, 243, 1, 128, 145, 58, 241, 119, 88, 211, 110, 157, 3, 188, 19, 208, 44, 244, 122, 92, 109, 69, 134, 22, 90, 61, 202, 193, 141, 183, 133, 75, 144, 116, 191, 39, 207, 140, 192, 247, 83, 43, 121, 99, 254, 226, 177, 26, 9, 173, 78, 176, 223, 210, 156, 16, 227, 125, 93, 54, 76, 150, 5, 36, 185, 65, 72, 246, 131, 41, 106, 248, 151, 182, 204, 225, 229, 70, 7, 250, 115, 85, 163, 124, 184, 130, 239, 196, 15, 100, 252, 25, 171, 143, 0, 67, 222, 96, 165, 180, 46, 232, 117, 48, 38, 161, 50, 35, 73, 18, 154, 114, 175, 146, 148, 89, 80, 112, 228, 49, 172, 63, 123, 86, 149, 103, 230, 64, 28, 27, 166, 111, 170, 55, 47, 20, 51, 215, 32, 13, 118, 11, 53, 205, 238, 91, 6, 94, 200, 181, 162, 178, 194, 126, 164, 2, 255, 137, 242, 23, 74, 197, 142, 108, 52, 187, 129, 186, 155, 97, 107, 34, 245, 68, 56, 127, 21, 219, 159, 62, 113, 237, 206, 45, 251, 168, 87, 31, 30, 235, 174, 139]

# Target hash
TARGET = bytes.fromhex("61b5649e894a15a053276c0dc828ee64ec2336f809e2dd7d2912c61c8ef02c26")

def xor(a, b):
    """XOR two byte arrays"""
    return bytes([x ^ y for x, y in zip(a, b)])

def verify_sbox_bijection():
    """Verify that KEY_SBOX is a permutation (bijection)"""
    return len(set(KEY_SBOX)) == 256

def create_inverse_sbox(k0):
    """Create inverse S-Box for a given key[0]"""
    sbox = [(KEY_SBOX[i] ^ k0) & 0xFF for i in range(256)]
    inv_sbox = [0] * 256
    for i in range(256):
        inv_sbox[sbox[i]] = i
    return inv_sbox

def permute(data):
    """Apply bit permutation using PBOX"""
    out = [0] * 32
    for num in range(256):
        outnum = PBOX[num]
        inbyte = num // 8
        inbit = 7 - (num % 8)
        outbyte = outnum // 8
        outbit = 7 - (outnum % 8)
        
        if data[inbyte] & (1 << inbit):
            out[outbyte] |= (1 << outbit)
    return bytes(out)

def inverse_permute(data):
    """Apply inverse bit permutation"""
    # Create inverse PBOX
    inv_pbox = [0] * 256
    for i in range(256):
        inv_pbox[PBOX[i]] = i
    
    out = [0] * 32
    for num in range(256):
        outnum = inv_pbox[num]
        inbyte = num // 8
        inbit = 7 - (num % 8)
        outbyte = outnum // 8
        outbit = 7 - (outnum % 8)
        
        if data[inbyte] & (1 << inbit):
            out[outbyte] |= (1 << outbit)
    return bytes(out)

def substitute(data, sbox):
    """Apply S-Box substitution"""
    return bytes([sbox[b] for b in data])

def decrypt_round(block, key, inv_sbox):
    """Decrypt one round"""
    # Reverse: block = xor(block, key)
    block = xor(block, key)
    # Reverse: block = permute(block)
    block = inverse_permute(block)
    # Reverse: block = substitute(block)
    block = substitute(block, inv_sbox)
    return block

def decrypt_full(ciphertext, key, k0):
    """Decrypt 100 rounds"""
    inv_sbox = create_inverse_sbox(k0)
    block = ciphertext
    for _ in range(100):
        block = decrypt_round(block, key, inv_sbox)
    return block

def compute_P_U(k0):
    """Compute P(U) where U is 32 bytes of k0"""
    U = bytes([k0] * 32)
    return permute(U)

def fixed_point_iteration(y, k0, max_iterations=100):
    """
    Fixed point iteration to find K such that:
    K = y ⊕ F_{k0}(K)
    
    We iterate: K_{n+1} = y ⊕ F_{k0}(K_n)
    """
    K = bytes(32)  # Start with zero
    
    for iteration in range(max_iterations):
        # Decrypt y with current K to get potential plaintext
        plaintext = decrypt_full(y, K, k0)
        
        # New K is the plaintext (since plaintext = key in this challenge)
        K_new = plaintext
        
        # Check convergence
        if K_new == K:
            return K_new
            
        K = K_new
        
        # Early termination if we find HTB{
        if K.startswith(b'HTB{'):
            return K
    
    return K

def solve():
    """Main solving function"""
    print("[*] Advanced Cryptanalysis Solver")
    print("[*] Target hash:", TARGET.hex())
    
    # Verify S-Box is bijection
    if not verify_sbox_bijection():
        print("[-] ERROR: KEY_SBOX is not a bijection!")
        return None
    
    print("[+] S-Box verified as bijection")
    
    # Try all possible k0 values
    print("[*] Searching through k0 space (256 values)...")
    
    for k0 in range(256):
        if k0 % 32 == 0:
            print(f"[*] Progress: {k0}/256")
        
        # Method 1: Fixed point iteration
        K = fixed_point_iteration(TARGET, k0, max_iterations=50)
        
        # Check if valid flag format
        if K.startswith(b'HTB{') and K.endswith(b'}'):
            print(f"\n[+] FOUND FLAG with k0={k0}!")
            print(f"[+] Flag: {K.decode()}")
            
            # Verify by re-encrypting
            from securehash import SecureHash
            h = SecureHash(K).digest()
            if h == TARGET:
                print("[+] Verification: PASSED!")
                return K
            else:
                print("[-] Verification failed, continuing search...")
        
        # Method 2: Direct algebraic solution
        # Since K = y ⊕ F_{k0}(K), and F_{k0} depends on the structure
        # We can try to solve this directly for specific patterns
        
        # Try assuming flag starts with HTB{
        test_prefix = b'HTB{'
        test_key = test_prefix + b'\x00' * 28
        
        # Check if this produces something close to target
        decrypted = decrypt_full(TARGET, test_key, k0)
        if decrypted.startswith(b'HTB{'):
            # Refine the key
            for i in range(10):  # Refinement iterations
                test_key = decrypted
                decrypted = decrypt_full(TARGET, test_key, k0)
                
                if test_key == decrypted:  # Fixed point found
                    if test_key.startswith(b'HTB{') and test_key.endswith(b'}'):
                        print(f"\n[+] FOUND FLAG via algebraic method with k0={k0}!")
                        print(f"[+] Flag: {test_key.decode()}")
                        return test_key
    
    print("\n[-] No valid flag found with current methods")
    return None

if __name__ == "__main__":
    print("="*60)
    print("ADVANCED CRYPTOGRAPHIC ATTACK")
    print("="*60)
    
    result = solve()
    
    if result:
        print("\n" + "="*60)
        print("SUCCESS! Flag captured!")
        print("="*60)
    else:
        print("\n[-] Attack failed. Implementing next level strategy...")