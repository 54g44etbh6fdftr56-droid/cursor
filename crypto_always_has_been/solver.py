#!/usr/bin/python3

import itertools
import string

KEY_SBOX = [170, 89, 81, 162, 65, 178, 186, 73, 97, 146, 154, 105, 138, 121, 113, 130, 33, 210, 218, 41, 202, 57, 49, 194, 234, 25, 17, 226, 1, 242, 250, 9, 161, 82, 90, 169, 74, 185, 177, 66, 106, 153, 145, 98, 129, 114, 122, 137, 42, 217, 209, 34, 193, 50, 58, 201, 225, 18, 26, 233, 10, 249, 241, 2, 188, 79, 71, 180, 87, 164, 172, 95, 119, 132, 140, 127, 156, 111, 103, 148, 55, 196, 204, 63, 220, 47, 39, 212, 252, 15, 7, 244, 23, 228, 236, 31, 183, 68, 76, 191, 92, 175, 167, 84, 124, 143, 135, 116, 151, 100, 108, 159, 60, 207, 199, 52, 215, 36, 44, 223, 247, 4, 12, 255, 28, 239, 231, 20, 134, 117, 125, 142, 109, 158, 150, 101, 77, 190, 182, 69, 166, 85, 93, 174, 13, 254, 246, 5, 230, 21, 29, 238, 198, 53, 61, 206, 45, 222, 214, 37, 141, 126, 118, 133, 102, 149, 157, 110, 70, 181, 189, 78, 173, 94, 86, 165, 6, 245, 253, 14, 237, 30, 22, 229, 205, 62, 54, 197, 38, 213, 221, 46, 144, 99, 107, 152, 123, 136, 128, 115, 91, 168, 160, 83, 176, 67, 75, 184, 27, 232, 224, 19, 240, 3, 11, 248, 208, 35, 43, 216, 59, 200, 192, 51, 155, 104, 96, 147, 112, 131, 139, 120, 80, 163, 171, 88, 187, 72, 64, 179, 16, 227, 235, 24, 251, 8, 0, 243, 219, 40, 32, 211, 48, 195, 203, 56]
PBOX = [59, 82, 101, 135, 189, 153, 105, 14, 179, 71, 167, 33, 160, 198, 218, 104, 66, 37, 216, 199, 132, 214, 217, 42, 231, 221, 236, 233, 203, 24, 220, 120, 158, 240, 84, 81, 152, 201, 57, 253, 249, 169, 79, 234, 136, 12, 40, 209, 29, 224, 17, 77, 60, 102, 195, 8, 212, 95, 147, 190, 138, 213, 98, 10, 4, 243, 1, 128, 145, 58, 241, 119, 88, 211, 110, 157, 3, 188, 19, 208, 44, 244, 122, 92, 109, 69, 134, 22, 90, 61, 202, 193, 141, 183, 133, 75, 144, 116, 191, 39, 207, 140, 192, 247, 83, 43, 121, 99, 254, 226, 177, 26, 9, 173, 78, 176, 223, 210, 156, 16, 227, 125, 93, 54, 76, 150, 5, 36, 185, 65, 72, 246, 131, 41, 106, 248, 151, 182, 204, 225, 229, 70, 7, 250, 115, 85, 163, 124, 184, 130, 239, 196, 15, 100, 252, 25, 171, 143, 0, 67, 222, 96, 165, 180, 46, 232, 117, 48, 38, 161, 50, 35, 73, 18, 154, 114, 175, 146, 148, 89, 80, 112, 228, 49, 172, 63, 123, 86, 149, 103, 230, 64, 28, 27, 166, 111, 170, 55, 47, 20, 51, 215, 32, 13, 118, 11, 53, 205, 238, 91, 6, 94, 200, 181, 162, 178, 194, 126, 164, 2, 255, 137, 242, 23, 74, 197, 142, 108, 52, 187, 129, 186, 155, 97, 107, 34, 245, 68, 56, 127, 21, 219, 159, 62, 113, 237, 206, 45, 251, 168, 87, 31, 30, 235, 174, 139]
BLOCK_SIZE = 32
xor = lambda a,b: bytes([b1 ^ b2 for b1, b2 in zip(a,b)])

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

# Target hash
target = bytes.fromhex("61b5649e894a15a053276c0dc828ee64ec2336f809e2dd7d2912c61c8ef02c26")

print("[*] Target hash:", target.hex())
print("[*] Searching for flag...")

# Método 1: Fuerza bruta con prefijo conocido
def brute_force_with_prefix():
    prefix = b"HTB{"
    charset = string.ascii_letters + string.digits + "_!@#$%^&*()-=+[]{}|;:,.<>?/"
    
    print("\n[*] Method 1: Brute force with known prefix 'HTB{'")
    
    # Generamos posibles flags
    for suffix_length in range(27, 28):  # 32 - 5 (HTB{ + }) = 27
        print(f"[*] Trying suffix length: {suffix_length}")
        
        # Para optimizar, primero probamos caracteres ASCII imprimibles comunes
        for chars in itertools.product(charset, repeat=min(suffix_length, 5)):
            # Construimos una flag candidata
            suffix = ''.join(chars).encode()
            if len(suffix) + 5 > 32:
                continue
                
            # Rellenamos con caracteres comunes
            padding_needed = 27 - len(suffix)
            if padding_needed > 0:
                suffix += b'_' * padding_needed
                
            candidate = prefix + suffix + b"}"
            
            if len(candidate) != 32:
                continue
                
            # Calculamos el hash
            h = SecureHash(candidate).digest()
            
            if h == target:
                print(f"\n[+] FLAG FOUND: {candidate.decode()}")
                return candidate
                
    return None

# Método 2: Análisis de propiedades algebraicas
def analyze_cipher_properties():
    print("\n[*] Method 2: Analyzing cipher properties...")
    
    # Analizamos si hay puntos fijos o patrones
    for test_byte in range(256):
        test_input = bytes([test_byte]) * 32
        cipher = SecureCipher(test_input)
        output = cipher.encrypt(test_input)
        
        if output == target:
            print(f"[+] Found match with repeated byte: {test_byte:02x}")
            return test_input
            
    # Probamos con patrones específicos
    patterns = [
        b"HTB{" + b"\x00" * 27 + b"}",
        b"HTB{" + b"a" * 27 + b"}",
        b"HTB{" + b"_" * 27 + b"}",
    ]
    
    for pattern in patterns:
        h = SecureHash(pattern).digest()
        if h == target:
            print(f"[+] FLAG FOUND: {pattern}")
            return pattern
            
    return None

# Método 3: Meet-in-the-middle attack (simplificado)
def mitm_attack():
    print("\n[*] Method 3: Meet-in-the-middle attack...")
    
    # Creamos una tabla de hashes parciales
    partial_hashes = {}
    
    # Primera mitad: probamos diferentes prefijos
    for i in range(256):
        for j in range(256):
            prefix = bytes([i, j])
            test_input = prefix + b"\x00" * 30
            h = SecureHash(test_input).digest()
            partial_hashes[h[:8]] = test_input
            
    print(f"[*] Generated {len(partial_hashes)} partial hashes")
    
    # Buscamos coincidencias con el target
    target_prefix = target[:8]
    if target_prefix in partial_hashes:
        print(f"[+] Found partial match!")
        candidate = partial_hashes[target_prefix]
        # Refinamos la búsqueda
        for suffix in itertools.product(range(256), repeat=4):
            test = candidate[:2] + bytes(suffix) + candidate[6:]
            h = SecureHash(test).digest()
            if h == target:
                print(f"[+] FLAG FOUND: {test}")
                return test
                
    return None

# Método 4: Búsqueda exhaustiva optimizada con caracteres ASCII
def optimized_search():
    print("\n[*] Method 4: Optimized ASCII search...")
    
    # Sabemos que la flag tiene formato HTB{...}
    # Intentamos diferentes combinaciones de caracteres ASCII imprimibles
    
    # Generamos todas las posibles flags de 32 bytes con formato HTB{...}
    prefix = b"HTB{"
    suffix = b"}"
    
    # Caracteres más probables en flags de CTF
    likely_chars = "0123456789abcdefghijklmnopqrstuvwxyz_"
    
    print("[*] Trying common CTF flag patterns...")
    
    # Patrones comunes en CTFs
    patterns = [
        "4lw4y5_h45_b33n",
        "always_has_been", 
        "alw4ys_h4s_b33n",
        "4lways_has_been",
        "always_h4s_been",
        "alw4y5_has_been",
        "4lw4ys_h4s_been",
        "always_has_b33n",
        "4lw4y5_h45_been",
        "alw4ys_has_b33n",
    ]
    
    for pattern in patterns:
        # Probamos diferentes variaciones
        for variant in [pattern, pattern.upper(), pattern.replace('_', '-')]:
            if len(variant) <= 27:
                padding_needed = 27 - len(variant)
                for pad_char in ['_', '!', '0']:
                    padded = variant + pad_char * padding_needed
                    candidate = prefix + padded.encode() + suffix
                    
                    if len(candidate) == 32:
                        h = SecureHash(candidate).digest()
                        if h == target:
                            print(f"\n[+] FLAG FOUND: {candidate.decode()}")
                            return candidate
                            
    # Si no encontramos con patrones conocidos, probamos combinaciones
    print("[*] Trying character combinations...")
    
    for length in range(20, 28):
        print(f"[*] Testing length {length}...")
        
        # Para longitudes cortas, probamos todas las combinaciones
        if length <= 15:
            for combo in itertools.product(likely_chars, repeat=length):
                content = ''.join(combo)
                padding_needed = 27 - length
                
                for pad in ['_', '!', '0', '']:
                    if padding_needed > 0:
                        full_content = content + pad * padding_needed
                    else:
                        full_content = content[:27]
                        
                    candidate = prefix + full_content.encode() + suffix
                    
                    if len(candidate) == 32:
                        h = SecureHash(candidate).digest()
                        if h == target:
                            print(f"\n[+] FLAG FOUND: {candidate.decode()}")
                            return candidate
                            
    return None

# Método 5: Análisis diferencial
def differential_analysis():
    print("\n[*] Method 5: Differential cryptanalysis...")
    
    # Analizamos cómo pequeños cambios en la entrada afectan la salida
    base = b"HTB{" + b"a" * 27 + b"}"
    base_hash = SecureHash(base).digest()
    
    print(f"[*] Base hash: {base_hash.hex()}")
    print(f"[*] Target:    {target.hex()}")
    
    # Calculamos la diferencia
    diff = bytes([b1 ^ b2 for b1, b2 in zip(base_hash, target)])
    print(f"[*] Difference: {diff.hex()}")
    
    # Intentamos encontrar una entrada que produzca esta diferencia
    for i in range(32):
        for byte_val in range(256):
            test = bytearray(base)
            test[i] = byte_val
            h = SecureHash(bytes(test)).digest()
            
            if h == target:
                print(f"\n[+] FLAG FOUND: {bytes(test).decode()}")
                return bytes(test)
                
    return None

# Ejecutamos todos los métodos
print("="*60)
print("CRYPTOGRAPHIC ATTACK IN PROGRESS")
print("="*60)

# Primero intentamos los métodos más rápidos
result = analyze_cipher_properties()
if not result:
    result = optimized_search()
if not result:
    result = differential_analysis()
if not result:
    result = mitm_attack()
if not result:
    result = brute_force_with_prefix()

if result:
    print("\n" + "="*60)
    print("SUCCESS!")
    print(f"Flag: {result.decode() if isinstance(result, bytes) else result}")
    print("="*60)
else:
    print("\n[-] Flag not found with current methods. Implementing advanced attack...")