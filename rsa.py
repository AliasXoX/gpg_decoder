import binascii
import hashlib
import random

def XOR_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

# Primitives

def I2OSP(x: int, x_len: int) -> bytes:
    if x < 0 or x >= 256 ** x_len:
        raise ValueError("Integer out of range")
    return x.to_bytes(x_len, byteorder='big')

def OS2IP(X: bytes) -> int:
    return int.from_bytes(X, byteorder='big')

def RSAEP(pub_key: tuple, m: int) -> int:
    e, n = pub_key
    if m < 0 or m >= n:
        raise ValueError("Message representative out of range")
    c_int = pow(m, e, n) 
    return c_int

def RSADP(priv_key: tuple, c: int) -> int:
    d, n = priv_key
    if c < 0 or c >= n:
        raise ValueError("Ciphertext representative out of range")
    m_int = pow(c, d, n) 
    return m_int

# Options
def hash(msg: bytes) -> bytes:
    return hashlib.sha1(msg).digest()

def MGF(seed: bytes, mask_len: int) -> bytes:
    h_len = len(hash(b''))
    if mask_len > 2**32 * h_len:
        raise ValueError("Mask length too long")
    
    T = b''
    for i in range(0, -(-mask_len // h_len)):  
        C = I2OSP(i, 4)
        T += hash(seed + C)
    
    return T[:mask_len]

# EME-OAEP Encoding and Decoding
def EME_OAEP_encode(M: bytes, em_len: int, label: bytes = b'') -> bytes:
    h_len = len(hash(b''))
    m_len = len(M)
    
    if m_len > em_len - 2 * h_len - 2:
        raise ValueError("Message too long")
    
    l_hash = hash(label)
    ps = b'\x00' * (em_len - m_len - 2 * h_len - 2)
    db = l_hash + ps + b'\x01' + M
    seed = random.randbytes(h_len)
    db_mask = MGF(seed, em_len - h_len - 1)
    masked_db = XOR_bytes(db, db_mask)
    seed_mask = MGF(masked_db, h_len)
    masked_seed = XOR_bytes(seed, seed_mask)
    
    EM = b'\x00' + masked_seed + masked_db
    return EM

def EME_OAEP_decode(EM: bytes, label: bytes = b'') -> bytes:
    h_len = len(hash(b''))
    em_len = len(EM)
    
    if em_len < 2 * h_len + 2:
        raise ValueError("Decryption error")
    
    Y = EM[0]
    if Y != 0:
        raise ValueError("Decryption error")
    masked_seed = EM[1:h_len + 1]
    masked_db = EM[h_len + 1:]
    
    seed_mask = MGF(masked_db, h_len)
    seed = XOR_bytes(masked_seed, seed_mask)
    db_mask = MGF(seed, em_len - h_len - 1)
    db = XOR_bytes(masked_db, db_mask)
    
    l_hash = hash(label)
    l_hash_prime = db[:h_len]
    if l_hash != l_hash_prime:
        raise ValueError("Decryption error")
    
    i = h_len
    while i < len(db):
        if db[i] == 0:
            i += 1
        elif db[i] == 1:
            i += 1
            break
        else:
            raise ValueError("Decryption error")
    
    M = db[i:]
    return M

# EME-PKCS1-v1_5 Encoding and Decoding
def EME_PKCS1_v1_5_encode(M: bytes, em_len: int) -> bytes:
    m_len = len(M)
    if m_len > em_len - 11:
        raise ValueError("Message too long")
    ps_len = em_len - m_len - 3
    ps = b''
    while len(ps) < ps_len:
        new_byte = random.randint(1, 255)
        ps += bytes([new_byte])
    EM = b'\x00\x02' + ps + b'\x00' + M
    return EM

def EME_PKCS1_v1_5_decode(EM: bytes) -> bytes:
    em_len = len(EM)
    if em_len < 11:
        raise ValueError("Decryption error1")
    if EM[0] != 0 or EM[1] != 2:
        raise ValueError("Decryption error2")
    i = 2
    while i < em_len:
        if EM[i] == 0:
            i += 1
            break
        i += 1
    if i >= em_len:
        raise ValueError("Decryption error3")
    M = EM[i:]
    return M

# Schemes
def RSAES_OAEP_encrypt(pub_key: tuple, M: bytes, label: bytes = b'') -> bytes:
    e, n = pub_key
    k = (n.bit_length() + 7) // 8  
    EM = EME_OAEP_encode(M, k, label)
    m_int = OS2IP(EM)
    c_int = RSAEP(pub_key, m_int)
    C = I2OSP(c_int, k)
    return C

def RSAES_OAEP_decrypt(priv_key: tuple, C: bytes, label: bytes = b'') -> bytes:
    d, n = priv_key
    k = (n.bit_length() + 7) // 8  
    hlen = len(hash(b''))
    if len(C) != k or k < 2 * hlen + 2:
        raise ValueError("Decryption error")
    c_int = OS2IP(C)
    m_int = RSADP(priv_key, c_int)
    EM = I2OSP(m_int, k)
    M = EME_OAEP_decode(EM, label)
    return M

def RSAES_PKCS1_v1_5_encrypt(pub_key: tuple, M: bytes) -> bytes:
    e, n = pub_key
    k = (n.bit_length() + 7) // 8  
    EM = EME_PKCS1_v1_5_encode(M, k)
    m_int = OS2IP(EM)
    c_int = RSAEP(pub_key, m_int)
    C = I2OSP(c_int, k)
    return C

def RSAES_PKCS1_v1_5_decrypt(priv_key: tuple, C: bytes) -> bytes:
    d, n = priv_key
    k = (n.bit_length() + 7) // 8  
    if len(C) != k:
        raise ValueError("Decryption error")
    c_int = OS2IP(C)
    m_int = RSADP(priv_key, c_int)
    EM = I2OSP(m_int, k)
    M = EME_PKCS1_v1_5_decode(EM)
    return M