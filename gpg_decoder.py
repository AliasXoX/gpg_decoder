# OpenPGP Decoder Module
# Only version 4 signatures are supported.

import base64
from const import PACKET_TAGS, LENGTH_TYPE, SIGNATURE_TYPE, SUBPACKET_TYPE, PUBLIC_KEY_ALGORITHMS, HASH_ALGORITHMS, COMPRESSION_ALGORITHMS, SYMMETRIC_KEY_ALGORITHMS

def packet_header(data: bytes) -> dict:
    """
    Decodes the header of an OpenPGP packet.

    Args:
        data (bytes): The byte sequence containing the packet header.

    Returns:
        dict: A dictionary containing header information.
    """

    header_1 = data[0].to_bytes(1, byteorder='big')  # Read first byte of the packet
    # Convert to binary string representation
    bin_data = ''.join(f'{byte:08b}' for byte in header_1)
    if bin_data[0] != '1':
        raise ValueError("Not a valid OpenPGP packet")
    length = 0
    partial = False
    len_type = None
    if bin_data[1] == '0': # Old Format Packet
        packet_tag = int(bin_data[2:6], 2)
        length_type = int(bin_data[6:8], 2)
        match length_type:
            case 0:
                length = data[1]
                len_type = 1
            case 1:
                length = int.from_bytes(data[1:3], byteorder='big')
                len_type = 2
            case 2:
                length = int.from_bytes(data[1:5], byteorder='big')
                len_type = 4
            case 3:
                raise NotImplementedError("Indeterminate length packets are not supported")
    else: # New Format Packet
        packet_tag = int(bin_data[2:8], 2)
        first_length_byte = data[1]
        match first_length_byte:
            case x if x < 192:
                length = first_length_byte
                len_type = 1
            case x if 192 <= x < 223:
                second_length_byte = data[2]
                length = ((first_length_byte - 192) << 8) + second_length_byte + 192
                len_type = 2
            case 255:
                length = int.from_bytes(data[2:6], byteorder='big')
                len_type = 5
            case x if 224 <= x < 255:
                len_type = 1
                length = 1 << (first_length_byte & 0x1F)
                partial = True
    header_info = {
        "length_type": len_type,
        "partial": partial,
        "header_format": "Old" if bin_data[1] == '0' else "New",
        "packet_tag": PACKET_TAGS[packet_tag],
        "length": length
    }
    return header_info

def signature_subpacket(data: bytes, type: int) -> dict:
    """
    Decodes a signature subpacket from OpenPGP data.

    Args:
        data (bytes): The byte sequence containing the signature subpacket.
    Returns:
        dict: A dictionary containing subpacket information.
    """
    match type:
        case 2:  # Signature Creation Time
            timestamp = int.from_bytes(data[0:4], byteorder='big')
            return {"signature_creation_time": timestamp}
        case 3:  # Signature Expiration Time
            expiration_time = int.from_bytes(data[0:4], byteorder='big')
            return {"signature_expiration_time": expiration_time}
        case 4: # Exportable Certification
            exportable = bool(data[0])
            return {"exportable_certification": exportable}
        case 5:  # Trust Signature
            trust_level = data[0]
            trust_amount = data[1]
            return {"trust_level": trust_level, "trust_amount": trust_amount}
        case 6: # Regular Expression
            regex = data.decode('utf-8')
            return {"regular_expression": regex}
        case 7:  # Revocable
            revocable = bool(data[0])
            return {"revocable": revocable}
        case 9:  # Key Expiration Time
            key_expiration_time = int.from_bytes(data[0:4], byteorder='big')
            return {"key_expiration_time": key_expiration_time}
        case 10:  # Placeholder for backward compatibility
            return {"note": "This subpacket is a placeholder for backward compatibility."}
        case 11:  # Preferred Symmetric Algorithms
            algorithms = list(data)
            return {"preferred_symmetric_algorithms": algorithms}
        case 12:  # Revocation Key
            class_data = data[0]
            key_class = ""
            if class_data == 0x80:
                key_class = "Primary Key"
            elif class_data == 0x40:
                key_class = "Subkey"
            key_alg = data[1]
            fingerprint = data[2:]
            return {"revocation_key": {"key_class": key_class, "key_algorithm": PUBLIC_KEY_ALGORITHMS.get(key_alg, "Unknown"), "fingerprint": fingerprint.hex()}}
        case 16: # Issuer
            issuer_key_id = data[0:8]
            return {"issuer_key_id": issuer_key_id.hex()}
        case 20: # Notation Data
            return {"notation_data": "notation data parsing not implemented"}
        case 21:  # Preferred Hash Algorithms
            algorithms = list(data)
            return {"preferred_hash_algorithms": [HASH_ALGORITHMS.get(algo, "Unknown") for algo in algorithms]}
        case 22:  # Preferred Compression Algorithms
            algorithms = list(data)
            return {"preferred_compression_algorithms": [COMPRESSION_ALGORITHMS.get(algo, "Unknown") for algo in algorithms]}
        case 23:  # Key Server Preferences
            preferences = list(data)
            return {"key_server_preferences": preferences}
        case 24:  # Preferred Key Server
            key_server = data.decode('utf-8')
            return {"preferred_key_server": key_server}
        case 25:  # Primary User ID
            primary_user_id = bool(data[0])
            return {"primary_user_id": primary_user_id}
        case 26:  # Policy URL
            policy_url = data.decode('utf-8')
            return {"policy_url": policy_url}
        case 27:  # Key Flags
            flags = list(data)
            return {"key_flags": flags}
        case 28:  # Signer's User ID
            signer_user_id = data.decode('utf-8')
            return {"signer_user_id": signer_user_id}
        case 29:  # Reason for Revocation
            reason_code = data[0]
            reason_string = data[1:].decode('utf-8')
            return {"reason_for_revocation": {"reason_code": reason_code, "reason_string":  reason_string}}
        case 30:  # Features
            features = list(data)
            return {"features": features}
        case 31:  # Signature Target
            return {"signature_target": "signature target parsing not implemented"}
        case 32:  # Embedded Signature
            return {"embedded_signature": "embedded signature parsing not implemented"}
        case _:
            return {"unknown_subpacket_data": data.hex()}

def signature_packet(data: bytes) -> dict:
    """
    Decodes a signature packet from OpenPGP data.

    Args:
        data (bytes): The byte sequence containing the signature packet body.
    Returns:
        dict: A dictionary containing signature packet information.
    """
    version = data[0]
    if version != 4:
        raise NotImplementedError("Only version 4 signatures are supported")
    
    sig_type = data[1]
    pub_key_algo = data[2]
    hash_algo = data[3]
    hashed_subpacket_len = int.from_bytes(data[4:6], byteorder='big')
    c = 6
    hashed_subpackets = []
    while c < 6 + hashed_subpacket_len:
        subpacket_len = 0
        subpacket_type = 0
        subpacket_body = b''
        match data[c]:
            case x if x < 192:
                subpacket_len = data[c]
                c+=1
                subpacket_type = data[c]
                subpacket_body = data[c+1:c+subpacket_len]
                c += subpacket_len
            case x if 192 <= x < 255:
                subpacket_len = ((data[c] - 192) << 8) + data[c+1] + 192
                c+=2
                subpacket_type = data[c]
                subpacket_body = data[c+1:c+subpacket_len]
                c += subpacket_len
            case 255:
                subpacket_len = int.from_bytes(data[c+1:c+5], byteorder='big')
                c+=5
                subpacket_type = data[c]
                subpacket_body = data[c+1:c+subpacket_len]
                c += subpacket_len
        decoded_subpacket = signature_subpacket(subpacket_body, subpacket_type)
        decoded_subpacket = {"length": subpacket_len, "type": SUBPACKET_TYPE[subpacket_type] if subpacket_type < len(SUBPACKET_TYPE) else "Unknown", **decoded_subpacket}
        hashed_subpackets.append(decoded_subpacket)
    
    unhashed_subpackets_len = int.from_bytes(data[c:c+2], byteorder='big')
    c += 2
    start = c
    unhashed_subpackets = []
    while c < start + unhashed_subpackets_len:
        subpacket_len = 0
        subpacket_type = 0
        subpacket_body = b''
        match data[c]:
            case x if x < 192:
                subpacket_len = data[c]
                c+=1
                subpacket_type = data[c]
                subpacket_body = data[c+1:c+subpacket_len]
                c += subpacket_len
            case x if 192 <= x < 255:
                subpacket_len = ((data[c] - 192) << 8) + data[c+1] + 192
                c+=2
                subpacket_type = data[c]
                subpacket_body = data[c+1:c+subpacket_len]
                c += subpacket_len
            case 255:
                subpacket_len = int.from_bytes(data[c+1:c+5], byteorder='big')
                c+=5
                subpacket_type = data[c]
                subpacket_body = data[c+1:c+subpacket_len]
                c += subpacket_len
        decoded_subpacket = signature_subpacket(subpacket_body, subpacket_type)
        decoded_subpacket = {"length": subpacket_len, "type": SUBPACKET_TYPE[subpacket_type] if subpacket_type < len(SUBPACKET_TYPE) else "Unknown", **decoded_subpacket}
        unhashed_subpackets.append(decoded_subpacket)
    
    signed_hash = data[c:c+2]
    c+=2
    signature = data[c:]

    signature_info = {
        "version": version,
        "signature_type": SIGNATURE_TYPE.get(sig_type.to_bytes(1, byteorder='big'), "Unknown"),
        "public_key_algorithm": PUBLIC_KEY_ALGORITHMS.get(pub_key_algo, "Unknown"),
        "hash_algorithm": HASH_ALGORITHMS.get(hash_algo, "Unknown"),
        "hash_subpacket_count": hashed_subpacket_len,
        "hashed_subpackets": hashed_subpackets,
        "unhashed_subpacket_count": unhashed_subpackets_len,
        "unhashed_subpackets": unhashed_subpackets,
        "signed_hash_value": signed_hash.hex(),
        "signature": signature.hex()
    }
    return signature_info

def public_key_packet(data: bytes) -> dict:
    """
    Decodes a public key packet from OpenPGP data.

    Args:
        data (bytes): The byte sequence containing the public key packet body.
    Returns:
        dict: A dictionary containing public key packet information.
    """
    # 1 octet Version
    version = data[0]
    if version != 4:
        raise NotImplementedError("Only version 4 secret keys are supported")

    # 4 octets Creation Time
    created_at = int.from_bytes(data[1:5], byteorder='big')

    # 1 octet Public Key Algorithm ID
    pub_key_algo = data[5]

    # Public Key Material
    if pub_key_algo not in [1, 2, 3]: # not RSA
        raise NotImplementedError("Only RSA secret keys are supported")

    c = 6
    n_len = (int.from_bytes(data[c:c+2], byteorder='big') + 7) // 8
    c += 2
    n = data[c:c+n_len]
    c += n_len
    e_len = (int.from_bytes(data[c:c+2], byteorder='big') + 7) // 8
    c += 2
    e = data[c:c+e_len]
    c += e_len

    public_key_info = {
        "version": version,
        "creation_time": created_at,
        "public_key_algorithm": PUBLIC_KEY_ALGORITHMS.get(pub_key_algo, "Unknown"),
        "n": n.hex(),
        "e": e.hex()
    }
    return public_key_info

def secret_key_packet(data: bytes) -> dict:
    """
    Decodes a secret key packet from OpenPGP data.

    Args:
        data (bytes): The byte sequence containing the secret key packet body.
    Returns:
        dict: A dictionary containing secret key packet information.
    """
    # 1 octet Version
    version = data[0]
    if version != 4:
        raise NotImplementedError("Only version 4 secret keys are supported")

    # 4 octets Creation Time
    created_at = int.from_bytes(data[1:5], byteorder='big')

    # 1 octet Public Key Algorithm ID
    pub_key_algo = data[5]

    # Public Key Material
    if pub_key_algo not in [1, 2, 3]: # not RSA
        raise NotImplementedError("Only RSA secret keys are supported")

    c = 6
    n_len = (int.from_bytes(data[c:c+2], byteorder='big') + 7) // 8
    c += 2
    n = data[c:c+n_len]
    c += n_len
    e_len = (int.from_bytes(data[c:c+2], byteorder='big') + 7) // 8
    c += 2
    e = data[c:c+e_len]
    c += e_len

    # Secret Key Specific Fields

    s2k_usage = data[c]
    c += 1
    s2k_encrytion_algo = None
    s2k_specifier = None
    secret_key_material = None
    iv = None
    if s2k_usage == 254 or s2k_usage == 255:
        s2k_encryption_algo = data[c]
        c += 1
        match data[c]:
            case 0:  # Simple S2K
                s2k_specifier = {"type": "Simple S2K"}
                c += 1
                s2k_specifier["hash_algorithm"] = HASH_ALGORITHMS.get(data[c], "Unknown")
                c += 1
            case 1:  # Salted S2K
                s2k_specifier = {"type": "Salted S2K"}
                c += 1
                s2k_specifier["hash_algorithm"] = HASH_ALGORITHMS.get(data[c], "Unknown")
                c += 1
                s2k_specifier["salt"] = data[c:c+8].hex()
                c += 8
            case 3:  # Iterated and Salted S2K
                s2k_specifier = {"type": "Iterated and Salted S2K"}
                c += 1
                s2k_specifier["hash_algorithm"] = HASH_ALGORITHMS.get(data[c], "Unknown")
                c += 1
                s2k_specifier["salt"] = data[c:c+8].hex()
                c += 8
                s2k_specifier["count"] = (16 + (data[c] & 15)) << ((data[c] >> 4) + 6)
                c += 1
        iv_length = 0
        match s2k_encryption_algo:
            case 7:  # AES-128
                iv_length = 128 // 8
            case 8:  # AES-192
                iv_length = 192 // 8
            case 9:  # AES-256
                iv_length = 256 // 8
            case _:
                raise NotImplementedError("Only AES symmetric encryption is supported for secret keys")
        iv = data[c:c+iv_length]
        c += iv_length

    if not s2k_usage == 254:
       raise NotImplementedError("Only S2K usage 254 (encrypted secret key) is supported")
    
    secret_key_material = data[c:]

    secret_key_info = {
        "version": version,
        "creation_time": created_at,
        "public_key_algorithm": PUBLIC_KEY_ALGORITHMS.get(pub_key_algo, "Unknown"),
        "n": n.hex(),
        "e": e.hex(),
        "s2k_usage": s2k_usage,
        "s2k_encryption_algorithm": SYMMETRIC_KEY_ALGORITHMS.get(s2k_encryption_algo, "Unknown"),
        "s2k_specifier": s2k_specifier,
        "iv": iv.hex() if iv else None,
        "secret_key_material": secret_key_material.hex()
    }
    return secret_key_info


def secret_key_material(data: bytes) -> dict:
    """
    Decodes secret key material from OpenPGP data.

    Args:
        data (bytes): The byte sequence containing the decrypted secret key material.
    Returns:
        dict: A dictionary containing secret key material information.
    """
    c = 0
    # Algorithm-specific Field for RSA Secret Key
    d_len = (int.from_bytes(data[c:c+2], byteorder='big') + 7) // 8
    c += 2
    d = data[c:c+d_len]
    c += d_len
    p_len = (int.from_bytes(data[c:c+2], byteorder='big') + 7) // 8
    c += 2
    p = data[c:c+p_len]
    c += p_len
    q_len = (int.from_bytes(data[c:c+2], byteorder='big') + 7) // 8
    c += 2
    q = data[c:c+q_len]
    c += q_len
    u_len = (int.from_bytes(data[c:c+2], byteorder='big') + 7) // 8
    c += 2
    u = data[c:c+u_len]
    c += u_len

    end_hash = data[c:c+20]

    secret_key_material = {
        "d": d,
        "p": p,
        "q": q,
        "u": u,
        "end_hash": end_hash
    }

def user_id_packet(data: bytes) -> dict:
    """
    Decodes a user ID packet from OpenPGP data.

    Args:
        data (bytes): The byte sequence containing the user ID packet body.
    Returns:
        dict: A dictionary containing user ID packet information.
    """
    user_id = data.decode('utf-8')
    return {"user_id": user_id}

def public_key_encrypted_session_key_packet(data: bytes) -> dict:
    """
    Decodes a public key encrypted session key packet from OpenPGP data.

    Args:
        data (bytes): The byte sequence containing the packet body.
    Returns:
        dict: A dictionary containing packet information.
    """
    version = data[0]
    if version != 3:
        raise NotImplementedError("Only version 3 public key encrypted session key packets are supported")
    
    key_id = data[1:9]

    pub_key_algo = data[9]

    encrypted_session_key = data[10:]

    packet_info = {
        "version": version,
        "key_id": key_id.hex(),
        "public_key_algorithm": PUBLIC_KEY_ALGORITHMS.get(pub_key_algo, "Unknown"),
        "encrypted_session_key": encrypted_session_key.hex()
    }
    return packet_info

def sym_encrypted_integrity_protected_data_packet(data: bytes) -> dict:
    """
    Decodes a symmetrically encrypted integrity protected data packet from OpenPGP data.

    Args:
        data (bytes): The byte sequence containing the packet body.
    Returns:
        dict: A dictionary containing packet information.
    """
    version = data[0]
    if version != 1:
        raise NotImplementedError("Only version 1 symmetrically encrypted integrity protected data packets are supported")
    data_body = data[1:]
    packet_info = {
        "version": version,
        "data_body": data_body.hex()
    }
    return packet_info

def parse_file(path: str) -> list:
    """
    Parses an OpenPGP file and decodes its packets.

    Args:
        path (str): The file path to the OpenPGP file.
    Returns:
        list: A list of dictionaries containing decoded packet information.
    """

    file = open(path, "r+")
    content = ""
    for line in file:
        if line.startswith('-----'):
            continue
        content += line.strip()
    file.close()

    # Decode base64 content
    data = base64.b64decode(content)
    c = 0
    packets = []
    while c < len(data):
        header = packet_header(data[c:])
        c += 1  # Move past the first byte already read in header

        c += header["length_type"] # Move past length bytes

        packet_body = data[c:c+header["length"]]
        c += header["length"]
        if header["partial"]:
            while True:
                partial_header = data[c]
                if 224 <= partial_header < 255:
                    partial_length = 1 << (partial_header & 0x1F)
                    c += 1
                    packet_body += data[c:c+partial_length]
                    c += partial_length
                    header["length"] += partial_length
                else:
                    match partial_header:
                        case x if x < 192:
                            partial_length = partial_header
                            c += 1
                        case x if 192 <= x < 255:
                            second_length_byte = data[c+1]
                            partial_length = ((partial_header - 192) << 8) + second_length_byte + 192
                            c += 2
                        case 255:
                            partial_length = int.from_bytes(data[c+1:c+5], byteorder='big')
                            c += 5
                    packet_body += data[c:c+partial_length]
                    c += partial_length
                    header["length"] += partial_length
                    break
        match header["packet_tag"]:
            case "Public Key Packet":
                decoded_packet = public_key_packet(packet_body)
            case "Public Subkey Packet":
                decoded_packet = public_key_packet(packet_body)
            case "Secret Key Packet":
                decoded_packet = secret_key_packet(packet_body)
            case "Secret Subkey Packet":
                decoded_packet = secret_key_packet(packet_body)
            case "Signature Packet":
                decoded_packet = signature_packet(packet_body)
            case "User ID Packet":
                decoded_packet = user_id_packet(packet_body)
            case "Public-Key Encrypted Session Key Packet":
                decoded_packet = public_key_encrypted_session_key_packet(packet_body)
            case "Sym. Encrypted and Integrity Protected Data Packet":
                decoded_packet = sym_encrypted_integrity_protected_data_packet(packet_body)
            case _:
                decoded_packet = {"note": f"Decoding for {header['packet_tag']} not implemented."}
        decoded_packet = {"packet_tag": header["packet_tag"], "length": header["length"], "partial": header["partial"], **decoded_packet}
        packets.append(decoded_packet)
    return packets

# Utils

def pretty_dict(d: dict, indent: int = 0) -> None:
    for key, value in d.items():
        if isinstance(value, dict):
            print(f"{' ' * indent}{key}:")
            pretty_dict(value, indent + 4)
        elif isinstance(value, list):
            print(f"{' ' * indent}{key}:")
            for item in value:
                if isinstance(item, dict):
                    pretty_dict(item, indent + 4)
                else:
                    print(f"{' ' * (indent + 4)}{item}")
        else:
            print(f"{' ' * indent}{key}: {value}")

def to_hex(path: str) -> None:
    file = open(path, "r+")
    content = ""
    for line in file:
        if line.startswith('-----'):
            continue
        content += line.strip()
    file.close()

    # Decode base64 content
    data = base64.b64decode(content)

    print(data.hex())

path = "enter_path_to_gpg_file" 

packets = parse_file(path)

for packet in packets:
    print()
    pretty_dict(packet)
    print()
