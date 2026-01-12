from const import PACKET_TAGS, LENGTH_TYPE, SIGNATURE_TYPE, SUBPACKET_TYPE, PUBLIC_KEY_ALGORITHMS, HASH_ALGORITHMS, SYMMETRIC_KEY_ALGORITHMS, COMPRESSION_ALGORITHMS

def pretty_dict(d: dict, body: str = "", indent: int = 0) -> str:
    for key, value in d.items():
        if isinstance(value, dict):
            body += f"{' ' * indent}{key}:\n"
            body = pretty_dict(value, body, indent + 4)
        elif isinstance(value, list):
            body += f"{' ' * indent}{key}:\n"
            for item in value:
                if isinstance(item, dict):
                    body = pretty_dict(item, body, indent + 4)
                else:
                    body += f"{' ' * (indent + 4)}{item}\n"
        else:
            body += f"{' ' * indent}{key}: {value if not isinstance(value, bytes) else value.hex()}\n"
    return body

class Packet:
    def __init__(self, tag: int, length: int, body: bytes, partial: bool = False, new: bool = True):
        self.tag = tag
        self.length = length
        self.body = body
        self.partial = partial
        self.new = new
        self.decoded = self._decode()

    def __repr__(self):
        return(pretty_dict({"tag": PACKET_TAGS[self.tag] if self.tag < len(PACKET_TAGS) else "Unknown", "length": self.length, "partial": self.partial, "new_format": self.new, **self.decoded}))

    def _decode(self):
        match self.tag:
            case 1:  # Public Key Encrypted Session Key Packet
                return self.__public_key_encrypted_session_key_packet(self.body)
            case 2:  # Signature Packet
                return self.__signature_packet(self.body)
            case 5:  # Secret Key Packet
                return self.__secret_key_packet(self.body)
            case 6:  # Public Key Packet
                return self.__public_key_packet(self.body)
            case 7: # Secret Subkey Packet
                return self.__secret_key_packet(self.body)
            case 8:  # Compressed Data Packet
                return self.__compressed_data_packet(self.body)
            case 13:  # User ID Packet
                return self.__user_id_packet(self.body)
            case 14:  # Public Subkey Packet
                return self.__public_key_packet(self.body)
            case 18:  # Sym. Encrypted and Integrity Protected Data Packet
                return self.__sym_encrypted_integrity_protected_data_packet(self.body)
            case _:
                return {"body_hex": self.body}
    

    def __signature_packet(self, data: bytes) -> dict:
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
            decoded_subpacket = self.__signature_subpacket(subpacket_body, subpacket_type)
            decoded_subpacket = {"length": subpacket_len, "type": SubpacketType(subpacket_type), **decoded_subpacket}
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
            decoded_subpacket = self.__signature_subpacket(subpacket_body, subpacket_type)
            decoded_subpacket = {"length": subpacket_len, "type": SubpacketType(subpacket_type), **decoded_subpacket}
            unhashed_subpackets.append(decoded_subpacket)
        
        signed_hash = data[c:c+2]
        c+=2
        signature = data[c:]

        signature_info = {
            "version": version,
            "signature_type": SignatureType(sig_type.to_bytes(1, byteorder='big')),
            "public_key_algorithm": PublicKeyAlgorithm(pub_key_algo),
            "hash_algorithm": HashAlgorithm(hash_algo),
            "hash_subpacket_count": hashed_subpacket_len,
            "hashed_subpackets": hashed_subpackets,
            "unhashed_subpacket_count": unhashed_subpackets_len,
            "unhashed_subpackets": unhashed_subpackets,
            "signed_hash_value": signed_hash,
            "signature": signature
        }
        return signature_info

    def __signature_subpacket(self, data: bytes, type: int) -> dict:
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
                return {"revocation_key": {"key_class": key_class, "key_algorithm": PublicKeyAlgorithm(key_alg), "fingerprint": fingerprint}}
            case 16: # Issuer
                issuer_key_id = data[0:8]
                return {"issuer_key_id": issuer_key_id}
            case 20: # Notation Data
                return {"notation_data": "notation data parsing not implemented"}
            case 21:  # Preferred Hash Algorithms
                algorithms = list(data)
                return {"preferred_hash_algorithms": [HashAlgorithm(algo) for algo in algorithms]}
            case 22:  # Preferred Compression Algorithms
                algorithms = list(data)
                return {"preferred_compression_algorithms": [CompressionAlgorithm(algo) for algo in algorithms]}
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
                return {"unknown_subpacket_data": data}

    def __public_key_packet(self, data: bytes) -> dict:
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
            "public_key_algorithm": PublicKeyAlgorithm(pub_key_algo),
            "n": n,
            "e": e
        }
        return public_key_info

    def __secret_key_packet(self, data: bytes) -> dict:
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
                    s2k_specifier["hash_algorithm"] = HashAlgorithm(data[c])
                    c += 1
                case 1:  # Salted S2K
                    s2k_specifier = {"type": "Salted S2K"}
                    c += 1
                    s2k_specifier["hash_algorithm"] = HashAlgorithm(data[c])
                    c += 1
                    s2k_specifier["salt"] = data[c:c+8]
                    c += 8
                case 3:  # Iterated and Salted S2K
                    s2k_specifier = {"type": "Iterated and Salted S2K"}
                    c += 1
                    s2k_specifier["hash_algorithm"] = HashAlgorithm(data[c])
                    c += 1
                    s2k_specifier["salt"] = data[c:c+8]
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
            "public_key_algorithm": PublicKeyAlgorithm(pub_key_algo),
            "n": n,
            "e": e,
            "s2k_usage": s2k_usage,
            "s2k_encryption_algorithm": SymmetricKeyAlgorithm(s2k_encryption_algo) if s2k_encryption_algo is not None else None,
            "s2k_specifier": s2k_specifier,
            "iv": iv if iv else None,
            "secret_key_material": secret_key_material
        }
        return secret_key_info

    def __user_id_packet(self, data: bytes) -> dict:
        """
        Decodes a user ID packet from OpenPGP data.

        Args:
            data (bytes): The byte sequence containing the user ID packet body.
        Returns:
            dict: A dictionary containing user ID packet information.
        """
        user_id = data.decode('utf-8')
        return {"user_id": user_id}

    def __public_key_encrypted_session_key_packet(self, data: bytes) -> dict:
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
            "key_id": key_id,
            "public_key_algorithm": PublicKeyAlgorithm(pub_key_algo),
            "encrypted_session_key": encrypted_session_key
        }
        return packet_info

    def __sym_encrypted_integrity_protected_data_packet(self, data: bytes) -> dict:
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
            "data_body": data_body
        }
        return packet_info

    def __compressed_data_packet(self, data: bytes) -> dict:
        """
        Decodes a compressed data packet from OpenPGP data.

        Args:
            data (bytes): The byte sequence containing the packet body.
        Returns:
            dict: A dictionary containing packet information.
        """
        compression_algo = data[0]
        compressed_data = data[1:]
        packet_info = {
            "compression_algorithm": CompressionAlgorithm(compression_algo),
            "compressed_data": compressed_data
        }
        return packet_info

class MPI:
    def __init__(self, data: bytes):
        self.data = data
        c = 0
        self.bit_length = int.from_bytes(data[c:c+2], byteorder='big')
        c += 2
        byte_length = (self.bit_length + 7) // 8
        self.value = int.from_bytes(data[c:c+byte_length], byteorder='big')
        self.byte_length = byte_length

class PacketTag():
    def __init__(self, tag: int):
        self.tag = tag
        self.name = PACKET_TAGS[tag] if tag < len(PACKET_TAGS) else "Unknown"

    def __repr__(self):
        return f"{self.name} (Tag {self.tag})"

class SignatureType():
    def __init__(self, sig_type: bytes):
        self.sig_type = sig_type
        self.name = SIGNATURE_TYPE.get(sig_type, "Unknown")

    def __repr__(self):
        return f"{self.name} (Type {self.sig_type})"

class SubpacketType():
    def __init__(self, subpacket_type: int):
        self.subpacket_type = subpacket_type
        self.name = SUBPACKET_TYPE[subpacket_type] if subpacket_type < len(SUBPACKET_TYPE) else "Unknown"

    def __repr__(self):
        return f"{self.name} (Type {self.subpacket_type})"

class PublicKeyAlgorithm():
    def __init__(self, algo_id: int):
        self.algo_id = algo_id
        self.name = PUBLIC_KEY_ALGORITHMS.get(algo_id, "Unknown")

    def __repr__(self):
        return f"{self.name} (ID {self.algo_id})"

class HashAlgorithm():
    def __init__(self, algo_id: int):
        self.algo_id = algo_id
        self.name = HASH_ALGORITHMS.get(algo_id, "Unknown")

    def __repr__(self):
        return f"{self.name} (ID {self.algo_id})"

class SymmetricKeyAlgorithm():
    def __init__(self, algo_id: int):
        self.algo_id = algo_id
        self.name = SYMMETRIC_KEY_ALGORITHMS.get(algo_id, "Unknown")

    def __repr__(self):
        return f"{self.name} (ID {self.algo_id})"

class CompressionAlgorithm():
    def __init__(self, algo_id: int):
        self.algo_id = algo_id
        self.name = COMPRESSION_ALGORITHMS.get(algo_id, "Unknown")

    def __repr__(self):
        return f"{self.name} (ID {self.algo_id})"