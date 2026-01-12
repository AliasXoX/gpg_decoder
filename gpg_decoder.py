# OpenPGP Decoder Module
# Only version 4 signatures are supported.

import base64
import zlib
import hashlib
from Crypto.Cipher import AES
from packets import Packet, MPI
from rsa import RSAES_PKCS1_v1_5_decrypt

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
                # Assume to the end of the file for simplicity
                length = len(data) - 1
                len_type = 0
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
        "packet_tag": packet_tag,
        "length": length
    }
    return header_info

def parse_file(m: str or bytes) -> list:
    """
    Parses an OpenPGP file and decodes its packets.

    Args:
        m (str): The file path to the OpenPGP file.
        m (bytes): The byte content of the OpenPGP file.
    Returns:
        list: A list of dictionaries containing decoded packet information.
    """
    data = b''
    if isinstance(m, bytes):
        data = m
    else:
        file = open(m, "r+")
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
        packet = Packet(tag=header["packet_tag"], length=header["length"], body=packet_body, partial=header["partial"], new=(header["header_format"] == "New"))
        packets.append(packet)
    return packets

def decrypt_s2k_iterated_salted(passphrase: str, salt: bytes, count: int, iv: bytes, enc_data: bytes) -> dict:
    """
        Decrypts data encrypted with GPG's Iterated and Salted S2K method using AES in CFB mode.
    """
    salted_passphrase = salt + passphrase.encode('utf-8')
    h = hashlib.sha1()
    while count > 0:
        chunk = salted_passphrase[:min(len(salted_passphrase), count)]
        h.update(chunk)
        count -= len(chunk)
    key = h.digest()[:16]

    aes = AES.new(key, AES.MODE_CFB, iv=iv, segment_size=128)
    data = aes.decrypt(enc_data)
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

    info = {
        "d": d,
        "p": p,
        "q": q,
        "u": u,
        "end_hash": end_hash
    }

    return info

def decrypt_message(m_path: str, key_path: str, passphrase: str) -> bytes:
    """
    Decrypts an OpenPGP encrypted message using the provided private key.

    Args:
        m_path (str): The file path to the encrypted message.
        key_path (str): The file path to the private key.
        passphrase (str): The passphrase for the private key.
    Returns:
        bytes: The decrypted message.
    """
    m_packets = parse_file(m_path)
    key_packets = parse_file(key_path)

    # Extract the private key from the key packets
    private_key = None
    n = b''
    for packet in key_packets:
        if packet.tag == 7:  # Secret subkey Packet
            n = int.from_bytes(packet.decoded['n'], byteorder='big')
            if packet.decoded['s2k_encryption_algorithm'].algo_id not in [7, 8, 9]:  # Not AES variants
                raise ValueError("Unsupported encryption algorithm for private key, only AES variants are supported.")
            if packet.decoded['s2k_specifier']['type'] != "Iterated and Salted S2K":
                raise ValueError("Unsupported S2K specifier for private key, only Iterated and Salted S2K is supported.")

            salt = packet.decoded['s2k_specifier']['salt']
            count = packet.decoded['s2k_specifier']['count']
            iv = packet.decoded['iv']
            enc_secret_key_material = packet.decoded['secret_key_material']
            private_key_info = decrypt_s2k_iterated_salted(passphrase, salt, count, iv, enc_secret_key_material)
            private_key = (int.from_bytes(private_key_info['d'], byteorder='big'), n)  # RSA private exponent
            break
    if not private_key:
        raise ValueError("No suitable private key found in the key file.")

    # Extract the encrypted session key from the message packets
    enc_session_key = b''
    for packet in m_packets:
        if packet.tag == 1:  # Public-Key Encrypted Session Key Packet
            mpi_enc_session_key = MPI(packet.decoded['encrypted_session_key'])
            enc_session_key = mpi_enc_session_key.value.to_bytes(mpi_enc_session_key.byte_length, byteorder='big')
            break


    session = RSAES_PKCS1_v1_5_decrypt(private_key, enc_session_key) # First byte is the symmetric algorithm, last two bytes are checksum
    sym_alg = session[0]
    session_key = session[1:-2]  # Exclude first byte and last two
    checksum = session[-2:]

    if sym_alg not in [7, 8, 9]:  # Not AES variants
        raise ValueError("Unsupported symmetric algorithm for session key, only AES variants are supported.")
    iv = b'\x00' * 16
    aes = AES.new(session_key, AES.MODE_CFB, iv=iv, segment_size=128)

    # Decrypt the message data
    decrypted_data = b''
    for packet in m_packets:
        if packet.tag == 18:  # Symmetrically Encrypted and Integrity Protected Data Packet
            enc_data = packet.decoded['data_body']
            decrypted_data += aes.decrypt(enc_data)
    
    # Remove the MDC packet (last 22 bytes) and the 18-byte prefix
    message_packets = parse_file(decrypted_data[18:-22])

    message = b''
    for packet in message_packets:
        if packet.tag == 8: # Compressed Data Packet
            if packet.decoded['compression_algorithm'].algo_id != 2:  # Not ZLIB
                raise ValueError("Unsupported compression algorithm, only ZLIB is supported.")
            message = zlib.decompress(packet.decoded['compressed_data'])

    return message


#path = "./private_winrard.key"
path = "./message_crypted.txt"
message = decrypt_message(path, "./private_winrard.key", "winrard")