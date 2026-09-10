import os
import struct
from typing import Optional, Callable
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# Cryptographic Constants
SALT_SIZE = 16          # 128-bit salt for PBKDF2
NONCE_SIZE = 12         # 96-bit nonce standard for AES-GCM
TAG_SIZE = 16           # 128-bit authentication tag
ITERATIONS = 600000     # OWASP recommendation for PBKDF2-HMAC-SHA256
DEFAULT_CHUNK_SIZE = 64 * 1024  # 64 KB chunks for constant O(1) memory streaming

# File Format Metadata
MAGIC_HEADER = b"SECV"  # 4-byte magic identifier (Secure Vault)
FORMAT_VERSION = 1      # Format version number

def derive_key(password: str | bytes, salt: bytes, iterations: int = ITERATIONS) -> bytes:
    """
    Derives a cryptographically strong 256-bit AES key from a passphrase using PBKDF2-HMAC-SHA256.
    """
    pwd_bytes = password.encode("utf-8") if isinstance(password, str) else password
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(pwd_bytes)

# Legacy alias for backward compatibility
_derive_key = derive_key

def _get_chunk_nonce(base_nonce: bytes, chunk_index: int) -> bytes:
    """
    Derives a deterministic, strictly unique 12-byte nonce for each chunk by XORing the
    64-bit chunk index into the lower 8 bytes of the random base nonce.
    """
    base_int = int.from_bytes(base_nonce[4:], byteorder="big")
    chunk_int = base_int ^ chunk_index
    return base_nonce[:4] + chunk_int.to_bytes(8, byteorder="big")

def encrypt_file(
    input_path: str,
    output_path: str,
    password: str | bytes,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    progress_callback: Optional[Callable[[int, int], None]] = None,
) -> None:
    """
    Encrypts a file of arbitrary size in chunks using AES-256-GCM authenticated encryption.

    Features:
    - O(1) Constant Memory: Streams data in chunks (64 KB default), handling multi-GB files without RAM exhaustion.
    - Tamper & Reorder Proof: Binds chunk index and EOF flag into Authenticated Associated Data (AAD).
    - Atomic Output: Writes to a temporary file first and renames upon success, avoiding partial files.

    Format:
    [Header (37B)]
      - MAGIC (4B): b'SECV'
      - VERSION (1B): 0x01
      - CHUNK_SIZE (4B, uint32)
      - SALT (16B)
      - BASE_NONCE (12B)
    [Body]
      - Sequence of Chunks: [Ciphertext (chunk_size) + AuthTag (16B)]
    """
    total_bytes = os.path.getsize(input_path)
    salt = os.urandom(SALT_SIZE)
    base_nonce = os.urandom(NONCE_SIZE)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)

    temp_output_path = output_path + ".tmp"
    bytes_processed = 0

    try:
        with open(input_path, "rb") as fin, open(temp_output_path, "wb") as fout:
            # Write 37-byte file header
            header = struct.pack(">4sBI", MAGIC_HEADER, FORMAT_VERSION, chunk_size) + salt + base_nonce
            fout.write(header)

            chunk_index = 0
            while True:
                chunk = fin.read(chunk_size)

                # Lookahead 1 byte to check if this is the final chunk
                next_byte = fin.read(1)
                is_last = (len(next_byte) == 0)

                if not is_last:
                    fin.seek(-1, os.SEEK_CUR)

                # Bind metadata to AAD to prevent chunk swapping or premature truncation
                aad = struct.pack(">4sBQI", MAGIC_HEADER, FORMAT_VERSION, chunk_index, 1 if is_last else 0)
                chunk_nonce = _get_chunk_nonce(base_nonce, chunk_index)

                ciphertext = aesgcm.encrypt(chunk_nonce, chunk, aad)
                fout.write(ciphertext)

                bytes_processed += len(chunk)
                if progress_callback:
                    progress_callback(bytes_processed, total_bytes)

                if is_last:
                    break
                chunk_index += 1

        # Atomic replacement of destination file
        if os.path.exists(output_path):
            os.remove(output_path)
        os.rename(temp_output_path, output_path)

    except Exception:
        # Clean up temporary incomplete file on failure
        if os.path.exists(temp_output_path):
            os.remove(temp_output_path)
        raise

def decrypt_file(
    input_path: str,
    output_path: str,
    password: str | bytes,
    progress_callback: Optional[Callable[[int, int], None]] = None,
) -> None:
    """
    Decrypts a file encrypted with streaming AES-256-GCM (with automatic fallback to legacy single-block format).

    Verifies cryptographic integrity and authentication tags per chunk before committing to disk.
    """
    temp_output_path = output_path + ".tmp"
    total_bytes = os.path.getsize(input_path)

    try:
        with open(input_path, "rb") as fin:
            header_prefix = fin.read(4)

            # Check if file has the new chunked stream header
            if header_prefix == MAGIC_HEADER:
                version, chunk_size = struct.unpack(">BI", fin.read(5))
                if version != FORMAT_VERSION:
                    raise ValueError(f"Unsupported format version: {version}")

                salt = fin.read(SALT_SIZE)
                base_nonce = fin.read(NONCE_SIZE)
                if len(salt) < SALT_SIZE or len(base_nonce) < NONCE_SIZE:
                    raise ValueError("Invalid or corrupted encrypted file header.")

                key = derive_key(password, salt)
                aesgcm = AESGCM(key)

                encrypted_chunk_size = chunk_size + TAG_SIZE
                chunk_index = 0
                bytes_processed = 37

                with open(temp_output_path, "wb") as fout:
                    while True:
                        encrypted_chunk = fin.read(encrypted_chunk_size)
                        if not encrypted_chunk:
                            raise ValueError("Unexpected end of file or truncated ciphertext.")

                        # Lookahead to detect EOF
                        next_byte = fin.read(1)
                        is_last = (len(next_byte) == 0)
                        if not is_last:
                            fin.seek(-1, os.SEEK_CUR)

                        aad = struct.pack(">4sBQI", MAGIC_HEADER, FORMAT_VERSION, chunk_index, 1 if is_last else 0)
                        chunk_nonce = _get_chunk_nonce(base_nonce, chunk_index)

                        decrypted_chunk = aesgcm.decrypt(chunk_nonce, encrypted_chunk, aad)
                        fout.write(decrypted_chunk)

                        bytes_processed += len(encrypted_chunk)
                        if progress_callback:
                            progress_callback(bytes_processed, total_bytes)

                        if is_last:
                            break
                        chunk_index += 1

            else:
                # Fallback: Decrypt legacy single-block format
                fin.seek(0)
                salt = fin.read(SALT_SIZE)
                nonce = fin.read(NONCE_SIZE)
                ciphertext = fin.read()

                if len(salt) < SALT_SIZE or len(nonce) < NONCE_SIZE:
                    raise ValueError("Invalid or corrupted encrypted file format.")

                key = derive_key(password, salt)
                aesgcm = AESGCM(key)
                decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)

                with open(temp_output_path, "wb") as fout:
                    fout.write(decrypted_data)

                if progress_callback:
                    progress_callback(total_bytes, total_bytes)

        # Atomic replacement
        if os.path.exists(output_path):
            os.remove(output_path)
        os.rename(temp_output_path, output_path)

    except Exception:
        # Clean up temporary incomplete file on failure
        if os.path.exists(temp_output_path):
            os.remove(temp_output_path)
        raise