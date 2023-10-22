from .libs import model_crypto as C


def encrypt_with_header(data: bytes, key: str, iv: str, magic_number: str = "MODEL", version: str = "VERSION:1.0") -> bytes:
    """
    Encrypts the given data using AES encryption with additional header information.

    Args:
        data (bytes): The data to be encrypted.
        key (str): The AES encryption key.
        iv (str): The initialization vector (IV) for encryption.
        magic_number (str, optional): The magic number to include in the header. Defaults to "MODEL".
        version (str, optional): The version information to include in the header. Defaults to "VERSION:1.0".

    Returns:
        bytes: The encrypted data including the header.
    """
    return C.EncryptWithHeader(data, key, iv, magic_number, version)


def decrypt_with_header(cipher: bytes, key: str, iv: str) -> bytes:
    """
    Decrypts the given data with an encrypted header using AES decryption.

    Args:
        cipher (bytes): The data to be decrypted, including the header.
        key (str): The AES decryption key.
        iv (str): The initialization vector (IV) for decryption.

    Returns:
        bytes: The decrypted data without the header.
    """
    return C.DecryptWithHeader(cipher, key, iv)


def generate_aes_key(content: str) -> str:
    """
    Generates an AES encryption key based on the provided content.

    Args:
        content (str): The content used to generate the AES key.

    Returns:
        str: The generated AES key.
    """
    return C.GenerateAESKey(content)


def generate_random_iv() -> str:
    """
    Generates a random Initialization Vector (IV) for AES encryption.

    Returns:
        str: The randomly generated IV.
    """
    return C.GenerateRandomIV()
