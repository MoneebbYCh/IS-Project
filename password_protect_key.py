from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
import secrets
import binascii

# Constants for key derivation
SALT_SIZE = 16  # Size of the salt for PBKDF2
KEY_LENGTH = 32  # AES-256 requires a 32-byte key
ITERATIONS = 100000  # Number of iterations for PBKDF2

def pad(data):
    padding_length = AES.block_size - len(data) % AES.block_size
    padding = bytes([padding_length] * padding_length)
    return data + padding

def derive_key(password):
    """
    Derives a 32-byte AES key from the provided password.
    Uses PBKDF2 with a salt and high iteration count.
    """
    salt = secrets.token_bytes(SALT_SIZE)
    key = PBKDF2(password, salt, dkLen=KEY_LENGTH, count=ITERATIONS)
    return key, salt

def encrypt_key_with_password(password, key):
    """
    Encrypts the provided AES key using a password-derived key.
    Returns the encrypted key prefixed with an IV and the salt.
    """
    derived_key, salt = derive_key(password)
    iv = secrets.token_bytes(AES.block_size)
    cipher = AES.new(derived_key, AES.MODE_CBC, iv)
    encrypted_key = iv + cipher.encrypt(pad(binascii.unhexlify(key)))
    return encrypted_key, salt

def save_encrypted_key_file(password, key, filepath):
    """
    Encrypts the key with the given password and saves it to a file with a .enc extension.
    """
    encrypted_key, salt = encrypt_key_with_password(password, key)
    with open(filepath + "_key.enc", 'wb') as key_file:
        key_file.write(salt + encrypted_key)
