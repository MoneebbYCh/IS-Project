from Crypto.Cipher import AES
import secrets
import binascii
import os
from password_protect_key import save_encrypted_key_file  # Import the password protection functions

def pad(data):
    padding_length = AES.block_size - len(data) % AES.block_size
    padding = bytes([padding_length] * padding_length)
    return data + padding

def unpad(data):
    padding_length = data[-1]
    return data[:-padding_length]

def encrypt_text(key, plaintext):
    """
    Encrypts plaintext using the provided AES key and returns the encrypted text.
    """
    iv = secrets.token_bytes(AES.block_size)
    cipher = AES.new(binascii.unhexlify(key), AES.MODE_CBC, iv)
    padded_data = pad(plaintext.encode())
    encrypted = iv + cipher.encrypt(padded_data)
    result = binascii.hexlify(encrypted).decode()
    
    # Securely clear sensitive data
    del padded_data, plaintext, key
    
    return result

def encrypt_file(key, filepath, password=None, progress_callback=None):
    """
    Encrypts the contents of a file and optionally saves the key with password protection.
    """
    iv = secrets.token_bytes(AES.block_size)
    cipher = AES.new(binascii.unhexlify(key), AES.MODE_CBC, iv)
    encrypted_filepath = filepath + '.enc'
    filesize = os.path.getsize(filepath)
    total_chunks = (filesize // (1024 * AES.block_size)) + 1

    with open(filepath, 'rb') as f_in, open(encrypted_filepath, 'wb') as f_out:
        f_out.write(iv)
        for i, chunk in enumerate(iter(lambda: f_in.read(1024 * AES.block_size), b'')):
            if len(chunk) % AES.block_size != 0:
                chunk = pad(chunk)
            f_out.write(cipher.encrypt(chunk))
            if progress_callback:
                progress_callback((i + 1) / total_chunks * 100)
    
    # Save the key file with password protection if a password is provided
    if password:
        save_encrypted_key_file(password, key, filepath)
    else:
        with open(filepath + "_key.txt", 'w') as key_file:
            key_file.write(key)
    
    # Securely clear sensitive data
    del iv, key, cipher
    
    return encrypted_filepath
