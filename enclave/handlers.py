from ecies.utils import generate_key
from ecies import encrypt, decrypt

def encrypt_data(public_key, plaintext):
    encrypted_data = encrypt(bytes.fromhex(public_key), bytes(plaintext))
    return encrypted_data.hex()