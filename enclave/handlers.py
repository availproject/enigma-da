from ecies.utils import generate_key
from ecies import encrypt, decrypt
from vssspy import reconstruct_secret
import json
import urllib.request

def encrypt_data(public_key, plaintext):
    encrypted_data = encrypt(bytes.fromhex(public_key), bytes(plaintext))
    return encrypted_data.hex()

def fetch_shares():
    query = "https://<domain>/get-share"
    data = urllib.request.urlopen(query)
    response = json.loads(data.read())
    shares = response.get('shares')
    return shares

def decrypt_data(encrypted_data):
    secret_shares = fetch_shares()
    secret = reconstruct_secret(secret_shares)
    decrypted_data = decrypt(bytes(secret), bytes(encrypted_data))
    return decrypted_data.hex()