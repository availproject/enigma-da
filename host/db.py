from host.models import RegisterRequest
import hashlib
import plyvel
import struct

db = plyvel.DB('./app_data', create_if_missing=True)

def generate_app_id(public_key: str) -> int:
    """
    Generates a unique app_id derived from public key

    Args:
        public_key (str): Application's public key as string

    Returns:
        int: A unique app_id
    """
    hashed_key = hashlib.sha256(public_key.encode()).digest()
    app_id = struct.unpack('>Q', hashed_key[:8])[0]
    return app_id

def register_app(register_params: RegisterRequest):
    """
    Registers an application by storing their public key and assigning a unique app_id.

    Args:
        register_params: Application details including public key.

    Returns:
        int: The assigned app_id, or None if app is already registered.
    """
    public_key = register_params.public_key
    app_id = generate_app_id(str(public_key))

    if db.get(str(app_id).encode()):
        return None

    db.put(str(app_id).encode(), bytes(public_key))

    return app_id

def get_public_key(app_id: int):
    """
    Retrieves the public key associated with a given app_id.

    Args:
        app_id (int): The app_id for which the public key is requested.

    Returns:
        str: The public key associated with the app_id, or None if not found.
    """
    public_key_bytes = db.get(str(app_id).encode())

    if public_key_bytes:
        return public_key_bytes.hex()
    else:
        return None