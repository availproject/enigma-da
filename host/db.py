from host.models import RegisterRequest
import hashlib
import plyvel
import struct

db = plyvel.DB('./app_data', create_if_missing=True)

def register_app(register_params: RegisterRequest):
    """
    Registers an application by storing their public key and assigning a unique app_id.

    Args:
        register_params: Application details including app_id and public key.

    Returns:
        int: The app_id, or None if app is already registered.
    """
    public_key = register_params.public_key
    app_id = register_params.app_id

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