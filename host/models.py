from pydantic import BaseModel
from typing import List

class RegisterRequest(BaseModel):
    """
    Request body model for registering an application.
    
    Attributes:
        app_id (int): A unique application id
        public_key (List[int]): The public key to be registered as raw bytes.
    """
    app_id: int
    public_key: List[int]

class RegisterResponse(BaseModel):
    """
    Response body model after attempting app registration.
    
    Attributes:
        app_id (int): The generated app_id if registration was successful.
    """
    app_id: int
    

class EncryptionRequest(BaseModel):
    """
    Request body model for encryption.

    Attributes:
        app_id (int): Application id for fetching public key
        plaintext (List[int]): Plaintext to be encrypted as raw bytes
    """
    app_id: int
    plaintext: List[int]

class EncryptionResponse(BaseModel):
    """
    Response body model after attempting data encryption.

    Attributes:
        encrypted_data (List[int]): Combined raw bytes of ephemeral public key and ciphertext
    """
    encrypted_data: List[int]

class DecryptionRequest(BaseModel):
    """
    """
    app_id: int
    encrypted_data: List[int]

class DecryptionResponse(BaseModel):
    """
    """
    plaintext: List[int]