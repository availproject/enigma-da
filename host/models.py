from pydantic import BaseModel
from typing import List

class RegisterRequest(BaseModel):
    """
    Request body model for registering an application.
    
    Attributes:
        public_key (List[int]): The public key to be registered as raw bytes.
    """
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
        encryptedMessage (str): Base64-encoded encrypted message
        attestationDoc (str): Base64-encoded attestation document
    """
    encryptedMessage: str
    attestationDoc: str