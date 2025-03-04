from pydantic import BaseModel
from typing import List, Optional

class RegisterRequest(BaseModel):
    """
    Request body model for registering an application.
    
    Attributes:
        app_id (int): The app_id to be registered.
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
        encrypted_message (str): Base64-encoded encrypted message
        attestation_doc (str): Base64-encoded attestation document
    """
    encrypted_message: str
    attestation_doc: str
    
    class Config:
        # For backward compatibility
        allow_population_by_field_name = True
        alias_generator = lambda field_name: ''.join(word.capitalize() if i else word for i, word in enumerate(field_name.split('_')))

class DecryptionRequest(BaseModel):
    """
    Request body model for decryption.
    
    Attributes:
        app_id (int): Application id for fetching public key
        encrypted_message (str): Base64-encoded encrypted message
    """
    app_id: int
    encrypted_message: str

class DecryptionResponse(BaseModel):
    """
    Response body model after attempting data decryption.
    
    Attributes:
        plaintext (List[int]): Decrypted plaintext as raw bytes
        attestation_doc (Optional[str]): Base64-encoded attestation document
    """
    plaintext: List[int]
    attestation_doc: Optional[str] = None

class AttestationVerificationRequest(BaseModel):
    """
    Request body model for attestation verification.
    
    Attributes:
        encrypted_message (Optional[str]): Base64-encoded encrypted message
        attestation_doc (str): Base64-encoded attestation document
    """
    encrypted_message: Optional[str] = None
    attestation_doc: str
