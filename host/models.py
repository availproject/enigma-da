from pydantic import BaseModel
from typing import List

# Pydantic models for requests and responses
class RegisterRequest(BaseModel):
    app_id: int
    public_key: List[int]

class RegisterResponse(BaseModel):
    

class EncryptionRequest(BaseModel):