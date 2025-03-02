from fastapi import APIRouter, HTTPException
from host.models import RegisterRequest, RegisterResponse, EncryptionRequest, EncryptionResponse, DecryptionRequest, DecryptionResponse
from host.db import register_app, get_public_key
from host.vsock import VsockStream
from logger import logger
import config

router = APIRouter()


@router.get("/")
async def home():
    return "Welcome to Encifher!"


@router.post("/register", response_model=RegisterResponse)
async def register(request: RegisterRequest):
    """
    Registers a new application by receiving a public key and a unique app_id.
    
    Args:
        request (RegisterRequest): The registration request containing the public key.

    Returns:
        RegisterResponse: A response containing app_id if registration was successfull.
    """
    app_id = register_app(request)

    if app_id is None:
        raise HTTPException(status_code=400, detail="App already registered!")

    return RegisterResponse(
        app_id=app_id
    )
    

@router.post("/encrypt", response_model=EncryptionResponse)
async def encrypt(request: EncryptionRequest):
    """
    Encrypts plaintext using the application's public key.

    Args:
        request (EncryptionRequest): Contains plaintext to be encrypted and app_id

    Returns:
        EncryptionResponse: Response containg encrypted data
    """
    app_public_key = get_public_key(request.app_id)
    if app_public_key is None: 
        raise HTTPException(status_code=404, detail="App not found!")
    
    enclave_client = VsockStream()
    endpoint = (config.EnclaveCID, config.EnclavePort)
    enclave_client.connect(endpoint)

    encrypted_data = enclave_client.execute("encrypt", {
        "public_key": app_public_key,
        "plaintext": request.plaintext
    })
    encrypted_data_bytes = list(bytes.fromhex(encrypted_data))

    return EncryptionResponse(
        encrypted_data=encrypted_data_bytes
    )

@router.post("/decrypt", response_model=DecryptionResponse)
async def decrypt(request: DecryptionRequest):
    """
    """
    app_public_key = get_public_key(request.app_id)
    if app_public_key is None:
        raise HTTPException(status_code=404, detail="App not found!")

    enclave_client = VsockStream()
    endpoint = (config.EnclaveCID, config.EnclavePort)
    enclave_client.connect(endpoint)

    decrypted_data = enclave_client.execute("decrypt", {
        "encrypted_data": request.encrypted_data
    })
    plaintext = list(bytes.fromhex(decrypted_data))

    return DecryptionResponse(
        plaintext=plaintext
    )


# Register the routes with FastAPI
def register_routes(app):
    app.include_router(router)
