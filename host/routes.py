from fastapi import APIRouter, HTTPException, File, UploadFile, Form
from host.models import RegisterRequest, RegisterResponse, EncryptionRequest, EncryptionResponse, DecryptionRequest, DecryptionResponse
from host.db import register_app, get_public_key
from host.vsock import VsockStream
from logger import logger
import config
import base64
import json
import os
from datetime import datetime
from host.kms_client import get_standard_kms_client, get_ephemeral_kms_client_with_datakey
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Dict, Any, Optional, List
from host.attestation_verifier import verify_attestation_document, extract_pcrs_from_policy
import hashlib

router = APIRouter()

# Add a new model for the attestation verification request
class AttestationVerificationRequest(BaseModel):
    encryptedMessage: str
    attestationDoc: str

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
        RegisterResponse: A response containing app_id if registration is successful.
    """
    app_id = register_app(request)

    if app_id is None:
        raise HTTPException(status_code=400, detail="App already registered!")

    return RegisterResponse(
        app_id=app_id
    )
    

@router.post("/encrypt", response_model=None)
async def encrypt(request: EncryptionRequest):
    """
    Encrypts plaintext using the application's public key.

    Args:
        request (EncryptionRequest): Contains plaintext to be encrypted and app_id

    Returns:
        EncryptionResponse or ErrorResponse: Response containing encrypted data or error details
    """
    try:
        app_public_key = get_public_key(request.app_id)
        print(f"App public key: {app_public_key}")

        # Prepare the message to encrypt
        message_to_encrypt = json.dumps({
            'plaintext': bytes(request.plaintext).decode('utf-8', errors='replace'),
            'publicKey': app_public_key
        })
        
        # Use the data key pattern to encrypt the message
        result = get_ephemeral_kms_client_with_datakey(message_to_encrypt)
        
        print(f"encrypted data key: {result['encrypted_data_key']}")
        
        # Prepare the payload for the enclave
        payload = {
            'apiCall': "encrypt_with_datakey",
            'credential': result['aws_credentials'],
            'encryptedData': result['encrypted_data'],
            'encryptedDataKey': result['encrypted_data_key']
        }
        
        # Connect to the enclave using VsockStream
        enclave_client = VsockStream()
        endpoint = (config.EnclaveCID, config.EnclavePort)
        enclave_client.connect(endpoint)
        
        # Send the payload and get the response
        response_str = enclave_client.execute("processEncryptedMessage", payload)
        
        # Parse the response
        response = json.loads(response_str)
        
        # Check if the response indicates an error
        if response.get("status") == "error":
            # Return a proper error response with 400 status code
            error_message = response.get("message", "Unknown error")
            
            # Check for specific error types
            if "KMS decrypt" in error_message and "400" in error_message:
                return JSONResponse(
                    status_code=400,
                    content={"error": "Error decrypting in KMS, PCR check failed"}
                )
            else:
                return JSONResponse(
                    status_code=400,
                    content={"error": error_message}
                )
        
        # If successful, return the response as is
        return response
        
    except Exception as e:
        # Handle any other exceptions
        return JSONResponse(
            status_code=500,
            content={"error": f"Internal server error: {str(e)}"}
        )

@router.post("/verify-attestation")
async def verify_attestation(request: AttestationVerificationRequest):
    """
    Verify an attestation document from a Nitro Enclave
    
    Args:
        request: JSON containing the attestation data
        
    Returns:
        Dict: Verification results
    """
    try:
        # Extract the required fields
        encrypted_message = request.encryptedMessage
        attestation_doc = request.attestationDoc
        
        if not encrypted_message or not attestation_doc:
            return JSONResponse(
                status_code=400,
                content={"verification_status": "error", "error": "Missing required fields"}
            )
        
        # Extract expected PCR values from the key policy
        expected_pcrs = extract_pcrs_from_policy('key_policy.json')
        
        # Verify the attestation document
        verification_result = verify_attestation_document(
            attestation_doc,
            expected_pcrs
        )
        
        # Add the encrypted message hash to the response
        verification_result['encrypted_message_hash'] = hashlib.sha256(
            encrypted_message.encode()
        ).hexdigest()
        
        return verification_result
    
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"verification_status": "error", "error": f"Attestation verification failed: {str(e)}"}
        )

@router.post("/decrypt", response_model=DecryptionResponse)
async def decrypt(request: DecryptionRequest):
    """
    Decrypts data that was previously encrypted by the enclave.
    
    Args:
        request (DecryptionRequest): Contains encryptedMessage and app_id
        
    Returns:
        DecryptionResponse: Response containing decrypted plaintext and attestation document
    """
    try:
        app_public_key = get_public_key(request.app_id)
        if app_public_key is None:
            raise HTTPException(status_code=404, detail="App not found!")

        # Connect to the enclave
        enclave_client = VsockStream()
        endpoint = (config.EnclaveCID, config.EnclavePort)
        enclave_client.connect(endpoint)

        # Use the data key pattern to encrypt the request data
        message_to_encrypt = json.dumps({
            'encrypted_data': request.encryptedMessage,
        })
        
        # Encrypt the request with a data key
        result = get_ephemeral_kms_client_with_datakey(message_to_encrypt)
        
        # Send the encrypted data to the enclave for decryption
        payload = {
            'apiCall': "decrypt",
            'credential': result['aws_credentials'],
            'encryptedData': result['encrypted_data'],
            'encryptedDataKey': result['encrypted_data_key'],
        }
        
        # Send the payload and get the response
        response_str = enclave_client.execute("decrypt", payload)
        
        # Parse the response as JSON
        result = json.loads(response_str)
        
        # Check if there was an error
        if 'status' in result and result['status'] == 'error':
            raise Exception(result['message'])
        
        # Extract the decrypted data and attestation document
        decrypted_data_b64 = result.get('decryptedData')
        attestation_doc = result.get('attestationDoc')
        
        if not decrypted_data_b64:
            raise Exception("No decrypted data returned from enclave")
        
        # Decode the base64 decrypted data
        decrypted_data = base64.b64decode(decrypted_data_b64)
        
        # Verify the attestation document if present
        if attestation_doc:
            # Calculate hash of the original encrypted message for verification
            if isinstance(request.encryptedMessage, str):
                try:
                    # Try to decode from base64
                    encrypted_bytes = base64.b64decode(request.encryptedMessage)
                except:
                    # If not base64, encode as UTF-8
                    encrypted_bytes = request.encryptedMessage.encode('utf-8')
            else:
                encrypted_bytes = bytes(request.encryptedMessage)
                
            message_hash = hashlib.sha256(encrypted_bytes).hexdigest()
            
        
        # Convert the decrypted data to a list of integers for the response
        plaintext = list(decrypted_data)
        
        return DecryptionResponse(
            plaintext=plaintext,
            attestationDoc=attestation_doc
        )
        
    except Exception as e:
        # Handle any exceptions
        logger.error(f"Error in decrypt endpoint: {str(e)}")
        return JSONResponse(
            status_code=500,
            content={"error": f"Internal server error: {str(e)}"}
        )

# Register the routes with FastAPI
def register_routes(app):
    app.include_router(router)
