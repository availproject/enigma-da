from fastapi import APIRouter, HTTPException, File, UploadFile, Form
from host.models import RegisterRequest, RegisterResponse, EncryptionRequest, EncryptionResponse
from host.db import register_app, get_public_key
from host.vsock import VsockStream
from host.utils import get_iam_token
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
from attestation_verifier import verify_attestation_document, extract_pcrs_from_policy
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
    Registers a new application by receiving a public key and assigning a unique app_id.
    
    Args:
        request (RegisterRequest): The registration request containing the public key.

    Returns:
        RegisterResponse: A response containing app_id.
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
        # if app_public_key is None: 
        #     raise HTTPException(status_code=404, detail="App not found!")
        # app_public_key = "0201d7ab5ac02f54e001f70625c06c9b831c10fcdd1c37c9b7f399ebeb30e38c49"
        # app_public_key = "0x046152e716725ccc10b10cc0d5c106e219906e6e65d6a4576e7ce01926c371d5eb8d149d17bdbc9327c3c52a45429ed30a5c3c8612a5c333e1907b9aa60546c00f"
        
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
            'apiCall': "processEncryptedMessage",
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
        request (AttestationVerificationRequest): Contains the encrypted message and attestation document
        
    Returns:
        Dict: Verification results
    """
    try:
        # Extract expected PCR values from the key policy
        expected_pcrs = extract_pcrs_from_policy('key_policy.json')
        
        # Verify the attestation document
        verification_result = verify_attestation_document(
            request.attestationDoc,
            expected_pcrs
        )
        
        # Add the encrypted message hash to the response
        # This could be used to verify that the message was processed by the enclave
        verification_result['encrypted_message_hash'] = hashlib.sha256(
            request.encryptedMessage.encode()
        ).hexdigest()
        
        return verification_result
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Attestation verification failed: {str(e)}")

@router.post("/verify-attestation-file")
async def verify_attestation_file(file: UploadFile = File(...)):
    """
    Verify an attestation document from a Nitro Enclave using a file upload
    
    Args:
        file: JSON file containing the attestation data
        
    Returns:
        Dict: Verification results
    """
    try:
        # Read the uploaded file
        contents = await file.read()
        
        # Parse the JSON content
        try:
            request_data = json.loads(contents)
        except json.JSONDecodeError:
            return JSONResponse(
                status_code=400,
                content={"verification_status": "error", "error": "Invalid JSON file"}
            )
        
        # Extract the required fields
        encrypted_message = request_data.get("encryptedMessage")
        attestation_doc = request_data.get("attestationDoc")
        
        if not encrypted_message or not attestation_doc:
            return JSONResponse(
                status_code=400,
                content={"verification_status": "error", "error": "Missing required fields in JSON file"}
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

# Register the routes with FastAPI
def register_routes(app):
    app.include_router(router)
