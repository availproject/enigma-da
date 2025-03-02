import boto3
import json
import datetime
import base64
from host.utils import get_iam_token, get_ephemeral_credentials_with_datakey
import config


def get_standard_kms_client():
    """
    Get a standard KMS client using the instance's IAM role credentials.
    
    Returns:
        tuple: (credential, boto3.client) A tuple containing the credentials and KMS client
    """
    credential = get_iam_token()
    return (credential, boto3.client(
        'kms',
        region_name=config.Region,
        aws_access_key_id=credential['aws_access_key_id'],
        aws_secret_access_key=credential['aws_secret_access_key'],
        aws_session_token=credential['aws_session_token']
    ))


def get_ephemeral_kms_client_with_datakey(plaintext_data):
    """
    Get ephemeral credentials with PCR attestation conditions and encrypt data with a data key.
    
    Args:
        plaintext_data: Data to encrypt
        
    Returns:
        dict: Dictionary containing encrypted data, encrypted data key, and credentials
    """
    pcr_values = {
        "0": "c3c9d35df78abed74942f7f852237359d424cefd2bbba051b8de527d9543c769111050da4f0175aaf82eae45f18cc2ac",
        "1": "0343b056cd8485ca7890ddd833476d78460aed2aa161548e4e26bedf321726696257d623e8805f3f605946b3d8b0c6aa",
        "2": "0472b1ac836e369cf1ccee9fb845cf0e466480c266692447a1498f4d3c0a93b1ce299da20106a212c6f585ea35025132"
    }
    
    # Use the data key pattern to encrypt the data
    result = get_ephemeral_credentials_with_datakey(pcr_values, plaintext_data, config.KeyId)
    
    return result
