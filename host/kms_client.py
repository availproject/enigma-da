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
    # Use the data key pattern to encrypt the data
    result = get_ephemeral_credentials_with_datakey(plaintext_data, config.KeyId)
    
    return result
