import requests
import boto3
import json
import base64
import datetime

def get_iam_token():
    """
    Get the AWS credential from EC2 instance metadata or use boto3 session credentials
    
    Returns:
    Dictionary containing AWS credentials
    """
    try:
        # Try IMDSv2 first (token-based approach)
        token_headers = {'X-aws-ec2-metadata-token-ttl-seconds': '21600'}
        token_url = "http://169.254.169.254/latest/api/token"
        
        try:
            token_response = requests.put(token_url, headers=token_headers, timeout=2)
            if token_response.status_code == 200:
                token = token_response.text
                headers = {'X-aws-ec2-metadata-token': token}
                
                # Get the role name
                role_url = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
                r = requests.get(role_url, headers=headers, timeout=2)
                instance_profile_name = r.text.strip()
                
                if not instance_profile_name:
                    print("No IAM role found attached to this EC2 instance (IMDSv2)")
                    return get_fallback_credentials()
                
                print(f"Found IAM role via IMDSv2: {instance_profile_name}")
                
                # Get the credentials
                cred_url = f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{instance_profile_name}"
                r = requests.get(cred_url, headers=headers, timeout=2)
                response = r.json()
                
                credential = {
                    'aws_access_key_id': response['AccessKeyId'],
                    'aws_secret_access_key': response['SecretAccessKey'],
                    'aws_session_token': response['Token']
                }
                print("Successfully retrieved credentials from instance metadata service")
                return credential
        except Exception as e:
            print(f"IMDSv2 attempt failed: {e}, falling back to IMDSv1")
            
        # Fall back to IMDSv1
        r = requests.get(
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            timeout=2)
        
        instance_profile_name = r.text.strip()
        if not instance_profile_name:
            print("No IAM role found attached to this EC2 instance (IMDSv1)")
            return get_fallback_credentials()
        
        print(f"Found IAM role via IMDSv1: {instance_profile_name}")
        
        # Get the credentials for the role
        r = requests.get(
            f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{instance_profile_name}",
            timeout=2)
        
        # Debug the response
        print(f"Response status: {r.status_code}")
        print(f"Response content: {r.text[:100]}...")  # Print first 100 chars
        
        try:
            response = r.json()
            
            credential = {
                'aws_access_key_id': response['AccessKeyId'],
                'aws_secret_access_key': response['SecretAccessKey'],
                'aws_session_token': response['Token']
            }
            print("Successfully retrieved credentials from instance metadata service")
            return credential
        except json.JSONDecodeError:
            print("Failed to parse JSON from metadata service")
            return get_fallback_credentials()
    except Exception as e:
        print(f"Error accessing EC2 metadata service: {e}")
        return get_fallback_credentials()

def get_fallback_credentials():
    """
    Use boto3 session credentials as fallback
    
    Parameters:
    region - AWS region to use for boto3 session (optional)
    
    Returns:
    Dictionary containing AWS credentials
    """
    region = "us-east-1"
    print("Using fallback credentials from boto3 session")
    session = boto3.Session(region_name=region)
    credentials = session.get_credentials()
    if credentials is None:
        raise Exception("No AWS credentials found. Please configure AWS credentials.")
    
    frozen_credentials = credentials.get_frozen_credentials()
    credential = {
        'aws_access_key_id': frozen_credentials.access_key,
        'aws_secret_access_key': frozen_credentials.secret_key,
        'aws_session_token': frozen_credentials.token if frozen_credentials.token else ""
    }
    print("Using fallback credentials")
    return credential

def get_ephemeral_credentials_with_datakey(pcr_values, plaintext_data, kms_key_id):
    """
    Encrypt data with a data key for secure processing in an enclave.
    """
    # Get base credentials
    base_credentials = get_iam_token()
    
    # Create a KMS client
    kms_client = boto3.client(
        'kms',
        aws_access_key_id=base_credentials['aws_access_key_id'],
        aws_secret_access_key=base_credentials['aws_secret_access_key'],
        aws_session_token=base_credentials['aws_session_token']
    )
    
    # Generate a data key without encryption context
    response = kms_client.generate_data_key(
        KeyId=kms_key_id,
        KeySpec='AES_256'
    )
    
    # Get the plaintext data key and encrypted data key
    plaintext_data_key = response['Plaintext']
    encrypted_data_key = response['CiphertextBlob']
    
    # Convert to base64 strings for easier handling
    plaintext_data_key_b64 = base64.b64encode(plaintext_data_key).decode('utf-8')
    encrypted_data_key_b64 = base64.b64encode(encrypted_data_key).decode('utf-8')
    
    # Create an AES cipher for encryption
    class AESCipher:
        def __init__(self, key):
            self.key = base64.b64decode(key) if isinstance(key, str) else key
            
        def encrypt(self, raw):
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            import os
            
            # Generate a random nonce
            nonce = os.urandom(12)
            
            # Create an AES-GCM cipher with the key
            aesgcm = AESGCM(self.key)
            
            # Encrypt the data
            if isinstance(raw, str):
                raw = raw.encode('utf-8')
                
            ciphertext = aesgcm.encrypt(nonce, raw, None)
            
            # Combine nonce and ciphertext and return as base64
            encrypted_data = nonce + ciphertext
            return base64.b64encode(encrypted_data)
    
    # Encrypt the data with the plaintext data key
    aes_cipher = AESCipher(plaintext_data_key)
    encrypted_data = aes_cipher.encrypt(plaintext_data)
    
    # Convert to string if it's bytes
    if isinstance(encrypted_data, bytes):
        encrypted_data = encrypted_data.decode('utf-8')
    
    # Use the instance credentials
    aws_credentials = {
        'aws_access_key_id': base_credentials['aws_access_key_id'],
        'aws_secret_access_key': base_credentials['aws_secret_access_key'],
        'aws_session_token': base_credentials['aws_session_token']
    }
    
    # Return the encrypted data, encrypted data key, and credentials
    return {
        'encrypted_data': encrypted_data,
        'encrypted_data_key': encrypted_data_key_b64,
        'aws_credentials': aws_credentials
    }

def setup_credential_with_pcr_access(secret_name, pcr_values, kms_key_id):
    """
    Set up a secret in Secrets Manager with PCR-based access control
    
    Args:
        secret_name: Name of the secret
        pcr_values: Dictionary of PCR values to include in the condition
        kms_key_id: KMS key ID to use for encryption
    """
    # Get base credentials
    base_credentials = get_iam_token()
    
    # Create KMS client
    kms_client = boto3.client(
        'kms',
        aws_access_key_id=base_credentials['aws_access_key_id'],
        aws_secret_access_key=base_credentials['aws_secret_access_key'],
        aws_session_token=base_credentials['aws_session_token']
    )
    
    # Update KMS key policy to include PCR conditions
    policy = kms_client.get_key_policy(
        KeyId=kms_key_id,
        PolicyName='default'
    )
    
    policy_json = json.loads(policy['Policy'])
    
    # Add a statement for PCR-based access
    pcr_statement = {
        "Sid": "Allow decryption only from specific Nitro Enclaves",
        "Effect": "Allow",
        "Principal": {"AWS": "*"},
        "Action": ["kms:Decrypt"],
        "Resource": "*",
        "Condition": {
            "StringEqualsIgnoreCase": {}
        }
    }
    
    # Add PCR values to the condition
    for pcr_id, pcr_value in pcr_values.items():
        pcr_statement["Condition"]["StringEqualsIgnoreCase"][f"kms:RecipientAttestation:PCR{pcr_id}"] = pcr_value
    
    policy_json["Statement"].append(pcr_statement)
    
    # Update the key policy
    kms_client.put_key_policy(
        KeyId=kms_key_id,
        PolicyName='default',
        Policy=json.dumps(policy_json)
    )
    
    print(f"Updated KMS key policy with PCR conditions for {kms_key_id}")

def get_role_credentials(role_arn):
    """
    Assume a specific IAM role and return temporary credentials
    
    Args:
        role_arn: The ARN of the role to assume
        
    Returns:
        Dictionary containing temporary AWS credentials
    """
    try:
        # First get the instance's credentials
        base_credentials = get_iam_token()
        
        # Create an STS client using the instance credentials
        sts_client = boto3.client(
            'sts',
            aws_access_key_id=base_credentials['aws_access_key_id'],
            aws_secret_access_key=base_credentials['aws_secret_access_key'],
            aws_session_token=base_credentials['aws_session_token']
        )
        
        # Assume the specified role
        response = sts_client.assume_role(
            RoleArn=role_arn,
            RoleSessionName='EnclaveSession'
        )
        
        # Extract and return the temporary credentials
        credentials = response['Credentials']
        return {
            'aws_access_key_id': credentials['AccessKeyId'],
            'aws_secret_access_key': credentials['SecretAccessKey'],
            'aws_session_token': credentials['SessionToken']
        }
    except Exception as e:
        print(f"Error assuming role {role_arn}: {e}")
        # Fall back to instance credentials
        return get_fallback_credentials()
