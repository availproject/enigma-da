import subprocess
import os
import json
import boto3
import requests
from NsmInterface import NsmInterface

class nitroKms:
    def __init__(self, region=None, credentials=None):
        self.nsm = NsmInterface.get_instance()
        self.region = region or os.getenv("REGION", "us-east-1")
        
        # If credentials are provided, use them directly
        if credentials:
            self.kms_client = boto3.client(
                'kms',
                region_name=self.region,
                aws_access_key_id=credentials['aws_access_key_id'],
                aws_secret_access_key=credentials['aws_secret_access_key'],
                aws_session_token=credentials.get('aws_session_token')
            )
            print("Using provided credentials for KMS client")
        else:
            # Try to get credentials from the parent instance
            try:
                self.kms_client = boto3.client('kms', region_name=self.region)
                print("Using default credential provider chain")
            except Exception as e:
                print(f"Error setting up KMS client: {e}")
                # Fall back to default credential provider chain
                self.kms_client = boto3.client('kms', region_name=self.region)
    
    
    def extract_pcrs_from_policy(self, policy_json):
        """Extract PCR values from a KMS key policy"""
        expected_pcrs = {}
        for statement in policy_json.get('Statement', []):
            if statement.get('Sid') == 'Allow decryption only from Nitro Enclaves':
                condition = statement.get('Condition', {}).get('StringEqualsIgnoreCase', {})
                for key, value in condition.items():
                    if key.startswith('kms:RecipientAttestation:PCR'):
                        pcr_id = key.split(':')[-1]
                        expected_pcrs[pcr_id] = value
        return expected_pcrs
    
    def get_key_policy(self, key_id):
        """Get the key policy for a KMS key"""
        try:
            print(f"Attempting to get key policy for key ID: {key_id}")
            response = self.kms_client.get_key_policy(
                KeyId=key_id,
                PolicyName='default'
            )
            return json.loads(response['Policy'])
        except Exception as e:
            print(f"Error getting key policy: {e}")
            # Check if this is a permissions issue
            if "AccessDeniedException" in str(e):
                print("This appears to be a permissions issue. Make sure the IAM role has kms:GetKeyPolicy permission.")
            # Check if this is a key not found issue
            elif "NotFoundException" in str(e):
                print(f"Key ID {key_id} not found. Make sure the key exists and is in region {self.region}.")
            return None
    
    def call_kms_generate_datakey(self, credential, keyId):
        """Generate a data key using KMS"""
        aws_access_key_id = credential['aws_access_key_id']
        aws_secret_access_key = credential['aws_secret_access_key']
        aws_session_token = credential['aws_session_token']

        subprocess_args = [
            "/app/kmstool_enclave_cli",
            "genkey",
            "--region", self.region,
            "--proxy-port", "8000",
            "--aws-access-key-id", aws_access_key_id,
            "--aws-secret-access-key", aws_secret_access_key,
            "--aws-session-token", aws_session_token,
            "--key-id", keyId,
            "--key-spec", "AES-256",
        ]

        print("subprocess args: {}".format(subprocess_args))

        proc = subprocess.Popen(
            subprocess_args,
            stdout=subprocess.PIPE
        )
        
        datakeyText = proc.communicate()[0].decode()
        return datakeyText
    
    def call_kms_decrypt(self, credential, ciphertext, key_id=None):
        """
        Decrypt data using KMS with attestation
        
        Args:
            credential: AWS credentials
            ciphertext: Base64-encoded encrypted data
            key_id: Optional KMS key ID for logging
            
        Returns:
            Decrypted data
        """
        aws_access_key_id = credential['aws_access_key_id']
        aws_secret_access_key = credential['aws_secret_access_key']
        aws_session_token = credential['aws_session_token']
        
        # Note: kmstool_enclave_cli automatically generates and uses an attestation document
        # We don't need to provide one explicitly
        subprocess_args = [
            "/app/kmstool_enclave_cli",
            "decrypt",
            "--region", self.region,
            "--proxy-port", "8000",
            "--aws-access-key-id", aws_access_key_id,
            "--aws-secret-access-key", aws_secret_access_key,
            "--aws-session-token", aws_session_token,
            "--ciphertext", ciphertext,
        ]
        
        print("subprocess args: {}".format(subprocess_args))
        
        try:
            proc = subprocess.Popen(
                subprocess_args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout, stderr = proc.communicate()
            
            if proc.returncode != 0:
                print(f"KMS decrypt failed with return code {proc.returncode}")
                print(f"STDERR: {stderr.decode()}")
                return f"ERROR: {stderr.decode()}"
            
            # returns b64 encoded plaintext
            plaintext = stdout.decode()
            return plaintext
        except Exception as e:
            print(f"Exception in KMS decrypt: {str(e)}")
            return f"ERROR: {str(e)}"

    def get_kms_public_key(self, key_id):
        """
        Get the public key for a KMS key if it's asymmetric
        
        Args:
            key_id: KMS key ID
            
        Returns:
            Public key in DER format, or None if not found or if key is symmetric
        """
        try:
            # Check if the key is asymmetric
            key_info = self.kms_client.describe_key(KeyId=key_id)
            if key_info['KeyMetadata'].get('KeyUsage') in ['SIGN_VERIFY', 'KEY_AGREEMENT']:
                # Get the public key for the KMS key
                response = self.kms_client.get_public_key(KeyId=key_id)
                # Return the public key in DER format
                return response['PublicKey']
            else:
                print(f"Key {key_id} is symmetric and doesn't have a public key")
                return None
        except Exception as e:
            print(f"Error getting KMS public key: {e}")
            return None
