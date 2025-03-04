import subprocess
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class NitroKms:
    def __init__(self, region=None, credentials=None):
        self.region = region or 'us-east-1'
        self.credentials = credentials
    
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
        
        logger.debug("Executing KMS decrypt command")
        
        try:
            proc = subprocess.Popen(
                subprocess_args,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout, stderr = proc.communicate()
            
            if proc.returncode != 0:
                logger.error(f"KMS decrypt failed with return code {proc.returncode}")
                logger.error(f"STDERR: {stderr.decode()}")
                return f"ERROR: {stderr.decode()}"
            
            # returns b64 encoded plaintext
            plaintext = stdout.decode()
            return plaintext
        except Exception as e:
            logger.error(f"Exception in KMS decrypt: {str(e)}")
            return f"ERROR: {str(e)}"