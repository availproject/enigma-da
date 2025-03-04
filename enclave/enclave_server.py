import base64
import json
import socket
import hashlib
import cbor2
import urllib.request
import logging
from ecies import encrypt, decrypt
from nsm_interface import NsmInterface, get_attestation_doc
from kms import NitroKms
from vssspy import reconstruct_secret

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class NitroServer:
    def __init__(self, region, credentials=None):
        self.__region = region
        self.nsm = NsmInterface.get_instance()
        self.kms = NitroKms(region, credentials)

    def process_message(self, credential, message_data):
        """
        Process a plaintext message and encrypt it with the provided public key using ECIES
        """
        try:
            # Decrypt the data using KMS with attestation
            decrypted_data = self.kms.call_kms_decrypt(credential, message_data)
        except Exception as ex:
            error_msg = f"KMS decryption call failed: {ex}"
            logger.error(error_msg)
            return {"status": "error", "message": error_msg}

        # Check if the decrypted data includes the expected marker.
        if "PLAINTEXT:" not in decrypted_data:
            error_msg = f"KMS decryption failed. Response: {decrypted_data}"
            logger.error(error_msg)
            return {"status": "error", "message": error_msg}

        try:
            # Parse the decrypted output that should start with "PLAINTEXT: "
            plaintext_base64 = decrypted_data.split("PLAINTEXT: ")[1].strip()
            decoded_json = base64.b64decode(plaintext_base64).decode("utf-8")
            message_data = json.loads(decoded_json)
        except Exception as e:
            error_msg = f"Failed to parse decrypted data: {e}"
            logger.error(error_msg)
            return {"status": "error", "message": error_msg}

        try:
            plaintext = message_data.get('plaintext', '')
            public_key = message_data.get('publicKey')
            
            if not public_key:
                return {'status': 'error', 'message': 'No public key found in the message data'}
            
            # Encrypt the plaintext with the provided public key using ECIES
            try:
                encrypted_message = encrypt(public_key, plaintext.encode())
                
                # Base64 encode the encrypted message
                encrypted_message_b64 = base64.b64encode(encrypted_message).decode('utf-8')
                
                # Calculate hash of encrypted message
                message_hash = hashlib.sha256(encrypted_message).hexdigest()
                
                # Create user data with message hash and app ID
                user_data = {
                    "message_hash": message_hash,
                }
                
                # Get attestation document with user data
                attestation_doc_b64 = self.nsm.get_attestation_doc(
                    user_data=user_data
                )
                
                return {
                    'encryptedMessage': encrypted_message_b64,
                    'attestationDoc': attestation_doc_b64,
                }
            except Exception as e:
                error_msg = f"Error encrypting message: {e}"
                logger.error(error_msg)
                return {'status': 'error', 'message': error_msg}
        except Exception as e:
            error_msg = f"Error processing message: {e}"
            logger.error(error_msg)
            return {'status': 'error', 'message': error_msg}

    def process_encrypted_message(self, credential, encrypted_data, encrypted_data_key):
        """
        Process a message encrypted with a data key
        
        Args:
            credential: AWS credentials with permission to call KMS
            encrypted_data: Base64-encoded data encrypted with the data key
            encrypted_data_key: Base64-encoded data key encrypted by KMS
            
        Returns:
            Dictionary with processing results
        """
        try:
            # First, decrypt the data key using KMS with attestation
            decrypted_key_response = self.kms.call_kms_decrypt(
                credential, 
                encrypted_data_key
            )
            
            # Check if the decrypted data includes the expected marker
            if "PLAINTEXT:" not in decrypted_key_response:
                error_msg = f"KMS decryption of data key failed. Response: {decrypted_key_response}"
                logger.error(error_msg)
                return {"status": "error", "message": error_msg}
            
            # Parse the decrypted output that should start with "PLAINTEXT: "
            plaintext_key_b64 = decrypted_key_response.split("PLAINTEXT: ")[1].strip()
            
            # Decrypt the data using the plaintext key
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            
            # Decode the base64 strings
            plaintext_key = base64.b64decode(plaintext_key_b64)
            encrypted_data_bytes = base64.b64decode(encrypted_data)
            
            # Extract the nonce (first 12 bytes) and ciphertext
            nonce = encrypted_data_bytes[:12]
            ciphertext = encrypted_data_bytes[12:]
            
            # Decrypt the data
            aesgcm = AESGCM(plaintext_key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            
            # Parse the decrypted JSON
            message_data = json.loads(plaintext)
            
            # Process the message as before
            plaintext = message_data.get('plaintext', '')
            public_key = message_data.get('publicKey')
            
            if not public_key:
                return {'status': 'error', 'message': 'No public key found in the message data'}
            
            # Encrypt the plaintext with the provided public key using ECIES
            try:
                encrypted_message = encrypt(public_key, plaintext.encode())
                
                # Base64 encode the encrypted message
                encrypted_message_b64 = base64.b64encode(encrypted_message).decode('utf-8')
                
                # Calculate hash of encrypted message
                message_hash = hashlib.sha256(encrypted_message).hexdigest()
                
                # Create user data with message hash
                user_data = {
                    "message_hash": message_hash,
                }
                
                # Get attestation document with user data
                attestation_doc_b64 = self.nsm.get_attestation_doc(
                    user_data=user_data
                )
                
                return {
                    'encryptedMessage': encrypted_message_b64,
                    'attestationDoc': attestation_doc_b64,
                }
            except Exception as e:
                error_msg = f"Error encrypting message: {e}"
                logger.error(error_msg)
                return {'status': 'error', 'message': error_msg}
        except Exception as e:
            error_msg = f"Error processing encrypted message: {e}"
            logger.error(error_msg)
            return {'status': 'error', 'message': error_msg}

    def fetch_shares(self):
        query = "https://refactored-palm-tree-97w79qxwxr63xjvw-3000.app.github.dev/get-share"
        data = urllib.request.urlopen(query)
        response = json.loads(data.read())
        shares = response.get('shares')
        return shares

    def decrypt_data(self, credential, encrypted_data, encrypted_data_key=None):
        """
        Decrypt the data using KMS and then decrypt again using secret shares
        
        Args:
            credential: AWS credentials with permission to call KMS
            encrypted_data: Base64-encoded or hex-encoded encrypted data
            encrypted_data_key: Optional Base64-encoded data key encrypted by KMS
            
        Returns:
            Dictionary with decrypted data and attestation document
        """
        try:
            # First handle data key decryption if provided
            if encrypted_data_key:
                try:
                    # First, decrypt the data key using KMS with attestation
                    decrypted_key_response = self.kms.call_kms_decrypt(
                        credential, 
                        encrypted_data_key
                    )
                    logger.info("Decrypted data key with KMS")
                    
                    # Check if the decrypted data includes the expected marker
                    if "PLAINTEXT:" not in decrypted_key_response:
                        error_msg = f"KMS decryption of data key failed. Response: {decrypted_key_response}"
                        logger.error(error_msg)
                        return {"status": "error", "message": error_msg}
                    
                    # Parse the decrypted output that should start with "PLAINTEXT: "
                    plaintext_key_b64 = decrypted_key_response.split("PLAINTEXT: ")[1].strip()
                    
                    # Decrypt the data using the plaintext key
                    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                    
                    # Decode the base64 strings
                    plaintext_key = base64.b64decode(plaintext_key_b64)
                    encrypted_data_bytes = base64.b64decode(encrypted_data)
                    
                    # Extract the nonce (first 12 bytes) and ciphertext
                    nonce = encrypted_data_bytes[:12]
                    ciphertext = encrypted_data_bytes[12:]
                    
                    # Decrypt the data
                    aesgcm = AESGCM(plaintext_key)
                    first_decryption = aesgcm.decrypt(nonce, ciphertext, None)
                    
                    # Now we have the first decryption result, proceed to second decryption
                    logger.info("First decryption completed, proceeding to second decryption with shares...")
                    
                except Exception as e:
                    error_msg = f"Error in first decryption with data key: {e}"
                    logger.error(error_msg)
                    return {"status": "error", "message": error_msg}
            else:
                # Process direct KMS decryption
                # Check the type of encrypted_data and convert appropriately
                if isinstance(encrypted_data, str):
                    try:
                        # Try to convert from hex
                        encrypted_data_bytes = bytes.fromhex(encrypted_data)
                    except ValueError:
                        # If not hex, try to decode from base64
                        try:
                            encrypted_data_bytes = base64.b64decode(encrypted_data)
                        except Exception:
                            # If not base64 either, encode as UTF-8
                            encrypted_data_bytes = encrypted_data.encode('utf-8')
                elif isinstance(encrypted_data, bytes):
                    # Already bytes
                    encrypted_data_bytes = encrypted_data
                else:
                    # Try to convert to bytes
                    encrypted_data_bytes = bytes(encrypted_data)
                
                logger.info(f"Encrypted data type: {type(encrypted_data_bytes)}, length: {len(encrypted_data_bytes)}")
                
                # Convert encrypted data to base64 for KMS
                encrypted_data_b64 = base64.b64encode(encrypted_data_bytes).decode('utf-8')
                
                try:
                    # Use the KMS decrypt operation with attestation
                    decrypted_data_response = self.kms.call_kms_decrypt(
                        credential, 
                        encrypted_data_b64
                    )
                    logger.info("Decrypted with KMS")
                    
                    # Check if the decrypted data includes the expected marker
                    if "PLAINTEXT:" not in decrypted_data_response:
                        error_msg = f"KMS decryption failed. Response: {decrypted_data_response}"
                        logger.error(error_msg)
                        return {"status": "error", "message": error_msg}
                    
                    # Parse the decrypted output that should start with "PLAINTEXT: "
                    plaintext_b64 = decrypted_data_response.split("PLAINTEXT: ")[1].strip()
                    first_decryption = base64.b64decode(plaintext_b64)
                    
                    # Now we have the first decryption result, proceed to second decryption
                    logger.info("First decryption completed, proceeding to second decryption with shares...")
                    
                except Exception as e:
                    error_msg = f"Error in first decryption with KMS: {e}"
                    logger.error(error_msg)
                    return {"status": "error", "message": error_msg}
            
            # After getting first_decryption, parse the JSON to extract the encrypted_data value
            if isinstance(first_decryption, bytes):
                first_decryption_str = first_decryption.decode('utf-8')
            else:
                first_decryption_str = first_decryption

            # Parse the JSON string to extract just the encrypted_data value
            try:
                parsed_data = json.loads(first_decryption_str)
                encrypted_data_value = parsed_data.get('encrypted_data')
                
                if not encrypted_data_value:
                    error_msg = "No encrypted_data found in the decrypted JSON"
                    logger.error(error_msg)
                    return {"status": "error", "message": error_msg}
                
                logger.info(f"Extracted encrypted data value for second decryption")
                
                # Now fetch shares and decrypt the actual encrypted data
                logger.info("Fetching secret shares for second decryption...")
                secret_shares = self.fetch_shares()
                logger.info(f"Retrieved {len(secret_shares)} shares")
                secret = reconstruct_secret(secret_shares)
                logger.info(f"Secret reconstructed, length: {len(secret)}")
                
                # Make sure secret is bytes
                if not isinstance(secret, bytes):
                    secret_bytes = bytes(secret)
                else:
                    secret_bytes = secret
                
                # Convert the extracted encrypted data string to bytes
                encrypted_data_bytes = base64.b64decode(encrypted_data_value)
                
                # Now decrypt using the private key from secret shares
                decrypted_data = decrypt(secret_bytes, encrypted_data_bytes)
                logger.info(f"Second decryption completed, length: {len(decrypted_data)}")
                
                # Calculate hash of original encrypted data for attestation
                data_hash = hashlib.sha256(encrypted_data_bytes).hexdigest()
                
                # Create user data with data hash
                user_data = {
                    "data_hash": data_hash,
                }
                
                # Get attestation document with user data
                attestation_doc_b64 = self.nsm.get_attestation_doc(
                    user_data=user_data
                )
                
                return {
                    'decryptedData': base64.b64encode(decrypted_data).decode('utf-8'),
                    'attestationDoc': attestation_doc_b64,
                }
                
            except json.JSONDecodeError as e:
                error_msg = f"Error parsing JSON from first decryption: {e}"
                logger.error(error_msg)
                return {"status": "error", "message": error_msg}
            
        except Exception as e:
            error_msg = f"Error in decryption process: {e}"
            logger.error(error_msg)
            return {"status": "error", "message": error_msg}

def main():
    logger.info("Nitro server started...")

    s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    cid = socket.VMADDR_CID_ANY
    port = 5000
    s.bind((cid, port))
    s.listen()

    region = 'us-east-1'
    server = None

    while True:
        c, addr = s.accept()

        # Get payload from parent instance
        payload = c.recv(4096)
        payload_json = json.loads(payload.decode())

        api_call = payload_json["apiCall"]
        credential = payload_json["credential"]
        
        # Initialize server with credentials if not already done
        if server is None:
            server = NitroServer(region, credential)

        # Process the API call
        response = None
        
        if api_call == "encrypt":
            message_data = payload_json.get("messageData")
            response = server.process_message(credential, message_data)
        elif api_call == "encrypt_with_datakey":
            encrypted_data = payload_json.get("encryptedData")
            encrypted_data_key = payload_json.get("encryptedDataKey")
            response = server.process_encrypted_message(credential, encrypted_data, encrypted_data_key)
        elif api_call == "decrypt":
            encrypted_data = payload_json.get("encryptedData")
            encrypted_data_key = payload_json.get("encryptedDataKey")
            response = server.decrypt_data(credential, encrypted_data, encrypted_data_key)
        else:
            response = {"status": "error", "message": f"Unknown API call: {api_call}"}
        
        # Send the response back to the parent instance
        c.send(json.dumps(response).encode())
        c.close()

if __name__ == "__main__":
    main()