import base64
import json
import socket
import hashlib
import cbor2

from ecies import encrypt
from NsmInterface import NsmInterface, get_attestation_doc
from kms import nitroKms

class nitroServer:

    def __init__(self, region, credentials=None):
        self.__region = region
        self.nsm = NsmInterface.get_instance()
        self.kms = nitroKms(region, credentials)

    def process_message(self, credential, message_data):
        """
        Process a plaintext message and encrypt it with the provided public key using ECIES
        """
        try:
            # Decrypt the data using KMS with attestation
            # Note: kmstool_enclave_cli automatically generates and uses an attestation document
            decrypted_data = self.kms.call_kms_decrypt(credential, message_data)
        except Exception as ex:
            error_msg = f"KMS decryption call failed: {ex}"
            print(error_msg)
            return {"status": "error", "message": error_msg}

        # Check if the decrypted data includes the expected marker.
        if "PLAINTEXT:" not in decrypted_data:
            error_msg = f"KMS decryption failed. Response: {decrypted_data}"
            print(error_msg)
            return {"status": "error", "message": error_msg}

        try:
            # Parse the decrypted output that should start with "PLAINTEXT: "
            plaintext_base64 = decrypted_data.split("PLAINTEXT: ")[1].strip()
            decoded_json = base64.b64decode(plaintext_base64).decode("utf-8")
            message_data = json.loads(decoded_json)
        except Exception as e:
            error_msg = f"Failed to parse decrypted data: {e}"
            print(error_msg)
            return {"status": "error", "message": error_msg}

        try:
            plaintext = message_data.get('plaintext', '')
            public_key = message_data.get('publicKey')
            
            # Fetch and print all PCR values
            print("Fetching PCR values from NSM...")
            try:
                # Get attestation document with empty user data to extract PCRs
                attestation_doc_b64 = self.nsm.get_attestation_doc()
                attestation_doc = base64.b64decode(attestation_doc_b64)
                
                # Decode CBOR attestation document
                data = cbor2.loads(attestation_doc)
                
                # Load and decode document payload
                doc = data[2]
                doc_obj = cbor2.loads(doc)
                
                # Get PCRs from attestation document
                pcrs = doc_obj.get('pcrs', {})
                
                print("Current PCR values:")
                for pcr_id, pcr_value in pcrs.items():
                    if pcr_value is not None:
                        print(f"PCR{pcr_id}: {pcr_value.hex()}")
                    else:
                        print(f"PCR{pcr_id}: None")
            except Exception as e:
                print(f"Error fetching PCR values: {e}")
            
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
                print(error_msg)
                return {'status': 'error', 'message': error_msg}
        except Exception as e:
            error_msg = f"Error processing message: {e}"
            print(error_msg)
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
            # Pass the encryption context if provided
            decrypted_key_response = self.kms.call_kms_decrypt(
                credential, 
                encrypted_data_key
            )
            print("decrypted wiht kms")
            
            # Check if the decrypted data includes the expected marker
            if "PLAINTEXT:" not in decrypted_key_response:
                error_msg = f"KMS decryption of data key failed. Response: {decrypted_key_response}"
                print(error_msg)
                return {"status": "error", "message": error_msg}
            
            # Parse the decrypted output that should start with "PLAINTEXT: "
            plaintext_key_b64 = decrypted_key_response.split("PLAINTEXT: ")[1].strip()
            
            # Decrypt the data using the plaintext key
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            import base64
            
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
                print(error_msg)
                return {'status': 'error', 'message': error_msg}
        except Exception as e:
            error_msg = f"Error processing encrypted message: {e}"
            print(error_msg)
            return {'status': 'error', 'message': error_msg}

def main():
    print("nitro server started ...")

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

        apiCall = payload_json["apiCall"]
        credential = payload_json["credential"]
        
        # Initialize server with credentials if not already done
        if server is None:
            server = nitroServer(region, credential)

        if apiCall == "processMessage":
            print("Processing message request")
            message_data = payload_json["messageData"]
            result = server.process_message(credential, message_data)
            c.send(str.encode(json.dumps(result)))
            print("Message processing finished")
        elif apiCall == "processEncryptedMessage":
            print("Processing encrypted message request")
            encrypted_data = payload_json["encryptedData"]
            encrypted_data_key = payload_json["encryptedDataKey"]
            result = server.process_encrypted_message(credential, encrypted_data, encrypted_data_key)
            c.send(str.encode(json.dumps(result)))
            print("Encrypted message processing finished")
        else:
            error_result = {'status': 'error', 'message': f'Unknown API call: {apiCall}'}
            c.send(str.encode(json.dumps(error_result)))

        c.close()

if __name__ == '__main__':
    main()
