import base64
from Crypto.PublicKey import RSA
import aws_nsm_interface_verifiably
import json

class NsmInterface:
    """Class to interact with the Nitro Security Module (NSM)"""
    
    _instance = None
    
    @classmethod
    def get_instance(cls):
        """Singleton pattern to ensure we reuse the same key pair"""
        if cls._instance is None:
            cls._instance = NsmInterface()
        return cls._instance
    
    def __init__(self):
        """Initialize the NSM interface with a persistent RSA key pair"""
        # Generate RSA key pair that will be used for all attestation documents
        self._rsa_key = RSA.generate(2048)
        self._public_key = self._rsa_key.publickey().export_key('DER')
        
        # Open NSM device once and keep it open
        self._file_desc = aws_nsm_interface_verifiably.open_nsm_device()
    
    def __del__(self):
        """Clean up resources when the object is destroyed"""
        try:
            aws_nsm_interface_verifiably.close_nsm_device(self._file_desc)
        except:
            pass
    
    def get_attestation_doc(self, user_data=None) -> str:
        """
        Get an attestation document with optional user data.
        
        Args:
            user_data: Optional dict or string to include in the attestation document.
            
        Returns:
            Base64 encoded attestation document as a string.
        """
        # Prepare user data
        user_data_bytes = None
        if user_data is not None:
            # If user_data is a dict, convert to JSON string
            if isinstance(user_data, dict):
                user_data = json.dumps(user_data)
            
            # Convert to bytes
            user_data_bytes = user_data.encode('utf-8')
        
        # Get attestation document with user data
        attestation_doc = aws_nsm_interface_verifiably.get_attestation_doc(
            self._file_desc, 
            public_key=self._public_key,
            user_data=user_data_bytes
        )["document"]
        
        # Encode attestation document in base64
        attestation_doc_b64 = base64.b64encode(attestation_doc).decode("utf-8")
        
        return attestation_doc_b64
    
    def get_public_key(self):
        """Get the public key used for attestation documents"""
        return self._public_key


# For backward compatibility
def get_attestation_doc(user_data=None) -> str:
    """Wrapper function for backward compatibility"""
    instance = NsmInterface.get_instance()
    return instance.get_attestation_doc(user_data=user_data)


# Example usage:
# attestation_doc_b64 = get_attestation_doc(user_data="hello")