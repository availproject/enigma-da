#!/usr/bin/env python3

import argparse
import base64
import json
import os
import subprocess
import tempfile
import hashlib
import cbor2
import binascii
import sys
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from OpenSSL import crypto

from cose import EC2, CoseAlgorithms, CoseEllipticCurves, Sign1Message
from Crypto.Util.number import long_to_bytes
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.exceptions import InvalidSignature


def verify_attestation_doc(attestation_doc, pcrs=None, root_cert_pem=None):
    """
    Verify the attestation document
    If invalid, raise an exception
    """
    # Decode CBOR attestation document
    data = cbor2.loads(attestation_doc)

    # Load and decode document payload
    doc = data[2]
    doc_obj = cbor2.loads(doc)

    # Get PCRs from attestation document
    document_pcrs_arr = doc_obj['pcrs']
    
    # Extract user data if present
    user_data = doc_obj.get('user_data')
    
    ###########################
    # Part 1: Validating PCRs #
    ###########################
    if pcrs:
        for index, pcr in pcrs.items():
            index = int(index)
            # Attestation document doesn't have specified PCR, raise exception
            if index not in document_pcrs_arr or document_pcrs_arr[index] is None:
                raise Exception(f"PCR{index} not found in attestation document")

            # Get PCR hexcode
            doc_pcr = document_pcrs_arr[index].hex()

            # Check if PCR match
            if pcr.lower() != doc_pcr.lower():
                raise Exception(f"PCR{index} mismatch. Expected: {pcr}, Got: {doc_pcr}")
            print(f"PCR{index} verified: {doc_pcr}")

    ################################
    # Part 2: Validating signature #
    ################################

    # Get signing certificate from attestation document
    cert = crypto.load_certificate(crypto.FILETYPE_ASN1, doc_obj['certificate'])

    # Get the key parameters from the cert public key
    cert_public_numbers = cert.get_pubkey().to_cryptography_key().public_numbers()
    x = cert_public_numbers.x
    y = cert_public_numbers.y

    x = long_to_bytes(x)
    y = long_to_bytes(y)

    # Create the EC2 key from public key parameters
    key = EC2(alg=CoseAlgorithms.ES384, x=x, y=y, crv=CoseEllipticCurves.P_384)

    # Get the protected header from attestation document
    phdr = cbor2.loads(data[0])

    # Construct the Sign1 message
    msg = Sign1Message(phdr=phdr, uhdr=data[1], payload=doc)
    msg.signature = data[3]

    # Verify the signature using the EC2 key
    if not msg.verify_signature(key):
        raise Exception("Invalid signature")
    print("Signature verification successful")

    ##############################################
    # Part 3: Validating signing certificate PKI #
    ##############################################
    if root_cert_pem is not None:
        # Create an X509Store object for the CA bundles
        store = crypto.X509Store()

        # Create the CA cert object from PEM string, and store into X509Store
        _cert = crypto.load_certificate(crypto.FILETYPE_PEM, root_cert_pem)
        store.add_cert(_cert)

        # Get the CA bundle from attestation document and store into X509Store
        # Except the first certificate, which is the root certificate
        for _cert_binary in doc_obj['cabundle'][1:]:
            _cert = crypto.load_certificate(crypto.FILETYPE_ASN1, _cert_binary)
            store.add_cert(_cert)

        # Get the X509Store context
        store_ctx = crypto.X509StoreContext(store, cert)
        
        # Validate the certificate
        # If the cert is invalid, it will raise exception
        store_ctx.verify_certificate()
        print("Certificate chain verification successful")
    
    return user_data


def verify_attestation(attestation_doc_b64, encrypted_message_b64=None, expected_pcrs=None, user_data_hex=None, root_cert_path=None):
    """
    Verify an attestation document against the AWS Nitro Enclaves root certificate.
    
    Args:
        attestation_doc_b64: Base64-encoded attestation document
        encrypted_message_b64: Base64-encoded encrypted message (optional)
        expected_pcrs: Dictionary of expected PCR values (optional)
        user_data_hex: Expected user data in hex format (optional)
        root_cert_path: Path to AWS Nitro Enclaves root certificate (optional)
        
    Returns:
        True if verification succeeds, False otherwise
    """
    try:
        # Decode the base64 attestation document
        attestation_doc = base64.b64decode(attestation_doc_b64)
        
        # Load root certificate if provided
        root_cert_pem = None
        if root_cert_path:
            with open(root_cert_path, 'rb') as f:
                root_cert_pem = f.read()
        
        # Verify the attestation document
        try:
            user_data = verify_attestation_doc(attestation_doc, expected_pcrs, root_cert_pem)
            print("Attestation document verified successfully")
        except Exception as e:
            print(f"Attestation document verification failed: {e}")
            return False
        
        # If we have encrypted_message_b64, verify the message hash in user_data
        if encrypted_message_b64 and user_data and isinstance(user_data, dict) and 'message_hash' in user_data:
            try:
                encrypted_message = base64.b64decode(encrypted_message_b64)
                calculated_hash = hashlib.sha256(encrypted_message).hexdigest()
                
                if calculated_hash != user_data['message_hash']:
                    print(f"Message hash mismatch: expected {user_data['message_hash']}, got {calculated_hash}")
                    return False
                
                print("Message hash verified successfully")
            except Exception as e:
                print(f"Error verifying message hash: {e}")
                return False
        
        # If expected_pcrs are provided, verify they match what's in user_data
        if expected_pcrs and user_data and isinstance(user_data, dict) and 'expected_pcrs' in user_data:
            try:
                user_pcrs = user_data['expected_pcrs']
                for pcr_id, expected_value in expected_pcrs.items():
                    if pcr_id not in user_pcrs or user_pcrs[pcr_id].lower() != expected_value.lower():
                        print(f"PCR {pcr_id} in user data does not match expected value")
                        print(f"Expected: {expected_value.lower()}")
                        print(f"Got: {user_pcrs.get(pcr_id, '').lower()}")
                        return False
                
                print("PCR values in user data verified successfully")
            except Exception as e:
                print(f"Error verifying PCR values in user data: {e}")
                return False
        
        return True
    
    except Exception as e:
        print(f"Error in attestation verification: {e}")
        return False


def extract_pcrs_from_policy(policy_file):
    """Extract PCR values from a KMS key policy file"""
    with open(policy_file, 'r') as f:
        policy_json = json.load(f)
    
    expected_pcrs = {}
    for statement in policy_json.get('Statement', []):
        if statement.get('Sid') == 'Allow decryption only from Nitro Enclaves':
            condition = statement.get('Condition', {}).get('StringEqualsIgnoreCase', {})
            for key, value in condition.items():
                if key.startswith('kms:RecipientAttestation:PCR'):
                    pcr_id = key.split(':')[-1]
                    expected_pcrs[pcr_id] = value
    
    return expected_pcrs


def decode_attestation_doc(attestation_doc):
    """
    Decode and parse an attestation document for pretty printing
    """
    try:
        # Decode CBOR attestation document
        data = cbor2.loads(attestation_doc)
        
        # Load and decode document payload
        doc = data[2]
        doc_obj = cbor2.loads(doc)
        
        # Format PCRs for better readability
        pcrs = {}
        if 'pcrs' in doc_obj:
            for pcr_id, pcr_value in doc_obj['pcrs'].items():
                if pcr_value is not None:
                    pcrs[str(pcr_id)] = pcr_value.hex()
                else:
                    pcrs[str(pcr_id)] = None
        
        # Extract user data if present
        user_data = None
        if 'user_data' in doc_obj and doc_obj['user_data'] is not None:
            try:
                # Try to decode as JSON
                user_data_str = doc_obj['user_data'].decode('utf-8')
                user_data = json.loads(user_data_str)
            except:
                # If not JSON, show as hex
                user_data = doc_obj['user_data'].hex() if doc_obj['user_data'] else None
        
        # Process public key with more detail
        public_key_info = None
        if 'public_key' in doc_obj and doc_obj['public_key']:
            try:
                # Get the raw hex representation
                public_key_hex = doc_obj['public_key'].hex()
                
                # Try to parse as RSA key to get more info
                try:
                    key = RSA.import_key(doc_obj['public_key'])
                    public_key_info = {
                        "type": "RSA",
                        "size": key.size_in_bits(),
                        "hex": public_key_hex[:64] + "..." if len(public_key_hex) > 64 else public_key_hex,
                        "full_hex": public_key_hex
                    }
                except:
                    # If not RSA, just show the hex
                    public_key_info = {
                        "type": "Unknown",
                        "hex": public_key_hex[:64] + "..." if len(public_key_hex) > 64 else public_key_hex,
                        "full_hex": public_key_hex
                    }
            except Exception as e:
                public_key_info = {"error": f"Failed to process public key: {str(e)}"}
        
        # Create a readable structure
        result = {
            "pcrs": pcrs,
            "user_data": user_data,
            "public_key": public_key_info,
            "certificate": "present" if 'certificate' in doc_obj and doc_obj['certificate'] else "not present",
            "cabundle": f"present ({len(doc_obj['cabundle'])} certificates)" if 'cabundle' in doc_obj and doc_obj['cabundle'] else "not present",
            "nonce": doc_obj.get('nonce', b'').hex() if 'nonce' in doc_obj and doc_obj['nonce'] else None,
            "timestamp": doc_obj.get('timestamp', 0)
        }
        
        return result
    except Exception as e:
        return {"error": f"Failed to decode attestation document: {str(e)}"}


def verify_root_cert(root_cert_pem):
    """Verify this is the official AWS Nitro Enclaves root certificate"""
    expected_fingerprint = "A2:F6:B2:7A:5E:C7:F8:E6:88:C3:32:E2:4E:31:D7:F5:C8:10:F7:95:C3:EF:8E:F9:C9:F2:9D:B8:41:D3:95"
    cert = crypto.load_certificate(crypto.FILETYPE_PEM, root_cert_pem)
    fingerprint = cert.digest("sha256").decode('utf-8')
    if fingerprint != expected_fingerprint:
        print(f"Warning: Root certificate fingerprint doesn't match expected value")
        print(f"Expected: {expected_fingerprint}")
        print(f"Got: {fingerprint}")
        return False
    return True


def verify_attestation_from_file(result_file, root_cert_path=None):
    """
    Verify attestation from a consolidated result file
    
    Args:
        result_file: Path to the consolidated JSON result file
        root_cert_path: Path to AWS Nitro Enclaves root certificate (optional)
        
    Returns:
        True if verification succeeds, False otherwise
    """
    try:
        # Load the consolidated result file
        with open(result_file, 'r') as f:
            result_data = json.load(f)
        
        # Extract the attestation document and encrypted data
        attestation_doc_b64 = result_data.get('attestation_doc')
        encrypted_message_b64 = result_data.get('encrypted_data')
        
        if not attestation_doc_b64:
            print(f"Error: No attestation document found in {result_file}")
            return False
            
        # Verify the attestation
        return verify_attestation(
            attestation_doc_b64, 
            encrypted_message_b64,
            root_cert_path=root_cert_path
        )
    
    except Exception as e:
        print(f"Error processing result file: {e}")
        return False


def verify_attestation_document(attestation_doc_b64, expected_pcrs=None):
    """
    Verify an attestation document from a Nitro Enclave
    
    Args:
        attestation_doc_b64: Base64-encoded attestation document
        expected_pcrs: Dictionary of expected PCR values (optional)
        
    Returns:
        Dictionary with verification results
    """
    try:
        # Fix base64 padding if needed
        padding_needed = len(attestation_doc_b64) % 4
        if padding_needed:
            attestation_doc_b64 += '=' * (4 - padding_needed)
        
        # Decode the attestation document
        attestation_doc_bytes = base64.b64decode(attestation_doc_b64)
        
        # Look for root certificate in common locations
        root_cert_paths = [
            'root.pem',
            '/etc/nitro_enclaves/root.pem',
            os.path.join(os.path.dirname(os.path.abspath(__file__)), 'root.pem'),
            os.path.join(os.path.dirname(os.path.abspath(__file__)), '../root.pem')
        ]
        
        root_cert_pem = None
        for path in root_cert_paths:
            if os.path.exists(path):
                with open(path, 'rb') as f:
                    root_cert_pem = f.read()
                print(f"Using root certificate from {path}")
                break
        
        if not root_cert_pem:
            print("Warning: No root certificate found. Certificate chain verification will be skipped.")
        
        # Use decode_attestation_doc to get document info first
        doc_info = decode_attestation_doc(attestation_doc_bytes)
        
        if "error" in doc_info:
            return {
                "verification_status": "error",
                "error": doc_info["error"]
            }
        
        # Convert expected PCRs to the format needed by verify_attestation_doc
        pcrs_for_verification = {}
        if expected_pcrs:
            for pcr_id, expected_value in expected_pcrs.items():
                # Extract numeric PCR ID from string (e.g., "PCR0" -> "0")
                numeric_pcr_id = pcr_id.replace("PCR", "")
                pcrs_for_verification[numeric_pcr_id] = expected_value
        
        # Verify the attestation document
        try:
            verify_attestation_doc(attestation_doc_bytes, pcrs_for_verification, root_cert_pem)
            
            # Verify PCR values if expected values are provided
            pcr_verification = {}
            if expected_pcrs:
                for pcr_id, expected_value in expected_pcrs.items():
                    # Extract numeric PCR ID from string (e.g., "PCR0" -> "0")
                    numeric_pcr_id = pcr_id.replace("PCR", "")
                    
                    # Get the actual PCR value from the document
                    actual_value = None
                    for i, pcr_value in doc_info["pcrs"].items():
                        if str(i) == numeric_pcr_id:
                            actual_value = pcr_value
                            break
                    
                    # Only include match status in verification result
                    match = actual_value and expected_value.lower() == actual_value.lower()
                    pcr_verification[pcr_id] = match
            
            # Determine overall verification status
            verification_passed = True
            if expected_pcrs:
                for pcr_id, match in pcr_verification.items():
                    if not match:
                        verification_passed = False
                        break
            
            # Filter PCRs to only include 0, 1, and 2
            filtered_pcrs = {}
            for pcr_id, pcr_value in doc_info["pcrs"].items():
                if str(pcr_id) in ["0", "1", "2"]:
                    filtered_pcrs[pcr_id] = pcr_value
            
            # Create a clean, simplified response
            return {
                "verification_status": "passed" if verification_passed else "failed",
                "pcrs": filtered_pcrs,
                "pcr_verification": pcr_verification,
                "timestamp": doc_info.get("timestamp"),
                "certificate_verified": root_cert_pem is not None
            }
        except Exception as e:
            return {
                "verification_status": "error",
                "error": f"Attestation verification failed: {str(e)}"
            }
    
    except Exception as e:
        return {
            "verification_status": "error",
            "error": str(e)
        }


def main():
    parser = argparse.ArgumentParser(description='Verify AWS Nitro Enclaves attestation documents')
    parser.add_argument('--result-file', help='Path to consolidated result JSON file')
    parser.add_argument('--root-cert', help='Path to AWS Nitro Enclaves root certificate')
    
    args = parser.parse_args()
    
    if args.result_file:
        success = verify_attestation_from_file(args.result_file, args.root_cert)
        if success:
            print("Attestation verification successful!")
            sys.exit(0)
        else:
            print("Attestation verification failed!")
            sys.exit(1)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
