import socket
import requests
import json
import boto3
import sys
import base64
from botocore.config import Config
from appStore import AppStore


"""
dynamodb design
table name: AccountTable

colume:
keyId: kms alias id which used for encryption for the private key
Name: account name for this Account
encipherPublicKey: public key for message encryption
encryptedMessage: encrypted message
encryptedDataKey: the data key used to encrypt the message
"""


class AccountClient:

    """
    region: region to deploy
    ddbTableName: the dynamodb table name which used to store and retrive the encrypted
    keyId: the kms alais id, used to encrypt the plaintext and decrypt the ciphertext
    cid: cid for vsock client to connect
    port: port for vsock client to connect
    """

    def __init__(self, region, ddbTableName, keyId, cid, port):
        self.__region = region
        self.__ddbTableName = ddbTableName
        self.__keyId = keyId
        self.__cid = cid
        self.__port = port
        self.__app_store = AppStore(region, 'AppKeyTable')  # Initialize AppStore

    def encryptAndStoreMessage(self, name, appId, encipherPlainText, save_to_ddb=False):
        """
        Encrypt a plaintext message with a public key from the app store and store in DynamoDB
        
        Parameters:
        name - The name to identify this message
        appId - The app ID to retrieve the public key
        encipherPlainText - The plaintext message to encrypt
        save_to_ddb - Whether to save the encrypted message to DynamoDB (default: False)
        """
        # Get the public key for the app ID
        try:
            encipherPublicKey = self.__app_store.getPublicKey(appId)
            print(f"Retrieved public key for app ID '{appId}'")
        except Exception as e:
            print(f"Error retrieving public key: {e}")
            return {'status': 'error', 'message': f'Error retrieving public key: {str(e)}'}
        
        # Get AWS credentials
        credential = self.__getIAMToken()
        
        # Use KMS directly to encrypt the appId and plaintext
        kms_client = boto3.client('kms', region_name=self.__region)
        message_to_encrypt = json.dumps({
            'appId': appId,
            'plaintext': encipherPlainText
        })
        
        try:
            encrypted_data = kms_client.encrypt(
                KeyId=self.__keyId,
                Plaintext=message_to_encrypt.encode()
            )
            
            # Convert the encrypted data to base64 string
            encrypted_data_b64 = base64.b64encode(encrypted_data['CiphertextBlob']).decode('utf-8')
            
            # Connect to the server
            s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
            s.connect((self.__cid, self.__port))

            payload = {}
            payload['apiCall'] = "processEncryptedMessage"
            payload['credential'] = credential
            payload['keyId'] = self.__keyId
            payload['publicKey'] = encipherPublicKey
            payload['encryptedData'] = encrypted_data_b64
            
            # Send data to the enclave
            s.send(str.encode(json.dumps(payload)))
            
            # Receive response from the enclave
            response = s.recv(65536).decode()
            
            # Save encrypted message to DynamoDB if requested
            if response and save_to_ddb:
                self.__saveEncryptedMessageToDDB(name, response, self.__keyId)
            
            s.close()
            if response:
                return json.loads(response)
            else:
                return {'status': 'error', 'message': 'No response from enclave'}
        except Exception as e:
            return {'status': 'error', 'message': f'Error encrypting message: {str(e)}'}

    def __saveEncryptedMessageToDDB(self, name, response, keyId):
        """
        Save encrypted message to DynamoDB
        """
        dynamodb = boto3.resource('dynamodb', self.__region)
        table = dynamodb.Table(self.__ddbTableName)
        response_json = json.loads(response)
        print("Saving encrypted message to DDB:", response_json)
        
        # Handle different field names in the response
        public_key = response_json.get('publicKey', response_json.get('encipherPublicKey', ''))
        encrypted_message = response_json.get('encryptedMessage', '')
        encrypted_data_key = response_json.get('encryptedDataKey', '')
        attestation_document = response_json.get('attestationDoc', '')
        message_digest = response_json.get('messageDigest', '')
        
        table.put_item(Item={
            'name': name,
            'keyId': keyId,
            'encipherPublicKey': public_key,
            'encryptedMessage': encrypted_message,
            'encryptedDataKey': encrypted_data_key,
            'attestationDocument': attestation_document,
            'messageDigest': message_digest
        })
        print("Successfully saved to DynamoDB")

    def decryptAndProcessMessage(self, keyId, name):
        """
        Retrieve encrypted message from DynamoDB and decrypt it in the enclave
        """
        # Get AWS credentials
        credential = self.__getIAMToken()
        
        # Get encrypted message from DynamoDB
        dynamodb = boto3.resource('dynamodb', self.__region)
        table = dynamodb.Table(self.__ddbTableName)
        response = table.get_item(
            Key={
                'keyId': keyId,
                'name': name
            }
        )
        
        if 'Item' not in response:
            raise Exception(f"No encrypted message found for {name}")
        
        item = response['Item']
        
        # Connect to the server
        s = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        s.connect((self.__cid, self.__port))

        payload = {}
        payload['apiCall'] = "decryptAndProcessMessage"
        payload['credential'] = credential
        payload['encipherPublicKey'] = item['encipherPublicKey']
        payload['encryptedMessage'] = item['encryptedMessage']
        payload['encryptedDataKey'] = item['encryptedDataKey']
        
        # Send data to the enclave
        s.send(str.encode(json.dumps(payload)))
        
        # Receive response from the enclave
        response = s.recv(65536).decode()
        s.close()
        return json.loads(response)

    def __getIAMToken(self):
        """
        Get the AWS credential from EC2 instance metadata or use boto3 session credentials
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
                        return self.__get_fallback_credentials()
                    
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
                return self.__get_fallback_credentials()
            
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
                return self.__get_fallback_credentials()
        except Exception as e:
            print(f"Error accessing EC2 metadata service: {e}")
            return self.__get_fallback_credentials()

    def __get_fallback_credentials(self):
        """
        Use boto3 session credentials as fallback
        """
        print("Using fallback credentials from boto3 session")
        session = boto3.Session(region_name=self.__region)
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


def main():
    if len(sys.argv) < 4:
        print("Usage: python appClient.py <app_id> <message_name> <plaintext_message> [save_to_ddb]")
        sys.exit(1)
        
    app_id = sys.argv[1]
    message_name = sys.argv[2]
    plaintext_message = sys.argv[3]
    save_to_ddb = False
    
    # Check if we should save to DynamoDB
    if len(sys.argv) > 4 and sys.argv[4].lower() in ('true', 'yes', '1'):
        save_to_ddb = True
    
    region = 'us-east-1'
    keyId = 'eb8a1ce9-b5fd-4ea3-a9a2-66167db14f28'
    tableName = 'AccountTable'

    config = Config(
        region_name=region
    )

    # Only create tables if we're going to save to DynamoDB
    if save_to_ddb:
        client = boto3.client('dynamodb', config=config)
        try:
            client.describe_table(TableName=tableName)
        except:
            client.create_table(
                TableName=tableName,
                KeySchema=[
                    {'AttributeName': 'keyId', 'KeyType': 'HASH'},
                    {'AttributeName': 'name', 'KeyType': 'RANGE'}
                ],
                AttributeDefinitions=[
                    {'AttributeName': 'keyId', 'AttributeType': 'S'},
                    {'AttributeName': 'name', 'AttributeType': 'S'}
                ],
                ProvisionedThroughput={
                    'ReadCapacityUnits': 10,
                    'WriteCapacityUnits': 10
                }
            )
    
    # Check if AppKeyTable exists, create if not
    client = boto3.client('dynamodb', config=config)
    try:
        client.describe_table(TableName='AppKeyTable')
    except:
        client.create_table(
            TableName='AppKeyTable',
            KeySchema=[
                {'AttributeName': 'appId', 'KeyType': 'HASH'}
            ],
            AttributeDefinitions=[
                {'AttributeName': 'appId', 'AttributeType': 'S'}
            ],
            ProvisionedThroughput={
                'ReadCapacityUnits': 10,
                'WriteCapacityUnits': 10
            }
        )
        print("Created AppKeyTable")
    
    # Generate a client and demo it
    client = AccountClient(region, tableName, keyId, 16, 5000)
    
    # Encrypt and store message
    encryptedResult = client.encryptAndStoreMessage(message_name, app_id, plaintext_message, save_to_ddb)
    
    if 'status' in encryptedResult and encryptedResult['status'] == 'error':
        print(f"Error: {encryptedResult['message']}")
        sys.exit(1)
    
    print("\nEncryption Result:")
    # if 'publicKey' in encryptedResult:
        # print(f"Public Key: {encryptedResult['publicKey'][:50]}...")
    if 'encryptedMessage' in encryptedResult:
        print(f"Encrypted Message: {encryptedResult['encryptedMessage'][:50]}...")
    if 'encryptedDataKey' in encryptedResult:
        print(f"Encrypted Data Key: {encryptedResult['encryptedDataKey'][:50]}...")
    if 'attestationDoc' in encryptedResult:
        print(f"Attestation Document: {encryptedResult['attestationDoc'][:50]}...")

    # write to a file in json format
    with open('encryptedResult.json', 'w') as f:
        json.dump(encryptedResult, f)
    
    # Only attempt to decrypt if we saved to DynamoDB
    if save_to_ddb:
        try:
            decryptedResult = client.decryptAndProcessMessage(keyId, message_name)
            print(f"Message processed in enclave. Result: {decryptedResult}")
        except Exception as e:
            print(f"Error decrypting message: {e}")


if __name__ == '__main__':
    main()
