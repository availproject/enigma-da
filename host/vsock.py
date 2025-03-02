from logger import logger
import json
import socket

class VsockStream:
    def __init__(self, timeout=30):
        self.timeout = timeout


    def connect(self, endpoint):
        """
        Connect to enclave on given endpoint
        """
        try:
            self.sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
            self.sock.settimeout(self.timeout)
            self.sock.connect(endpoint)
        except ConnectionResetError as e:
            logger.error(f"Caught error {str(e.strerror)}, ,{str(e.errno)}")


    def execute(self, type, data):
        """
        Communicate with enclave
        """
        # Ensure we're sending the data directly without wrapping it
        # The enclave expects a JSON with apiCall, credential, and messageData
        
        # The data already contains these fields, so we don't need to wrap it
        message_str = json.dumps(data)

        self.sock.send(message_str.encode('utf-8'))
        logger.info(f"Sent to enclave: {data}")

        # Receive data in chunks until we get the complete response
        chunks = []
        while True:
            chunk = self.sock.recv(4096).decode()
            if not chunk:
                break
            chunks.append(chunk)
            # If the chunk ends with a valid JSON closing character, we're done
            if chunk.endswith('}'):
                break
        
        data = ''.join(chunks)
        logger.info(f"Received from enclave: {data}")

        self.sock.close()
        return data