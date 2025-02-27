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
        message = {
            "type": type,
            "data": data
        }
        message_str = json.dumps(message)

        self.sock.send(message_str.encode('utf-8'))
        logger.info(f"Sent to enclave: {data}")

        data = self.sock.recv(1024).decode()
        logger.info(f"Received from enclave: {data}")

        self.sock.close()
        return data