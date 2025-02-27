from handlers import encrypt_data
import json
import socket 

class VsockListener:
    def __init__(self, backlog=128):
        self.backlog = backlog

    def bind(self, port):
        """
        Listen to connection from given port
        """
        self.sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
        self.sock.bind((socket.VMADDR_CID_ANY, port))
        self.sock.listen(self.backlog)

    def receive_data(self):
        """
        Recieve data from host
        """
        while True:
            try:
                print("Accepting connections...")
                (client, (remote_cid, remote_port)) = self.sock.accept()
                
                exec_data = client.recv(1024).decode('utf-8')
                if exec_data:
                    request = json.loads(exec_data)
                    if request.get('type') == 'encrypt':
                        data = request.get('data')
                        public_key = data.get('public_key')
                        plaintext = data.get('plaintext')
                        encrypted_data = encrypt_data(public_key, plaintext)
                        client.send(str(encrypted_data).encode())
    
                client.close()
            except Exception as ex:
                print(ex)


def main():
    server = VsockListener()
    server.bind(5005)
    server.receive_data()

if __name__ == '__main__':
    main()