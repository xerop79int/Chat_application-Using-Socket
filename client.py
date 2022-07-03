import socket
from time import sleep
from cryptography.fernet import Fernet
from ecdsa import SigningKey

def Verification_process(clientSocket, key):

    # Sending verification to server
    sk = SigningKey.generate()
    signature = sk.sign(key)

    clientSocket.send(signature)
    sleep(0.5)
    clientSocket.send(sk.to_string())
    sleep(0.5)
    clientSocket.send(key)

    # Verifing the server
    signature_recv = clientSocket.recv(1024)
    sk_recv = SigningKey.from_string(clientSocket.recv(2048))
    validation = clientSocket.recv(1024)
    vk = sk_recv.verifying_key

    if vk.verify(signature_recv, validation):
        print("Server is verified")

        return 

    


if __name__ == "__main__":
    Target_IP = "127.0.0.1"
    Port = 12345
    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    clientSocket.connect((Target_IP, Port))

    # Generating encryption Key
    key = Fernet.generate_key()
    f = Fernet(key)

    Verification_process(clientSocket, key)

    print("\nChat Application Started\n")

    while(True):

        msg = input("Enter your message:")
        encrypted_msg = f.encrypt(msg.encode())
        clientSocket.send(encrypted_msg)

        recv_encrypted_msg = clientSocket.recv(2048)
        recv_msg = f.decrypt(recv_encrypted_msg)
        print("server: " , recv_msg.decode())
