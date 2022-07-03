import socket
from time import sleep
from cryptography.fernet import Fernet
from ecdsa import SigningKey

def Verification_process(client):
	signature_recv = client.recv(1024)
	sk_recv = SigningKey.from_string(client.recv(2048))
	key = client.recv(1024)
	vk = sk_recv.verifying_key

	if vk.verify(signature_recv, key):
		print("Client is verified")

		# Sending verification to Client
		sk = SigningKey.generate()
		signature = sk.sign(b"Received")

		client.send(signature)
		sleep(0.5)
		client.send(sk.to_string())
		sleep(0.5)
		client.send(b"Received")

		return key




if __name__ == '__main__':

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)		
	ip = '127.0.0.1'
	port = 12345			
	s.bind((ip, port))		
	s.listen()	
	print ("socket is listening")		

	client, addr = s.accept()	
	print ('Got connection from', addr )

	key = Verification_process(client)
	f = Fernet(key)

	print("\nChat Application Started\n")

	while(True):
		recv_encrypted_msg = client.recv(1024)
		recv_msg = f.decrypt(recv_encrypted_msg)

		print("Client: " , recv_msg.decode())

		msg = input("Enter your message:")
		encrypted_msg = f.encrypt(msg.encode())
		client.send(encrypted_msg)

