#Crypto Session Start


from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from socketserver import socket
import random
import rsa


HEADERLENGTH = 10


def receiveMessageRSA(clientSocket, serverPrivateKey):
	messageHeader = rsa.decrypt(clientSocket.recv(256), serverPrivateKey)
	messageHeader = messageHeader.decode('utf-8')
	messageLength = int(messageHeader.strip())
	message = rsa.decrypt(clientSocket.recv(messageLength), serverPrivateKey)
	message = message.decode('utf-8')
	message = str(message)
	return message

def sendMessageRSA(clientSocket, message, clientPublicKey):
	message = str(message)
	message = rsa.encrypt(message.encode('utf-8'), clientPublicKey)
	messageHeader = rsa.encrypt(f"{len(message):<{HEADERLENGTH}}".encode('utf-8'), clientPublicKey)
	clientSocket.send(messageHeader + message)
	return

def main(socket, secret, clientPublicKey, serverPrivateKey, N1):
	cryptoVariables = {}
	N2 = random.getrandbits(128)
	message = f'{N2},{N2+N1}'
	sendMessageRSA(socket, message, clientPublicKey)

	#N2+N3, N3
	message = receiveMessageRSA(socket, serverPrivateKey)
	variables = message.split(",")
	clientAuth = int(variables[1])
	N3 = int(variables[0])

	if (clientAuth - N2) != N3:
		return "abort connection"

	print ("Client Has Been Authed")
	IV = hashlib.sha256(str((N2 * N3)).encode()).hexdigest()
	N2 = hashlib.sha256(str(N2).encode()).hexdigest()
	N3 = hashlib.sha256(str(N2).encode()).hexdigest()
	x = slice(16)
	N2 = N2[x]
	N3 = N3[x]

	cryptoVariables["sessionKey"] = N2 + N3
	cryptoVariables["IV"] = IV[x]

	return cryptoVariables