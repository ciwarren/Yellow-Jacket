#Crypto Session Start


from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from socketserver import socket
import random
import rsa


HEADERLENGTH = 10


def receiveMessageRSA(clientSocket, serverPrivateKey):
	messageHeader = rsa.decrypt(clientSocket.recv(256), privateKey)
	messageHeader = messageHeader.decode('utf-8')
	messageLength = int(messageHeader.strip())
	message = rsa.decrypt(clientSocket.recv(messageLength), privateKey)
	message = message.decode('utf-8')
	message = str(message)
	return message

def sendMessageRSA(clientSocket, message, clientPublicKey):
	clientPublic = clientPublicKeys[source]
	message = str(message)
	message = rsa.encrypt(message.encode('utf-8'), clientPublic)
	messageHeader = rsa.encrypt(f"{len(message):<{HEADERLENGTH}}".encode('utf-8'), clientPublic)
	clientSocket.send(messageHeader + message)
	return

def main(socket, secret, clientPublicKey, serverPrivateKey, N1):
	cryptoVariables = {}
	message = f'PHASE2'
	sendMessage(socket, message)
	N2 = random.getrandbits(128)
	message = f'{N2+N1},{N2}'
	sendMessageRSA(socket, message, clientPublicKey)

	#N2+N3, N3
	message = receiveMessageRSA(socket, serverPrivateKey)
	variables = message.split(",")
	clientAuth = int(variables[0])
	N3 = int(variables[1])

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