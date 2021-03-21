#Crypto Session Start


from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from socketserver import socket
import random
import rsa
import math
import hashlib

HEADERLENGTH = 10


def receiveMessageRSA(clientSocket, serverPrivateKey):
	messageHeader = rsa.decrypt(clientSocket.recv(64), serverPrivateKey)
	messageHeader = messageHeader.decode('utf-8')
	messageLength = int(messageHeader.strip())
	messageTotal = clientSocket.recv(messageLength)
	message = ''
	for x in range(0,math.floor(messageLength/64)):
		message+= rsa.decrypt(messageTotal[(x*64):((x+1)*64)], serverPrivateKey).decode('utf-8')
	message = str(message)
	print(message)
	return message

def sendMessageRSA(clientSocket, message, clientPublicKey):
	message = str(message)
	print(message)
	messageChunks = []
	messageTotal = b''
	while len (message) > 0:
		encryptedChunk = rsa.encrypt(message[0:min(53,len(message))].encode('utf-8'), clientPublicKey)
		messageTotal += encryptedChunk
		message = message[min(53,len(message)):]
	messageHeader = rsa.encrypt(f"{len(messageTotal):<{HEADERLENGTH}}".encode('utf-8'), clientPublicKey)
	clientSocket.send(messageHeader + messageTotal)
	return

def main(socket, secret, clientPublicKey, serverPrivateKey, N1):
	cryptoVariables = {}
	N2 = random.getrandbits(128)
	print(N1)
	print(N2)
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