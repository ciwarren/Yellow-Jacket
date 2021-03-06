#Client
#Sources:
	#https://www.geeksforgeeks.org/primitive-root-of-a-prime-number-n-modulo-n/
	#https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange
	#https://stackoverflow.com/questions/15285534/isprime-function-for-python-language
	#https://asecuritysite.com/encryption/diffie_py
from socketserver import socket
import random
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import rsa
import math
from datetime import datetime

HEADERLENGTH = 10

def sendMessage(clientSocket, message):
	message = str(message)
	message = message.encode('utf-8')
	messageHeader = f"{len(message):<{HEADERLENGTH}}".encode('utf-8')
	clientSocket.send(messageHeader + message)
	return

def receiveMessage(clientSocket):
	messageHeader = clientSocket.recv(HEADERLENGTH)
	if not len(messageHeader):
		return False
	messageLength = int(messageHeader.decode('utf-8').strip())
	message = clientSocket.recv(messageLength)
	message = message.decode('utf-8')
	message = str(message)
	return message

#Used for all communication after negotiation
def receiveMessageEncryptedCBC(clientSocket, sessionKey, IV):
	messageHeader = decryptMessageCBC(clientSocket.recv(256), sessionKey, IV)
	messageHeader = messageHeader.decode('utf-8')
	messageLength = int(messageHeader.strip())
	message = decryptMessageCBC(clientSocket.recv(messageLength), sessionKey, IV)
	message = message.decode('utf-8')
	message = str(message)
	return message


def sendMessageEncryptedCBC(clientSocket, message, clientPrivateKey, sessionKey, IV):
	message = str(message).encode('utf-8')
	signature = rsa.sign(message, clientPrivateKey, 'SHA-256')
	message = encryptMessageCBC(message, sessionKey, IV)
	messageHeader = encryptMessageCBC(f"{len(message):<{HEADERLENGTH}}".encode('utf-8'), sessionKey, IV)
	clientSocket.send(messageHeader + signature + message)
	return


def decryptMessageCBC(payload, sessionKey, IV):
	sessionKey = sessionKey.encode('utf-8')
	#If this breaks, revert to not encoding the sessionkey
	IV = IV.encode('utf-8')
	cipher = AES.new(sessionKey, AES.MODE_CBC, IV)
	data = unpad(cipher.decrypt(payload), 256)
	return data


def encryptMessageCBC(data, sessionKey, IV):
	sessionKey = sessionKey.encode('utf-8')
	IV = IV.encode('utf-8')
	cipher = AES.new(sessionKey, AES.MODE_CBC, IV)
	data = pad(data,256)
	payload = cipher.encrypt(data)
	return payload

#Used for all communication for cryptosessionstart


def receiveMessageRSA(clientSocket, privateKey):
	messageHeader = rsa.decrypt(clientSocket.recv(64), privateKey)
	messageHeader = messageHeader.decode('utf-8')
	messageLength = int(messageHeader.strip())
	messageTotal = clientSocket.recv(messageLength)
	message = ''
	for x in range(0,math.floor(messageLength/64)):
		message+= rsa.decrypt(messageTotal[(x*64):((x+1)*64)], privateKey).decode('utf-8')
	message = str(message)
	#print(message)
	return message

def sendMessageRSA(clientSocket, message, serverPublicKey):
	message = str(message)
	messageChunks = []
	messageTotal = b''
	while len (message) > 0:
		encryptedChunk = rsa.encrypt(message[0:min(53,len(message))].encode('utf-8'), serverPublicKey)
		messageTotal += encryptedChunk
		message = message[min(53,len(message)):]
	messageHeader = rsa.encrypt(f"{len(messageTotal):<{HEADERLENGTH}}".encode('utf-8'), serverPublicKey)
	#print(messageHeader)
	clientSocket.send(messageHeader + messageTotal)
	return


def interpretConfig(file):
	file = open(file, "r")
	serverConfig = file.readlines()
	file.close()
	configDict = {}

	for x in serverConfig:
		try:
			element = x.split(":")
			key = element[0]
			value = element[1]
			configDict[key] = value

		except:
			continue
	return configDict




def cryptoSessionStart(clientSocket, N1, privateKey, serverPublicKey):
	#N2+N1, N2
	message = receiveMessageRSA(clientSocket, privateKey)
	#print(message)
	variables = message.split(",")
	serverAuth = int(variables[0])
	N2 = int(variables[1])

	if (serverAuth - N1) != N2:
		return "fail"

	#print ("Server Has Been Authed")

	N3 = random.getrandbits(128)
	message = f'{N2+N3},{N3}'
	sendMessageRSA(clientSocket, message, serverPublicKey)

	IV = hashlib.sha256(str((N2 * N3)).encode()).hexdigest()
	N2 = hashlib.sha256(str(N2).encode()).hexdigest()
	N3 = hashlib.sha256(str(N2).encode()).hexdigest()
	x = slice(16)
	N2 = N2[x]
	N3 = N3[x]
	
	cryptoVariables = {}
	cryptoVariables["sessionKey"] = N2 + N3
	cryptoVariables["IV"] = IV[x]

	return cryptoVariables
	

def main(log):
	#clientConfig = interpretConfig("/var/Agent/Client/clientConfig.txt")
	#IP = clientConfig[ServerIP]
	#PORT = clientConfig[ServerPort]
	#hostname = clientConfig[Hostname]
	#TODO: Load client keys
	timestamp_key_generation_start = datetime.now()
	try:
		with open('clientPublic.pem', mode='rb') as publicFile:
			keydata = publicFile.read()
			publicKey = rsa.PublicKey.load_pkcs1(keydata)
		
		with open('clientPrivate.pem', mode='rb') as privateFile:
			keydata = privateFile.read()
			privateKey = rsa.PrivateKey.load_pkcs1(keydata)
	
	except:
		(publicKey, privateKey) = rsa.newkeys(512)
		
		file = open("clientPublic.pem", "w")
		file.write(publicKey.save_pkcs1().decode('utf-8'))
		file.close()

		file = open("clientPrivate.pem", "w")
		file.write(privateKey.save_pkcs1().decode('utf-8'))
		file.close()


	
	with open('serverPublic.pem', mode='rb') as publicFile:
		keydata = publicFile.read()
	serverPublicKey = rsa.PublicKey.load_pkcs1(keydata)
	timestamp_key_generation_end = datetime.now()
	lIP = '192.168.1.158'
	PORTS = []
	PORTS.extend(range(10000, 11000))
	lPort = random.choice(PORTS)
	localAddress = (lIP, lPort, )
	IP = "192.168.1.135"
	PORT = 1337
	hostname = "client1"
	clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	clientSocket.bind((localAddress))
	clientSocket.connect((IP, PORT))
	N1 = random.getrandbits(128)
	#print(N1)

	'''
	try:
		file = open("/var/Agent/Secure/secret.txt", "r")
		status = "PHASE2"

	except:
		status = "PHASE1"
	'''

	#message = f'{hostname},{N1},{status},{HMACGen(HMACKey,hostname)}'
	#TODO: Send Client Public Key in this message
	message = f'{hostname},{N1},{publicKey.save_pkcs1().decode("utf-8")}'
	#TODO: Message needs to be encrypted with the servers public key.
	#sendMessageRSA(clientSocket, message, serverPublicKey)
	sendMessage(clientSocket ,message)

	timestamp_authentication_start = datetime.now()
	cryptoVariables = cryptoSessionStart(clientSocket, N1, privateKey, serverPublicKey)
	timestamp_authentication_end = datetime.now()
	
	if "fail" in cryptoVariables:
		print("Failed to authenticate with server")

	timestamp_message_start = datetime.now()
	sendMessageEncryptedCBC(clientSocket, log, privateKey, cryptoVariables["sessionKey"], cryptoVariables["IV"])
	timestamp_message_end = datetime.now()

	#print(f'Sent message: {log}')

	clientSocket.close()
	delta_key_generation = timestamp_key_generation_end - timestamp_key_generation_start
	delta_authentication = timestamp_authentication_end - timestamp_authentication_start
	delta_message = timestamp_message_end - timestamp_message_start
	return(delta_key_generation,delta_authentication,delta_message)