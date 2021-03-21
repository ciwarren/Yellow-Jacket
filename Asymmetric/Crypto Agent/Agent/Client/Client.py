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


def sendMessageEncryptedCBC(clientSocket, message, sessionKey, IV):
	message = str(message)
	message = encryptMessageCBC(message.encode('utf-8'), sessionKey, IV)
	messageHeader = encryptMessageCBC(f"{len(message):<{HEADERLENGTH}}".encode('utf-8'), sessionKey, IV)
	clientSocket.send(messageHeader + message)
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
	messageHeader = rsa.decrypt(clientSocket.recv(256), privateKey)
	messageHeader = messageHeader.decode('utf-8')
	messageLength = int(messageHeader.strip())
	message = rsa.decrypt(clientSocket.recv(messageLength), privateKey)
	message = message.decode('utf-8')
	message = str(message)
	return message

def sendMessageRSA(clientSocket, message, serverPublicKey):
	message = str(message)
	message = rsa.encrypt(message.encode('utf-8'), serverPublicKey)
	messageHeader = rsa.encrypt(f"{len(message):<{HEADERLENGTH}}".encode('utf-8'), serverPublicKey)
	clientSocket.send(messageHeader + message)
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
	#TODO: Recieve message encrypted with client publickey
	message = receiveMessageRSA(clientSocket, privateKey)
	variables = message.split(",")
	serverAuth = int(variables[0])
	N2 = int(variables[1])

	if (serverAuth - N1) != N2:
		return "fail"

	print ("Server Has Been Authed")

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
	(publicKey, privateKey) = rsa.newkeys(512)
	with open('serverPublic.pem', mode='rb') as publicFile:
		keydata = publicFile.read()
	serverPublicKey = rsa.PublicKey.load_pkcs1(keydata)
	lIP = '192.168.1.159'
	PORTS = []
	PORTS.extend(range(10000, 11000))
	lPort = random.choice(PORTS)
	localAddress = (lIP, lPort, )
	IP = "192.168.1.158"
	PORT = 1337
	hostname = "client1"
	clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	clientSocket.bind((localAddress))
	clientSocket.connect((IP, PORT))
	N1 = random.getrandbits(128)

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


	cryptoVariables = cryptoSessionStart(clientSocket, N1, privateKey, serverPublicKey)
	
	if "fail" in cryptoVariables:
		print("Failed to authenticate with server")

	sendMessageEncryptedCBC(clientSocket, log, cryptoVariables["sessionKey"], cryptoVariables["IV"])

	print(f'Sent message: {log}')

	clientSocket.close()

main("This is a test")