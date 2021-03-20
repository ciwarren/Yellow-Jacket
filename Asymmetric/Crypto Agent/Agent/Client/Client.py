#Client
#Sources:
	#https://www.geeksforgeeks.org/primitive-root-of-a-prime-number-n-modulo-n/
	#https://en.wikipedia.org/wiki/Diffie%E2%80%93Hellman_key_exchange
	#https://stackoverflow.com/questions/15285534/isprime-function-for-python-language
	#https://asecuritysite.com/encryption/diffie_py
from socketserver import socket
import random
from math import sqrt
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hmac

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
def receiveMessageEncryptedECB(clientSocket, secret):
	messageHeader = decryptMessageECB(clientSocket.recv(256), secret)
	messageHeader = messageHeader.decode('utf-8')
	messageLength = int(messageHeader.strip())
	message = decryptMessageECB(clientSocket.recv(messageLength), secret)
	message = message.decode('utf-8')
	message = str(message)
	return message


def sendMessageEncryptedECB(clientSocket, message, secret):
	message = str(message)
	message = encryptMessageECB (message.encode('utf-8'), secret)
	messageHeader = encryptMessageECB(f"{len(message):<{HEADERLENGTH}}".encode('utf-8'), secret)
	clientSocket.send(messageHeader + message)
	return

def decryptMessageECB(payload, secret):
	secret = secret.encode('utf-8')
	cipher = AES.new(secret, AES.MODE_ECB)
	data = unpad(cipher.decrypt(payload), 256)
	return data

def encryptMessageECB(data, secret):
	secret = secret.encode('utf-8')
	cipher = AES.new(secret, AES.MODE_ECB)
	data = pad(data,256)
	payload = cipher.encrypt(data)
	return payload


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




def cryptoSessionStart(clientSocket, secret, HMACKey, N1):
	#N2+N1, N2
	#TODO: Recieve message encrypted with client publickey
	message = receiveMessageEncryptedECB(clientSocket, secret)
	variables = message.split(",")
	serverAuth = int(variables[0])
	N2 = int(variables[1])
	HMACToCheck = variables[2]
	HMACToComp = HMACGen(HMACKey, N2)
	
	if HMACToCheck != HMACToComp:
		return "fail" 

	if (serverAuth - N1) != N2:
		return "fail"

	print ("Server Has Been Authed")

	N3 = random.getrandbits(128)
	message = f'{N2+N3},{N3},{HMACGen(HMACKey,N3)}'
	sendMessageEncryptedECB(clientSocket, message, secret)

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
	lIP = '192.168.163.130'
	PORTS = []
	PORTS.extend(range(10000, 11000))
	lPort = random.choice(PORTS)
	localAddress = (lIP, lPort, )
	IP = "192.168.163.131"
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

	status = "PHASE1"

	#message = f'{hostname},{N1},{status},{HMACGen(HMACKey,hostname)}'
	#TODO: Send Client Public Key in this message
	message = f'{hostname},{N1}'
	#TODO: Message needs to be encrypted with the servers public key.
	sendMessage(clientSocket, message)

	status = receiveMessage(clientSocket)

	if "PHASE1" in status:
		#TODO: Rework this phase part
		cryptoVariables = cryptoSessionStart(clientSocket, N1)
	'''
	if "PHASE2" in status:
		secret = file.readline()
		cryptoVariables = cryptoSessionStart(clientSocket, secret, N1)
	'''
	if "fail" in cryptoVariables:
		print("Failed to authenticate with server")

	sendMessageEncryptedCBC(clientSocket, log, cryptoVariables["sessionKey"], cryptoVariables["IV"])

	print(f'Sent message: {log}')

	clientSocket.close()

main("This is a test")