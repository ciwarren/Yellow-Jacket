#Main Connection Handler
from socketserver import socket
import select
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import CryptoSessionStart
import hashlib, rsa

#Need to import database.py, KeyExchangeServer.py, CryptoSessionStart.py
HEADERLENGTH = 10

sessionKeys = {}
clientPublicKeys = {}
IVs = {}

	#Load RSA Server Private 
try:
	with open('private.pem', mode='rb') as privateFile:
		keydata = privateFile.read()
	privateKey = rsa.PrivateKey.load_pkcs1(keydata)

	with open('public.pem', mode='rb') as publicFile:
		keydata = publicFile.read()
	publicKey = rsa.PublicKey.load_pkcs1(keydata)
	
except:
	print("Generating keys, could not find them locally!")
	(publicKey, privateKey) = rsa.newkeys(512)
	
	file = open("public.pem", "w")
	file.write(publicKey.save_pkcs1().decode('utf-8'))
	file.close()

	file = open("private.pem", "w")
	file.write(privateKey.save_pkcs1().decode('utf-8'))
	file.close()
	
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


#Used for all conversation pre CryptoSessionStart
def receiveMessage(clientSocket):
	messageHeader = clientSocket.recv(HEADERLENGTH)
	if not len(messageHeader):
		return False
	messageLength = int(messageHeader.decode('utf-8').strip())
	message = clientSocket.recv(messageLength)
	message = message.decode('utf-8')
	message = str(message)
	return message

def sendMessage(clientSocket, message):
	message = str(message)
	message = message.encode('utf-8')
	messageHeader = f"{len(message):<{HEADERLENGTH}}".encode('utf-8')
	clientSocket.send(messageHeader + message)
	return

def receiveMessageRSA(clientSocket):
	messageHeader = rsa.decrypt(clientSocket.recv(256), privateKey)
	messageHeader = messageHeader.decode('utf-8')
	messageLength = int(messageHeader.strip())
	message = rsa.decrypt(clientSocket.recv(messageLength), privateKey)
	message = message.decode('utf-8')
	message = str(message)
	return message

def sendMessageRSA(clientSocket, message, source):
	clientPublic = clientPublicKeys[source]
	message = str(message)
	messageTotal = []
	while len (message) > 0:
		messageTotal.append(rsa.encrypt(message[0:min(53,len(message))].encode('utf-8'), serverPublicKey))
		message = message[min(53,len(message)):]
	messageTotal = ','.join(messageTotal)
	messageHeader = rsa.encrypt(f"{len(messageTotal):<{HEADERLENGTH}}".encode('utf-8'), serverPublicKey)
	clientSocket.send(messageHeader + messageTotal)
	return


#Used for all conversation post CryptoSessionStart
def receiveMessageEncrypted(clientSocket, source):
	IV = IVs[source]
	sessionKey = sessionKeys[source]
	messageHeader = decryptMessage(clientSocket.recv(256), sessionKey, IV)
	messageHeader = messageHeader.decode('utf-8')
	messageLength = int(messageHeader.strip())
	signature = clientSocket.recv(64)
	message = clientSocket.recv(messageLength)
	message = decryptMessage(message, sessionKey, IV)
	message = message.decode('utf-8')
	message = str(message)
	print(message)
	return message

def sendMessageEncrypted(clientSocket, message, source):
	IV = IVs[source]
	sessionKey = sessionKeys[source]
	message = str(message)
	message = encryptMessage(message.encode('utf-8'), sessionKey, IV)
	messageHeader = encryptMessage(f"{len(message):<{HEADERLENGTH}}".encode('utf-8'), sessionKey, IV)
	clientSocket.send(messageHeader + message)
	return

def decryptMessage(payload, sessionKey, IV):
	sessionKey = sessionKey.encode('utf-8')
	IV = IV.encode('utf-8')
	cipher = AES.new(sessionKey, AES.MODE_CBC, IV)
	data = unpad(cipher.decrypt(payload), 256)
	return data

def encryptMessage(data, sessionKey, IV):
	sessionKey = sessionKey.encode('utf-8')
	IV = IV.encode('utf-8')
	cipher = AES.new(sessionKey, AES.MODE_CBC, IV)
	data = pad(data,256)
	payload = cipher.encrypt(data)
	return payload




def main():

	#serverConfig = interpretConfig("/var/Agent/Server/serverConfig.txt")
	#lIP = serverConfig[ServerIP]
	#lPort = serverConfig[ServerPort]
	lIP = "192.168.0.100"
	lPort = 1337
	localAddress = (lIP,lPort, )
	serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	serverSocket.bind((localAddress))
	serverSocket.listen()
	sockets_list = [serverSocket]
	clients = {}

	#secrets = database.secretTable()


	#Used for client public keys to encrypt messages to them

	secrets = {}
	print ("\n")



	while True:

		read_sockets, _, exception_sockets = select.select(sockets_list, [], sockets_list)
		for notified_socket in read_sockets:
			# If notified socket is a server socket - new connection, accept it
			if notified_socket == serverSocket:
				clientSocket, clientAddress = serverSocket.accept()
                #First message format is (Hostname, N1, status)
				#TODO: Message needs to be decrypted by Server Private Key
				message = receiveMessage(clientSocket)
				variables = message.split(",")
				source = variables[0]
                #N1 is used for CryptoSessionStart
				N1 = int(variables[1])
				#TODO: Make sure the line below will work for next message
				clientPublicKeys[source] = rsa.PublicKey.load_pkcs1(variables[2])
				serverPublicKey = rsa.PublicKey.load_pkcs1(keydata)
				#status = variables[2] Not using because of commented out code below
				'''
				Moving Elsewhere
				HMACToCheck = variables[3]
				HMACToComp = HMACGen(HMAC[source],source)

				if HMACToCheck != HMACToComp:
					continue 
				'''

				'''
				if source in secrets and "PHASE2" in status:
             		#If a long-term secret exists in the database
					sockets_list.append(clientSocket)
					clients[clientSocket] = source
					print('Accepted new connection from {}:{}, source: {}'.format(*clientAddress, source))
	                #Retrieve secret
					sourceSecret = secrets[source]
	                #Generate session key and n2, n3 for source
					cryptoVariables = CryptoSessionStart.main(clientSocket, sourceSecret, N1)
					sessionKeys[source] = cryptoVariables["sessionKey"]
					IVs[source] = cryptoVariables["IV"]
	                 
				else:
	        		#If no long-term secret exists, create one
					sourceSecret = KeyExchangeServer.main(clientSocket)
	            	#Enter secret in database for next restart
					#database.createEntry(table = sources, source = source, secret = sourceSecret)
	            	#Update current dictonary
					secrets[source] = sourceSecret
					sockets_list.append(clientSocket)
					clients[clientSocket] = source
					print('Accepted new connection from {}:{}, source: {}'.format(*clientAddress, source))
					cryptoVariables = CryptoSessionStart.main(clientSocket, sourceSecret, N1)
					if  "abort connection" in cryptoVariables:
						print ("Connection Aborted")
						return
					sessionKeys[source] = cryptoVariables["sessionKey"]
					IVs[source] = cryptoVariables["IV"]

					print(f'sessionKey: {sessionKeys[source]}, IV: {IVs[source]}')
					'''



				#If no long-term secret exists, create one
	            #Enter secret in database for next restart
				#database.createEntry(table = sources, source = source, secret = sourceSecret)
	            #Update current dictonary
				sockets_list.append(clientSocket)
				clients[clientSocket] = source
				print('Accepted new connection from {}:{}, source: {}'.format(*clientAddress, source))
				#TODO: Change crypto variables start to match flow diagram
				cryptoVariables = CryptoSessionStart.main(clientSocket, source, clientPublicKeys[source], privateKey, N1)
				if  "abort connection" in cryptoVariables:
					print ("Connection Aborted")
					return
				sessionKeys[source] = cryptoVariables["sessionKey"]
				IVs[source] = cryptoVariables["IV"]
				print(f'sessionKey: {sessionKeys[source]}, IV: {IVs[source]}')

			else:
             	# Get source by notified socket, so we will know who sent the message
				source = clients[notified_socket]
				message = receiveMessageEncrypted(notified_socket, source)

				if message is False:
					print('Closed connection from: {}'.format(clients[notified_socket]))

                    # Remove from list for socket.socket()
					sockets_list.remove(notified_socket)

                    # Remove from our list of users
					del clients[notified_socket]

					continue

                
				print(f'Received message from {source}: {message}\n')



                #database.formatLog(source = source, logData = message)

				sockets_list.remove(notified_socket)
				del clients[notified_socket]



		for notified_socket in exception_sockets:


            # Remove from list for socket.socket()
			sockets_list.remove(notified_socket)

            # Remove from our list of users
			del clients[notified_socket]

main()