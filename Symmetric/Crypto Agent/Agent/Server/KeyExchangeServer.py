#Key Exchange Client

from socketserver import socket
import random
import hashlib

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
 
def isPrime(n):
	if n == 2 or n == 3: return True
	if n < 2 or n%2 == 0: return False
	if n < 9: return True
	if n%3 == 0: return False
	r = int(n**0.5)
	f = 5
	while f <= r:
		if n%f == 0: return False
		if n%(f+2) == 0: return False
		f +=6
	return True

def genPrime(min, max):
	primes = [i for i in range(min,max) if isPrime(i)]
	p = random.choice(primes)
	return p


  
# Utility function to store prime 
# factors of a number  
def findPrimefactors(s, n) : 
  
    # Print the number of 2s that divide n  
    while (n % 2 == 0) : 
        s.add(2)  
        n = n // 2
  
    # n must be odd at this po. So we can   
    # skip one element (Note i = i +2)  
    for i in range(3, int(sqrt(n)), 2): 
          
        # While i divides n, print i and divide n  
        while (n % i == 0) : 
  
            s.add(i)  
            n = n // i  
          
    # This condition is to handle the case  
    # when n is a prime number greater than 2  
    if (n > 2) : 
        s.add(n)  
  
# Function to find smallest primitive  
# root of n  

def findPrimitive( n) : 
    s = set()  

    # Check if n is prime or not  
    if (isPrime(n) == False):  
        return -1
  
    # Find value of Euler Totient function  
    # of n. Since n is a prime number, the  
    # value of Euler Totient function is n-1  
    # as there are n-1 relatively prime numbers. 
    phi = n - 1
  
    # Find prime factors of phi and store in a set  
    findPrimefactors(s, phi)  
  
    # Check for every number from 2 to phi  
    for r in range(2, phi + 1):  
  
        # Iterate through all prime factors of phi.  
        # and check if we found a power with value 1  
        flag = False
        for it in s:  
  
            # Check if r^((phi)/primefactors) 
            # mod n is 1 or not  
            if (pow(r, phi // it, n) == 1):  
  
                flag = True
                break
              
        # If there was no power with value 1.  
        if (flag == False): 
            return r  
  
    # If no primitive root found  
    return -1

def main(clientSocket):
	message = f'PHASE1'
	sendMessage(clientSocket, message)
	'''
	message = receiveMessage(clientSocket)
	diffeVars = message.split(",")
	p = int(diffeVars[0])
	g = int(diffeVars[1])
	'''
	min, max = 100000, 999999
	p = genPrime(min, max)
	g = findPrimitive(p)
	message =  f'{p},{g}'
	sendMessage(clientSocket, message)

	try:
		isPrime(p)

	except: 
		print("Invalid Parameters Received!")
	
	b = random.randint(1000000, 2000000)
	B = (g**b) % p

	sendMessage(clientSocket, B)

	A = int(receiveMessage(clientSocket))

	s = (A**b) % p

	secret = hashlib.sha256(str(s).encode()).hexdigest()
	x = slice(32)
	
	secret = secret[x]

	return secret