#author Stephanos Jemaneh

import socket
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from Cryptodome import Random
from Cryptodome.Hash import SHA3_256

#Generate private and public keys
random_generator = Random.new().read
private_key = RSA.generate(2048, random_generator)
public_key = private_key.publickey()

#Prints statements includes publickey
print("Server started!!!")
print("________________________________________________________________")
#removes the characters \r and \n from public_key.exportKey()
mypublickey = public_key.exportKey().decode().replace("\r\n", '')
print(mypublickey)

#Creates a TCP socket
mysocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#Gets the hostname
hostname = socket.gethostname()
#Gets the host ip
host = socket.gethostbyname(hostname)  
port = 7777

print("Host is: "+host)
# Prevents socket.error: [Errno 98] Address already in use
mysocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
print("Binding now")
#Bind the socket to the server ip and port
mysocket.bind((host, port))
print("Listening now")
#Max connections is 5
mysocket.listen(5)
print("Accepting")

encrypt_str = "Encrypted_message=".encode()

#error handeling if it cant accept a connection it would print the error statement
try:
    c, addr = mysocket.accept()
except Exception as error:
    print(error)
    
while True:
    data = c.recv(2048)
    if encrypt_str not in data:
        #if "encrypted_message=" isnt in data it will decode data and removes \r and \n
        data = data.decode()
        data = data.replace("\r\n", '')
    if data == "Client: OK":
        #sends the public key to the client
        c.send("Public_key=".encode() + public_key.exportKey())
        print("Public key sent to client.\n")
    elif data == "Quit":
        print("Quit command detected from client")
        #stops the while true loop
        break
    elif encrypt_str in data:
        #you'll see 'Encrypted_message=*the encrypted message part*'
        print("Incoming message from the client.")
        print("Received:\n"+str(data))
        print("________________________________________________________________")
        #removes the encrypt_str by calling the lenght which is 18 characters long
        data = data[len(encrypt_str):len(data)]
        #prints out the Encrypted_message= removed and prints the encrypted message without Encrypted_message= in the bytes
        print("Removing Encrypted_message= in the bytes.")
        print("Received:\nEncrypted message = "+str(data))
        print("________________________________________________________________\n")
        #uses the private key with the sha3_256 hash algoritm when hashalgoritm isnt defined it will use sha1 as default. THIS IS A SECURITY RISK!!!
        cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA3_256)
        decrypted = cipher.decrypt(data)
        #sends the encoded string (bytes) back to the client
        c.send("Server: OK".encode())
        #prints out the decrypted message
        print("Decrypted message = " + str(decrypted) + "\n")

#Sends the encoded string (bytes) to the server and closes the socket
c.send("Server stopped\n".encode())
print("Server stopped")
c.close()
