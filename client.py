#author Stephanos Jemaneh

import socket
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from Cryptodome.Hash import SHA3_256

server = socket.socket()
host = "145.109.167.21"
port = 7777

def general():
    #Tell server that connection is OK
    msg = "Client: OK".encode()
    server.sendall(msg)

    #Receive public key string from server and decodes it to string format
    server_string = server.recv(2048)
    server_string = server_string.decode()

    #Removing extra characters and prints the public key
    server_string = server_string.replace("Public_key=", '')
    server_string = server_string.replace("\r\n", '')
    print("________________________________________________________________\n")
    print(server_string)
    print("________________________________________________________________\n")
    #Convert the server_string string to a key
    server_public_key = RSA.importKey(server_string)
    
    #Simple print statement letting the user know how to quit the program
    print("Type quit to stop the program!")
    
    maxAmountofBytes = 190
    
    while True:
        #ask input from the user
        print("Your sentence that's going to be encrypted: ", end='')
        message = input().encode()
        #decodes the message to a string format and convert the word entirely lowercase to match if quit was not typed
        if message.decode().lower() != "quit":
            #because we use RSA2048 and use the SHA3_256 the max amout of bytes = 190. a nice explained table at: https://crypto.stackexchange.com/questions/42097/what-is-the-maximum-size-of-the-plaintext-message-for-rsa-oaep
            #this loop checks if the message is lower than 190
            while len(message) > maxAmountofBytes:
                print("\nOh no your sentence was to long to be encrypted!\nYour sentence was " + str(len(message)) +
                      " characters long. The maximum amount of characters is 190! You need " + str(len(message)-maxAmountofBytes) + " less characters in your sentence\n")
                print("Try a new sentence!: ", end='')
                message = input().encode()
            if message.decode().lower()  == "quit":
                print("Quit was typed trying to close server and client sockets")
                #calls the function closesocket and breaks the loop
                closesocket() 
                break             
            #uses the public key with the sha3_256 hash algoritm when hashalgoritm isnt defined it will use sha1 as default. THIS IS A SECURITY RISK!!!
            cipher = PKCS1_OAEP.new(server_public_key, hashAlgo=SHA3_256)
            encrypted = cipher.encrypt(message)
            #sends the "encrypted_message=" encoded in to bytes UNENCRYPTED with the encrypted message
            server.sendall("Encrypted_message=".encode()+encrypted)
        #decodes the message to a string format and convert the word entirely lowercase to match if quit has been typed
        elif message.decode().lower()  == "quit":
            print("Quit was typed trying to close server and client sockets")
            #calls the function closesocket and breaks the loop
            closesocket()  
            break
        #Gets the server's response if so it prints the server has decrypted the message
        server_response = server.recv(2048)
        server_response = server_response.decode() 
        server_response = server_response.replace("\r\n", '')
        if server_response == "Server: OK":
            print("Server decrypted message successfully") 

def closesocket():
    #Sends the encoded string (bytes) "Quit" to the socket, receives from the server that the server stopped and calls the closeserver() function
    server.sendall("Quit".encode())
    print(server.recv(2048).decode().replace("\r\n", '')+"Client stopped")  # Quit server response
    closeserver()
    
def closeserver():
    #closes the socket
    server.close()

try:
    #tries to connect to the server
    server.connect((host, port))
    #Simple print statement letting the user now its client connected with the server
    print("Beep Boop! Client connected with the server!")
    general()
except Exception as error:
    #when the client can't connect to the server it prints out an error statement
    print("connecting socket failed:\n" + str(error))
    closeserver()

