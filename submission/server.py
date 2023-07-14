import socket
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from base64 import b64decode

SERVER_IP = socket.gethostbyname(socket.gethostname())
SERVER_PORT = 5678

print('Server is listening')
print("generating RSA pair")
privateKey = RSA.generate(1024)
publicKey = privateKey.public_key()

def main():
    with socket.socket(socket.AF_INET , socket.SOCK_STREAM) as s:
        s.bind((SERVER_IP, SERVER_PORT))
        s.listen(1)
        conn,addr = s.accept()
        print("Connection received")
        print(f'Sending public key to :{addr}')
        with conn:
            while(True):
                print("Writing RSA pair into file")
                conn.send(generateRSAPair())
                print("Pair written")
                publicKeySentMessage = conn.recv(1024)
                print(publicKeySentMessage.decode())
                break
        conn,addr = s.accept()
        with conn:
            while(True):
                encKey = conn.recv(1024)
                print("Received encrypted key, decrypting ...")
                decKey = decryptRSA(encKey)
                print("Key decrypted, sending to client ...")
                conn.send(decKey)
                print("Decrypted key sent")
                break

def generateRSAPair():
    with open('keyPair.key','wb') as f:
        f.write(publicKey.export_key('PEM') + b"\n" + privateKey.export_key('PEM'))
    return publicKey.export_key('PEM')

def decryptRSA(ciphertext):
    cipher_rsa = PKCS1_OAEP.new(privateKey)
    plaintext = cipher_rsa.decrypt(b64decode(ciphertext))
    return plaintext

if __name__ == "__main__":
    main()


