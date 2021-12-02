from rijndael_aes import R_AES
import secrets

print("----------------------------------------------------------")
print("Cryptography Fall 2021")
print("One Block AES 128 Demonstration")
print("Written from scratch in python")
print("----------------------------------------------------------")

print("Generating Key: ")
key = []

for x in range(16):
    key.append(int(secrets.token_hex(1), 16))
print("Key: " + str(key))

aes = R_AES(key)

while(True):
    encrypt_decrypt = int(input("1) Encrypt\n2) Decrypt\n..."))
    if encrypt_decrypt == 1:
        plaintext = input("Input 32 character text to encrypt (no spaces. Only hex)...")
        print(aes.encrypt_one_block(plaintext))
    else:
        plaintext = input("Input 32 character text to decrypt (no spaces. Only hex)...")
        print(aes.decrypt_one_block(plaintext))

