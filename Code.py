# Author - Shivam Kapoor
# Github Link -https://github.com/ConanKapoor/Basic-Digital-Envelope

import uuid
import hashlib
from caesarcipher import CaesarCipher

# Function to compute gcd of 2 numbers
def gcd(a,b):
    while(b):
        a, b = b, (a % b)
    return a

# Function to compute modulo inverse
def modInverse(a,b):
    a = a % b
    for i in range(1,b):
        if ((a*i) % b) == 1:
            return i

# Function to perform hashing using  hashlib and uuid
def hashing(word):
    # uuid is used to generate a random number
    salt = uuid.uuid4().hex
    return hashlib.sha256(salt.encode() + word.encode()).hexdigest() + ':' + salt

# Function to compare hash values
def CompareHash(hashed_msz,new_msz):
    password, salt = hashed_msz.split(':')
    return password == hashlib.sha256(salt.encode() + new_msz.encode()).hexdigest()

# Function to input data
def Input_data():
    p = int(input("Please Enter value of p [Prime number. eg. 17]: "))
    q = int(input("Please Enter value of q [Prime number. eg. 11]: "))

    # Race condition
    if p == q:
        print("Value of p and q can't be equal. Please use different prime numbers.")
        Input_data()
        exit()

    # Common key to be shared between respondents for symmetric communication.
    common_key = int(input("Please enter the common key to be shared: "))
    return p,q,common_key

# RSA Key generation process
def RSAKeyGeneration(p,q):
    n = p * q
    totient_func = (p-1)*(q-1)

    flag = 1
    while(flag):
        e = int(input("Please select value of e: "))
        if gcd(totient_func,e) != 1:
            print("GCD of totient_func and e should be 1 (Relatively prime).")
            print("Please try again!")
            continue;
        flag = 0

    if e>1 and e<totient_func:
        d = modInverse(e,totient_func);
        print("Value of computed d is: %s" %(d))


    print("Public Key here is - PU(%s,%s)" %(e,n))
    print("Private Key here is - PR(%s,%s)" %(d,n))
    return n,e,d

# RSA Encryption process
def RSAEncryption(e,n,common_key):
    Cipher = (common_key**e) % n
    print("Cipher text generated is: %s" %(Cipher))
    return Cipher

# Symmetric Encryption using shared common key
def SymmetricEncryption(common_key):
    msz = input("Please enter the message to be shared: ")
    hashed_msz = hashing(msz)
    print("\nHash for message given is: %s" %(hashed_msz))

    cipher = CaesarCipher(msz, offset= common_key)
    encoded_msz = cipher.encoded
    print("\nSymmetrically encrypted data is: %s" %(encoded_msz))
    return hashed_msz, encoded_msz

# RSA Decryption Process
def RSADecryption(n,d,Cipher,common_key):
    Decipher = (Cipher**d) % n
    print("\nDeciphered Common key is %s" %(Decipher))
    print("\nWhich match the sent key - %s" %(common_key))
    return Decipher

# Symmetric Decryption using shared common key
def SymmetricDecryption(hashed_msz,encoded_msz,Decipher):
    decipher = CaesarCipher(encoded_msz, offset= Decipher)
    decoded_msz = decipher.decoded
    print("\nDecrypted message is: %s" %(decoded_msz))

    print("\n##### RESULT #####")
    if CompareHash(hashed_msz,decoded_msz):
        print("\n--> The hash match. The data is correct.")
    else:
        print("\n-->The hash is different. The data is incorrect")

##############################################################################################
print("\tWelcome to Digital Envelope Program.\n")

print("##### DATA INPUT #####")
p,q,common_key = Input_data()

print("\n##### KEY GENERATION PROCESS #####")
n,e,d = RSAKeyGeneration(p,q)

print("\n\n<------- Encryption Process starts here ------->")
print("\n##### RSA ENCRYPTION PROCESS #####")
Cipher = RSAEncryption(e,n,common_key)

print("\n##### SYMMETRIC ENCRYPTION PROCESS #####")
hashed_msz,encoded_msz = SymmetricEncryption(common_key)

print("\n\n<------- Decryption Process starts here ------->")
print("\n##### RSA DECRYPTION PROCESS #####")
Decipher = RSADecryption(n,d,Cipher,common_key)

print("\n##### SYMMETRIC DECRYPTION PROCESS #####")
SymmetricDecryption(hashed_msz,encoded_msz,Decipher)
