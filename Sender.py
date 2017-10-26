# Author - Shivam Kapoor
# Github Link -https://github.com/ConanKapoor/Basic-Digital-Envelope

import uuid
import hashlib

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
            return x

def hashing(word):
    # uuid is used to generate a random number
    salt = uuid.uuid4().hex
    return hashlib.sha256(salt.encode() + word.encode()).hexdigest() + ':' + salt

def input_data():
    p = int(input("Please Enter value of p [Prime number. eg. 17]: "))
    q = int(input("Please Enter value of q [Prime number. eg. 11]: "))
    if p == q:
        print("Value of p and q can't be equal. Please use different prime numbers.")
        input_data()
        exit()

def RSAKeyGeneration(p,q):
    n = p * q
    totient_func = (p-1)*(q-1)

    flag = 1
    while(flag):
        e = int(input("Please select value of e: "))
        if gcd(totient_func,e) != 1:
            print("GCD of totient_func and e should be 1 (Relatively prime).")
            print("Please try again!")
            break;
        flag = 1

    while(e>1 and e<totient_func):
        d = modInverse(e,totient);

    print("Public Key here is - PU(%s,%s)" %(e,n))
    print("Private Key here is - PR(%s,%s)" %(d,n))
    return n,e,d
