# Author - Shivam Kapoor
# Github Link -

def gcd(a,b):
    while(b):
        a, b = b, (a % b)
    return a
