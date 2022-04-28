import math
import hashlib
import random
import base64
import os
from multiprocessing import Pool
from tkinter import filedialog
#random witnesses for Miller Rabin Test
die = random.SystemRandom()  # A single dice.
#Verify the Signature
def Verify_Signature(Cipher,signature,p,q,e):
    try:
        md5 = RSADec(signature,p,q,e) # decrypting the Signature
        Cipher_md5 = hashlib.md5(Cipher.encode()).hexdigest() # md5sum for Cipher
        if md5 == Cipher_md5: # verify
            return True,md5
        else:
            return False,False
    except Exception as e:
        return False,False

# singing the Text
def Signature(msg,N,d):
    md5 = hashlib.md5(msg.encode()).hexdigest()
    signature = RSAEnc(md5,N,d) # encrypt Signature

    return signature
    pass
#Base64 Encoding
def Encode(msg):
    try:
        message_bytes = msg.encode('ascii')
        base64_bytes = base64.b64encode(message_bytes)
        base64_message = base64_bytes.decode('ascii')
        return base64_message
    except Exception as e:
        print(e)


#Base64 decoding
def decode (msg):
    try:
        base64_bytes = msg.encode('ascii')
        message_bytes = base64.b64decode(base64_bytes)
        message = message_bytes.decode('ascii')
        return message
    except Exception as e:
        print(e)


#Get Desktop path
def get_Desktop():
    desktop = os.path.join(os.path.join(os.path.expanduser('~')), 'Desktop')
    return desktop

# Sing Miller Rabin test
def single_test(n, a):
    exp = n - 1

    while not exp & 1:
        exp >>= 1

    if pow(a, exp, n) == 1:

        return True

    while exp < n - 1:
        if pow(a, exp, n) == n - 1:

            return True
        exp <<= 1


    return False

#Miller Rabin Test
def miller_rabin(n, k=100):
    for i in range(k):
        a = die.randrange(2, n - 1)
        if not single_test(n, a):
            return False

    return True

# calculate the multiplicative inverse of a number
def multiplicativeInverse(a, m):
    for x in range(1, m):
        if (((a % m) * (x % m)) % m == 1):
            return x
    return -1

# Euclidean Algorithm
def EuclidExtended(mod, b):
    # Base Case
    if mod == 0:
        return b, 0, 1

    gcd, x1, y1 = EuclidExtended(b % mod, mod)
    x = y1 - (b // mod) * x1
    y = x1
    return gcd, x, (y%mod)
# GCD Calculator
def gcd(a,b):
    if(b==0):
        return a
    else:
        return gcd(b,a%b)
# The main RSA Encryption method
def RSAEnc(message,N,e):
    CipherText=""
    for i in range(len(message)):
        c = pow(ord(message[i]),e,N) # m^e mod N
        CipherText+=str(hex(c)) # Convert to hex
        if i != len(message)-1:
            CipherText+=" "



    return Encode(CipherText) # Encode the cipher and return the output
# The main RSA Decryption method
def RSADec(message,p,q,d):
    print("Decrypting....")
    N=q*p # Calculate N
    message = decode(message) # Decoding Base64
    msg = message.split(' ') #Deffentiation
    PlainText=""

    for i in msg:

        m = pow(int(str(i),16), d, N) #Decrypt m^d mod N
        PlainText+=chr(m)



    return PlainText
# Calculate ed = 1 mod (p-1)(q-1)
def PivKey(e,p,q):
    print("Calculating D")
    phi = (p-1)*(q-1)
    d = EuclidExtended(int(phi),e)[2]
    return d




#Generating Keys p,q
def KeyGen():
    Proceed=False
    e = 65537 # e, can be generated 1<e<phi. gcd(e,phi) = 1,  but 65537 is already  gcd(e,phi) = 1 with every number.
    print("Generating P , Q ......")
    for i in range(pow(1024,2)//2):
        p=random.getrandbits(512) # random 512 but size number for p
        if miller_rabin(p): # apply rabin miller test
            Proceed = True # if the number is prime
        if Proceed == True:
                Proceed = False
                break
    for i in range(pow(1024,2)//2):
        q = random.getrandbits(512)# random 512 but size number for q
        if miller_rabin(q):# apply rabin miller test
                Proceed = True # if the number is prime
        if Proceed == True:
                Proceed = False
                break

    return p,q,e

if __name__ == '__main__':
    Greeting_Message="hello, this is a program to Encrypt and decrypt using RSA algorithm.\n[+] Enter 1 to generate RSA encryption Keys\n[+] Enter 2 to encrypt a message\n[+] Enter 3 to encrypt a file\n[+] Enter 4 to decrypt a message\n[+] Enter 5 to decrypt a file\n[+] Enter 6 show public & private Keys"
    Deskpath = get_Desktop()
    try:
        with open('RSA Public Kyes.txt', 'r') as file:
            Keys = file.read().split('\n\n')
            e=int(Keys[0])
            N = int(Keys[1])
        with open('RSA Private Kyes.txt', 'r') as file:
            Keys = file.read().split('\n\n')
            p = int(Keys[0])
            q = int(Keys[1])
            phi = int(Keys[3])
            d = int(Keys[5])
    except Exception as e:
        pass
    while(True):
        print(Greeting_Message)
        choice = int(input("-> "))
        if choice == 1:
            try:
                path = os.getcwd()
                p,q,e = KeyGen()
                with open('RSA Private Kyes.txt','w+') as file:
                    file.write(str(p))
                    file.write('\n\n')
                    file.write(str(q))
                    file.write('\n\n')
                    file.write(str(e))
                    file.write('\n\n')
                    file.write(str((p-1)*(q-1)))
                    file.write('\n\n')
                    file.write(str(p*q))
                    file.write('\n\n')
                    file.write(str(PivKey(e,p,q)))
                    print("RSA Keys was generated Successfuly")

                    with open('RSA Public Kyes.txt', 'w+') as Pubfile:

                        Pubfile.write(str(e))
                        Pubfile.write('\n\n')
                        Pubfile.write(str(p*q))
            except Exception as e:
                print(e)
        elif choice ==2:
            Cipher = RSAEnc(input("enter a message: "), N, e)
            signature = Signature(Cipher ,N,d)
            print("Encrypted Message: ", Cipher)
            print("Signature : " + signature)
            print("Signature Verify : " + str(Verify_Signature(Cipher,signature,p, q, e)))

        elif choice == 3:
            path = str(filedialog.askopenfilename(initialdir=Deskpath, title='Select a file to Encrypt')).strip()
            with open(path,'r') as file:
                data = file.read()
                CipherText = RSAEnc(data,N,e)
                signature = Signature(CipherText, N, d)
                with open(path,'w') as file2:
                    file2.write(CipherText+"\n\n"+signature)
                print("Ecnryption Process Completed")
                Verify, hash = Verify_Signature(CipherText, signature, p, q, e)
                print("Signature Verify : " + str(Verify))
        elif choice == 4:
            CipherText = str(input("Enter Cipher Text + signature (No space) : "))
            Cipher = CipherText[:len(CipherText)-11036]
            signature = CipherText[len(CipherText)-11036:]
            Verify, hash = Verify_Signature(Cipher, signature, p, q, e)
            if Verify == True:

                PlainText = RSADec(Cipher, p, q, d)
                print("signature : \t\t\t   " + hash)
                print("Cihper Text hash : " + hashlib.md5(RSAEnc(PlainText, N, e).encode()).hexdigest())
                print("Verity : True")
                print("Deryption Process Completed")
                print("[+] ============================= Decrypted Message ============================= [+]\n"+PlainText+"\n[+] ============================= Decrypted Message ============================= [+]\n\n")
            else:
                print("signature is Manipulated, Aborting ....")
                exit(1)
            pass
        elif choice == 5:
            path = str(filedialog.askopenfilename(initialdir=Deskpath, title='Select a file to Encrypt')).strip()
            with open(path,'r') as file:
                data = file.read()
                RealData = data.split("\n\n")
                Verify,hash = Verify_Signature(RealData[0],RealData[1],p,q,e)
                if Verify == True:
                    PlainText = RSADec(data,p,q,d)
                    print("signature :        " + hash)

                    print("Cihper Text hash : "+ hashlib.md5(RSAEnc(PlainText,N,e).encode()).hexdigest())
                    print("Verify : True")
                    with open(path,'w') as file2:
                        file2.write(PlainText)
                    print("Deryption Process Completed")
                else:
                    print("signature is Manipulated, Aborting ....")
                    exit(1)
        elif choice == 6:
            with open('RSA Public Kyes.txt', 'r') as file:
                Keys = file.read().split('\n\n')
                print("[+] Public Keys [+]")
                print("e :",Keys[0])
                print("N :", Keys[1])
            with open('RSA Private Kyes.txt', 'r') as file:
                Keys = file.read().split('\n\n')
                print("[+] Private Keys [+]")
                print("p :",Keys[0])
                print("q :", Keys[1])
                print("phi :", Keys[3])
                print("d :", Keys[5])
        else:
            exit(1)
