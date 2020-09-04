
#Encryption and Decrytion In RSA using Square and Multiply and ChineseRemainderTheorem
import sys, threading
import gmpy2
from Crypto.Util.number import *
from Crypto import Random
import Crypto

sys.setrecursionlimit(10**7)
threading.stack_size(2**27)

bits = 512

def squareandmultiply(a, b,mod):
    exp = bin(b)
    val = a

    for i in range(3, len(exp)):
        val = (val * val) % mod
        if(exp[i:i+1]=='1'):
            val = (val * a)%mod
    return val % mod

def ConvertToInt(message_str):
    res = 0
    for i in range(len(message_str)):
        res = res * 128 + ord(message_str[i])
    return res

def ConvertToStr(n):
    res = ""
    while n > 0:
        res += chr(n % 128)
        n //= 128
    return res[::-1]


def ExtendedEuclid(a, b):
    if b == 0:
        return (1, 0)
    (x, y) = ExtendedEuclid(b, a % b)
    k = a // b
    return (y, x - k * y)

def InvertModulo(a, n):
    (b, x) = ExtendedEuclid(a, n)
    if b < 0:
        b = (b % n + n) % n
    return b

def ChineseRemainderTheorem(p, r1, q, r2):
    #(x, y) = ExtendedEuclid(n1, n2)
    q_inverse = InvertModulo(q, p)#have big integers
    h = (q_inverse * (r1 - r2)) % p #have big integers
    m = r2 + (h * q) #have big integers
    return m
    #return ((r2 * x * n1 + r1 * y * n2) % (n1 * n2) + (n1 * n2)) % (n1 * n2)

def Encrypt(message, modulo, exponent):
    ciphertext = squareandmultiply(ConvertToInt(message), exponent, modulo)
    return ciphertext

def Decrypt(ciphertext, p, q, exponent):
    p1 = p - 1 #have big integers
    q1 = q - 1 #have big integers
    d = InvertModulo(exponent,p1*q1) #have big integers
    dp = d % (p1)
    dq = d % (q1)
    #ciphertext_p = ciphertext % p
    #ciphertext_q = ciphertext % q
    first_message = squareandmultiply(ciphertext,dp,p) #have big integers
    second_message = squareandmultiply(ciphertext,dq,q) #have big integers
    #return ConvertToStr(squareandmultiply(ciphertext, d, p * q))
    return ConvertToStr(ChineseRemainderTheorem(p,first_message,q,second_message)) #have big integers

def enter_input():
    val_input = input("Enter an input:")
    return val_input

def main():
    #p = (1000000007) #have big integers
    #q = (1000000009) #have big integers
    p = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
    q = Crypto.Util.number.getPrime(bits, randfunc=Crypto.Random.get_random_bytes)
    #p = 65537
    #q = 524287
    exponent = 65537
    modulo = (p * q)
    ciphertext = Encrypt(enter_input(), modulo, exponent)
    print("ciphertext:",ciphertext)
    message = Decrypt(ciphertext, p, q, exponent)
    print(message)

if __name__ == "__main__":
    main()
