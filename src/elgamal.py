#####################################
# Cole Brooks
# Homework 5, Problem 1
# El Gamal Encryption
#
# Description:
# Implement ElGamal cryptosystem. Your code will accept p and a,
# Then a user will pick either key generation, message encryption, or message decryption
#
# Key Generation: Program will randomly pick a secret X_a and output private and public keys
#
# Message Encryption: User will provide m. The program will use random k. Output (C1, C2). Note program should compute K_-1
#
# Message Decryption: User provides (C1, C2) and gets m

import random
from MillerRabins import fullMillerRabins, MillerRabins_1

ran = random.SystemRandom()

# greatestCommonDenominator:
#   a helper function for the key gen portion of El Gamal Cryptosystem
def greatestCommonDenominator(num1, num2):
    if num1 < num2:
        # let's make sure that num1 is the larger number
        return greatestCommonDenominator(num2, num1)
    elif num1 % num2 == 0:
        return num2
    else:
        return greatestCommonDenominator(num2, num1 % num2)

# encrypt
#  encrypts a message, m, using the private key of the user


# get a whole bunch of prime numbers
primes = [2, 3]

for num in range(4, 100000):
    if fullMillerRabins(num):
        primes.append(num)

####################
# Main Loop
####################

# Stored values from key gen
X_a = None
Y_a = None
C1 = None
C2 = None
kInverse = None

print("Welcome to the ElGamal Cryptosystem.")
p = int(input("Please input p"))
a = int(input("Please input a"))
q = primes[random.randint(0, len(primes) -1)]

while True:
    mode = int(input("(1) Key Generation \n(2) Message Encryption\n(3) Message Decryption"))
    match int(mode):
        case 1:
            print("We'll pick a secret X_a and output private and public keys")

            # X_a: private key - note that 1 <= X_a <= q -1 
            # Note that X_a should be relatively prime to q
            X_a = ran.randint(500, q-1)
            
            Y_a = pow(int(a), X_a, q)
            pubKey = (q, a, Y_a)
            print("Private Key X_a: " + str(X_a))
            print("Public Key (q, a, Y_a):")
            print(pubKey)

        case 2:
            if X_a == None or Y_a == None:
                print("You need to generate keys first!")
            else:
                m = int(input("Please provide m, We'll then use random k and output (C1, C2)"))
                k = ran.randint(1, q - 1)
                oneTimeKey = pow(Y_a, k, q)
                kInverse = 1 / oneTimeKey
                C1 = pow(a, k, q)
                C2 = (oneTimeKey * m ) % q
                print("C1: " + str(C1))
                print("C2: " + str(C2))
                print("K^-1: " + str(1 / oneTimeKey))

        case 3:
            if X_a == None:
                print("You need to generate keys first!")
            else:
                c1 = int(input("Please provide C1"))
                c2 = int(input("Please provide C2"))
                oneTimeKey = pow(C1, X_a, q)
                M = (C2 * kInverse) % q
                print("Message: " + str(M))