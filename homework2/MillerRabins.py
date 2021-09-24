#######################################################
# Miller Rabins Primality Test
# Author: Cole Brooks
# 
# Purpose: Determine if a number is likely prime or it is composite
#
# Steps:
#	1) Find n-1 = 2^k x m
#	2) Choose a: 1 < a < n-1
#	3) Compute b0 = a^m (mod n), bi = b(i-1)^2
#
import random
ranNum = random.SystemRandom()

####################################################
# Function Definitions
####################################################

def MillerRabins_1(n, witness):
	exponent = n - 1

	while exponent % 2 != 1: # while exponent is even
		exponent //= 2 # integer divide by 2

	if pow(witness, exponent, n) == 1:
		return True

	while exponent < n -1:
		if pow(witness, exponent, n) == n - 1:
			return True

		exponent *= 2

	return False

def fullMillerRabins(n, k=40):
	for i in range(k):
		# pick a random number in [2... n-1)
		# Just make sure that n > 4 
		# and use that number as the witness
		a = ranNum.randrange(2, n-1) # randrange is non inclusive
		if not MillerRabins_1(n, a):
			# if we were able to find a random number 'a' that 
			# proves that 'n' is composite, we know that 'n' is
			# just composite
			return False
	# if we were unable to find a random number in all our iterations that proved the number 
	# composite, we're going to go ahead and say that the number is likely prime. Although
	# it is important to remember that the Miller Rabins test does not prove primeness.
	return True

####################################################
# Driver Portion
# Comment out for no console logging
####################################################

# to test my code I'm going to attempt to find all prime numbers between 1 and 10000
#
# I've tested it with a few different caps and found that it's accurate (as many times as I've run it)
# and quick enough for at least until 50,000
#
# Although I'm realizing it may just be because the websites I'm looking at implement their prime number
# finding using this algorithm, too.
#

high = 50001
primes = [2, 3]

for num in range(4, high):
	if fullMillerRabins(num):
		primes.append(num)
print("There are " + str(len(primes)) + " prime numbers between 0 and " + str(high))
print(primes)