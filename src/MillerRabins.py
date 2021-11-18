import random
ranNum = random.SystemRandom()

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