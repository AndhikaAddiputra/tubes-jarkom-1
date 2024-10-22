import random
import math
import gfg

def precompute_prime(max: int):
    nums = [1 for i in range(0, max + 1)]
    primes = list()
    for i in range(2, max+1):
        if nums[i] == 1:
            primes.append(i)
            for j in range(i * 2, max + 1, i):
                nums[j] = 0
        
    return primes

primes = precompute_prime(1000)
 

def pickRandom(bit):
    return random.randrange(2**(bit - 1) + 1, 2**(bit) - 1, 2)

def lowLevelTest(divisors: list[int], num:int):
    for divisor in divisors:
        if(num % divisor == 0 and divisor ** 2 <= num): return False

    return True

def pickRandomLowLevelPrime(bit):
    while True:
        random_num = pickRandom(bit)
        if lowLevelTest(primes, random_num): return random_num

def millerRabinTest(num, num_of_trials):
    s = 0 # maximum division by two
    d = num - 1 # gotta save the result of (num - 1) divided by (2^s) 
    while d % 2 == 0:
        d //=2
        s += 1
        # print("s:", d)

    assert(2**s * d == num-1)
    for _ in range(num_of_trials):
        # a must be coprime to num
        a = random.randrange(2, num)
        
        # FIRST TEST: a ^ d === 1 mod num
        bjirlah = pow(a, d, num)
        if(bjirlah == 1 or bjirlah == num - 1): 
            # print("F1: TRUE")
            continue # probable prime
        
    
        # print(s)
        # SECOND TEST: a ^ ((2 ^ r) * d) === -1 mod num (incase it didn't pass the first test case)
        for r in range(s):
            # print("as", a)
            if(pow(a, (2**r) * d, num) == num - 1):
                break # probable prime

            if(r == s - 1): return False # obviously composite

    return True


def random_prime(n: int):
    while True:
        num = pickRandomLowLevelPrime(n)
        if(millerRabinTest(num, 20)):
            return num

# while True:
#     prime = random_prime(1024)
#     test1 = millerRabinTest(prime, 20)
#     test2 = gfg.isMillerRabinPassed(prime)
    
#     if(test1 != test2): break
#     print(prime)
