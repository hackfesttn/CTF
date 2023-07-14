#!/usr/bin/python3

import math

def is_prime(n):
    if n < 2:
        return False

    for i in range(2, int(math.sqrt(n)) + 1):
        if n % i == 0:
            return False

    return True

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def is_carmichael(n):
    if is_prime(n):
        return False

    for a in range(2, n):
        if gcd(a, n) == 1 and pow(a, n - 1, n) != 1:
            return False

    return True

def find_carmichaels(start, end):
    count = 0
    n = 0
    ref = 1333337
    nums = []

    for num in range(start, end + 1):
        if (n == 10):
            return nums

        if is_carmichael(num):
            c = num
            count += 1
        
        if (count == ref):
            nums.append(str(c))
            ref += 1337
            n += 1

start = 2
end = 10 ** 18

print("Bring your ☕ 🚬 ...")

carmichaels = find_carmichaels(start, end)

print("Hackfest{" + "".join(carmichaels) + "}")
