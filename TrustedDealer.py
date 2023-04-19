# Generate a private key and a public key
from keyGen1 import generate_keys
private_key, public_key = generate_keys()
print("Private key:", private_key.toPem())
print("Public key:", public_key.toString())
prime = private_key.curve.N
_PRIME = prime

import random

def _RINT(n):
    # This function generates cryptographically secure random integers
    return random.SystemRandom().randrange(n)

def make_random_shares(secret, minimum, shares, prime=_PRIME):
    if minimum > shares:
        raise ValueError("Pool secret would be irrecoverable.")
    poly = [secret] + [_RINT(prime - 1) for i in range(minimum - 1)]
    points = [(i, _eval_at(poly, i, prime))
              for i in range(1, shares + 1)]
    return points

def _eval_at(poly, x, prime):
    """
    Evaluate polynomial (coefficient tuple) at x, used to generate a shamir pool.
    """
    accum = 0
    for coeff in reversed(poly):
        accum *= x
        accum += coeff
        accum %= prime
    return accum

# Generate a set of shares from the private key with lagrange interpolation
# Use the private key to create shares
minimum = 2
shares = 3
secret = private_key.secret.to_bytes((private_key.curve.N.bit_length() + 7) // 8, byteorder='big')
points = make_random_shares(int.from_bytes(secret, 'big'), minimum, shares, prime)
print("Shares:", points)

# Save the shares to several files as KeyStore1, KeyStore2, KeyStore3, etc.
# Save the shares/points to separate files
for i, point in enumerate(points):
    filename = f"KeyStore{i+1}"
    with open(filename, "w") as f:
        f.write(f"{point[0]},{point[1]}")
    print(f"Saved point {i+1} to file {filename}")


# Order of operations: run TrustedDealer.py, then run FetchTeleportLSS.py
# FetchTeleportLSS.py needs to iterate over all running instances of TeleportLSS.js
# If MPC sig succeeds next step is to JVSS private key shares, and then use JVSS to add new parties
# To detect new parties some work on P2P is needed??
# Finally, we can merge LSS MPC into TeleportMPC if we choose or do vaulting
# If Vaulting, we need to figure out JVSS creation of new public key private key pair
# If vaulting, serialization of merged sig shares. Also crypto primitives need to be stronger.
   
