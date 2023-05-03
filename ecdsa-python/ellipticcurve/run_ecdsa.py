import sys
import os

# Add the ecdsa-python/ellipticcurve directory to the sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from ellipticcurve.ecdsa import Ecdsa
from ellipticcurve.privateKey import PrivateKey

def main():
    message = sys.argv[1]
    blinded_private_key = PrivateKey.fromString(sys.argv[2])
    k = int(sys.argv[3])

    signature = Ecdsa.signBlind(message, blinded_private_key, k, chain='BTC')
    print(str(signature.r) + "," + str(signature.s)+ "," + str(signature.recoveryId))

if __name__ == "__main__":
    main()
