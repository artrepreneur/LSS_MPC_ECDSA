from ellipticcurve.privateKey import PrivateKey
from ecdsa import SigningKey
from ellipticcurve.utils.integer import RandomInteger


def generate_keys():
    private_key = PrivateKey()
    public_key = private_key.publicKey()
    public_key_string = public_key.toString()

    return private_key, public_key

def generate_ephemeral_keys():
    k_share = RandomInteger.between(1, curve.N - 1)
    return k_share