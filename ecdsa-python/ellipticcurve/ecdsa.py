# This file is a modified version of the original ecdsa.py file from the ellipticcurve library.
from hashlib import sha256

from ellipticcurve.signature import Signature
from ellipticcurve.ec_math import Math

from ellipticcurve.utils.integer import RandomInteger
from ellipticcurve.utils.binary import numberFromByteString
from ellipticcurve.utils.compatibility import *
from ecdsa import SECP256k1, SigningKey, util
from sha3 import keccak_256
from web3 import Web3
w3 = Web3()



class Ecdsa:

    @classmethod
    def sign(cls, message, privateKey, chain='BTC', hashfunc=sha256):
        byteMessage = w3.keccak(text=message) if chain == 'ETH' else hashfunc(toBytes(message)).digest()
        numberMessage = numberFromByteString(byteMessage)
        curve = privateKey.curve

        r, s, randSignPoint = 0, 0, None
        while r == 0 or s == 0:
            randNum = RandomInteger.between(1, curve.N - 1)
            randSignPoint = Math.multiply(curve.G, n=randNum, A=curve.A, P=curve.P, N=curve.N)
            r = randSignPoint.x % curve.N
            s = ((numberMessage + r * privateKey.secret) * (Math.inv(randNum, curve.N))) % curve.N
        recoveryId = randSignPoint.y & 1
        if randSignPoint.y > curve.N:
            recoveryId += 2

        return Signature(r=r, s=s, recoveryId=recoveryId)

    
    @classmethod
    def signBlind(cls, message, blindedPrivateKey, k=None, chain='BTC', hashfunc=sha256):# blinding_share=None,
        #print('message',message)
        byteMessage = w3.keccak(text=message) if chain == 'ETH' else hashfunc(toBytes(message)).digest()
        numberMessage = numberFromByteString(byteMessage)
        #print('numberMessage',numberMessage)
        curve = blindedPrivateKey.curve
        #print('blindedPrivateKey in ecdsa',blindedPrivateKey.secret, blindedPrivateKey.toString())
        #print('curve:',curve.N, curve.A, curve.P)

        # Blind the message if a blinding factor is provided
        #if blinding_share:
        #    numberMessage = (numberMessage * blinding_share) % curve.N

        r, s, randSignPoint = 0, 0, None
        while r == 0 or s == 0:
            randNum = k #RandomInteger.between(1, curve.N - 1) #
            randSignPoint = Math.multiply(curve.G, n=randNum, A=curve.A, P=curve.P, N=curve.N)
            r = randSignPoint.x % curve.N
            #print('CURVE PARAMS:',curve.G, curve.A, curve.P, curve.N)

            try:
                int(blindedPrivateKey.toString(), 16)
                s = ((numberMessage + r * int(blindedPrivateKey.toString())) * (Math.inv(randNum, curve.N))) % curve.N
            except ValueError:
                s = ((numberMessage + r * int(blindedPrivateKey.secret)) * (Math.inv(randNum, curve.N))) % curve.N

        recoveryId = randSignPoint.y & 1
        if randSignPoint.y > curve.N:
            recoveryId += 2

        return Signature(r=r, s=s, recoveryId=recoveryId)

 

    @classmethod
    def verify(cls, message, signature, publicKey, chain='BTC', hashfunc=sha256):
        byteMessage = w3.keccak(text=message) if chain == 'ETH' else hashfunc(toBytes(message)).digest()
        numberMessage = numberFromByteString(byteMessage)
        curve = publicKey.curve
        r = signature.r
        s = signature.s
        if not 1 <= r <= curve.N - 1:
            return False
        if not 1 <= s <= curve.N - 1:
            return False
        inv = Math.inv(s, curve.N)
        u1 = Math.multiply(curve.G, n=(numberMessage * inv) % curve.N, N=curve.N, A=curve.A, P=curve.P)
        u2 = Math.multiply(publicKey.point, n=(r * inv) % curve.N, N=curve.N, A=curve.A, P=curve.P)
        v = Math.add(u1, u2, A=curve.A, P=curve.P)
        if v.isAtInfinity():
            return False
     
        sk = SigningKey.from_secret_exponent(r, curve=SECP256k1)
        verifying_key = sk.get_verifying_key()
        public_key = verifying_key.to_string()

        print('pubkey', int(public_key.hex(), 16), 'real pubkey', int(publicKey.toString(),16))

        #Verify the public key using the signature and message hash
        #message_hash = sha256(message.encode('utf-8')).digest()
        #assert verifying_key.verify(s, message_hash, util.sigdecode_der(s, r))

        return v.x % curve.N == r
