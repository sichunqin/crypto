from Crypto.Cipher import AES
from Crypto.Util import Counter
import random
"""
    >>> pt = b'\x00'*1000000
    >>> ctr = Counter.new(128)
    >>> cipher = AES.new(b'\x00'*16, AES.MODE_CTR, counter=ctr)
    >>> ct = cipher.encrypt(pt)
    Both python and c AES CTR implementation doesn't use nonce, and only use counter which would be incremented for each AES block.
"""
def testAesCtr():
    key = b'\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c'
    iv =  b'\x00' * 32
    ctr = Counter.new(128,initial_value=1)
    aes = AES.new(key, AES.MODE_CTR, counter=ctr)
    data = b'\x05' * 127

    encd = aes.encrypt(data)
    print(data.hex())
    print(encd.hex())

def main():
    testAesCtr();
    return

if __name__ == "__main__":
    main()