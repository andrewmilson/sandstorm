# read the file in array-sum.proof and write it in hex to the file array-sum.proof.hex
# this is the file that is used by the verifier

import sys
import binascii


data = open(sys.argv[1], 'r').read()
# decode data from hex into binary string
data = binascii.unhexlify(data)
open(sys.argv[2], 'wb').write(data)