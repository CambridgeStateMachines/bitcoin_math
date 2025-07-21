from bitcoinlib.mnemonic import Mnemonic
from bitcoinlib.keys import HDKey
from bitcoinlib.encoding import sha256
import os

from bitcoinlib.services.services import *

e = os.urandom(32)
e_hex = e.hex()
print(f"ENTROPY: 0x{e_hex}")
print("BASE: 16\n")


e_sha256 = sha256(e)
chk = e_sha256[0:1].hex()
print(f"CHECKSUM: 0x{chk}\n")

ec = e + e_sha256[0].to_bytes()
ec_num = int.from_bytes(ec)
ids = [0] * 24
for i in range (0, 24):
    ids[i] = ec_num & 2047
    ec_num >>= 11
ids.reverse()
print(f"BIP39 IDs: {ids}\n")

mnemonic = Mnemonic()
m = mnemonic.to_mnemonic(e)
print(f"MNEMONIC PHRASE: {m}\n")

s = mnemonic.to_seed(m)
s_hex = s.hex()
print(f"SEED: 0x{s_hex}\n")

hd_key = HDKey.from_seed(s)
pv = hd_key.private_hex
cc = hd_key.chain.hex()
xprv = hd_key.wif_private('0488ade4')
print(f"MASTER PRIVATE KEY: 0x{pv}")
print(f"MASTER CHAIN CODE: 0x{cc}")
print(f"MASTER XPRV: {xprv}\n")

pu = hd_key.public_hex
xpub = hd_key.wif_public('0488b21e')
print(f"MASTER PUBLIC KEY COMPRESSED: 0x{pu}")
print(f"MASTER XPUB: {xpub}")

ad1 = hd_key.address(encoding='base58')
print(f"MASTER P2PKH ADDRESS: {ad1}")

ad2 = hd_key.address()
print(f"MASTER SEGWIT P2WPKH ADDRESS: {ad2}\n")

# blockchaininfo
# bitgo
# blockchair
# bitaps
# litecoinblockexplorer
# blockbook
# blockstream
# mempool

srv = Service(network='bitcoin', providers=['blockchaininfo'])
print("%s: %s" % (ad1, srv.getbalance(ad1)))
print("%s: %s" % (ad2, srv.getbalance(ad2)))
