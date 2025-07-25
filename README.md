# bitcoin_math
Zero dependency Bitcoin math implementation in C

**WARNING:**
**THIS PROGRAM USES THE rand_s FUNCTION FROM THE WINDOWS**
**stdlib.h TO GENERATE PSEUDO RANDOM ENTROPY.**
**MICROSOFT CLAIMS THAT rand_s PRODUCES CRYPTOGRAPHICALLY** 
**SECURE RANDOM NUMBERS. HOWEVER, IT IS RECOMMENDED THAT**
**USERS DO NOT SEND COINS TO "RANDOM" ADDRESSES GENERATED**
**BY THIS PROGRAM!**

## Introduction

I started the `bitcoin_math` project in order to teach myself the basics of Bitcoin math from first principles, without having to wade through the source code of any of the crypto or "bignum" libraries on which standard Bitcoin implementations in Python depend.

My goal was to collect together a minimal set of functions in a single C source code file with no dependencies other than the following standard C libraries: `ctype.h`, `math.h`, `stdint.h`, `stdio.h`, `stdlib.h`, and `string.h`.

Given a choice between efficiency and readability, I have opted for the latter, for example by avoiding inline functions and macros.

The result is `bitcoin_math.exe`, a simple menu driven console application which implements functions for the generation of mnemonic phrases, seeds, private keys, extended keys, public keys, and Bitcoin addresses (P2PKH, P2SH-P2WPKH and P2WPKH) using various cryptographic hash functions, arbitrary precision integer math, elliptic curve math, and radix conversions, all built from standard C data types and a few custom structs.

Wherever possible, hash digests, MACs, seeds, keys, and addresses are manipulated as arbitrary precision integers, reflecting their essentially numerical nature. These numbers are typically rendered onscreen in hex or Bitcoin base 58 format, but can be rendered in any base between 2 and 64 using the base conversion function.

P2PKH addresses have at least one leading zero. When rendered on screen in Bitcoin base58, each leading zero is indicated by a "1" character. In `bitcoin_math`, P2PKH addresses are stored as `bnz_t` values. When the P2PKH address is rendered on screen, leading zeros are added before the non-zero numercial part.

Storing P2WPKH addresses as numbers is not straightforward: the "bc1q" prefix (which contains non bech32 characters) is concatenated with a numerical part which consists of a bech32-encoded ripemd160-sha256 double hash digest of the relevant compressed public key, concatendated with a corresponding special P2WPKH checksum. Adding to the complication, this numerical part can have zeroes at the MSB end. Leading zeroes are typically stripped out when `bitcoin_math` prints `bnz_t` numbers, which would lead to invalid P2WPKH addresses. `bitcoin_math` solves these issues by storing the numercial part as a `bnz_t` number, and using a dedicated print function to add the "bc1q" prefix, and any necessary zero padding (in the form of bech32 'q' digits), prior to printing, leveraging the fact that P2WPKH addresses are 42 characters long.

Outputs from `bitcoin_math` can be verified using online tools. My preferred sources of verification are the excellent https://iancoleman.io/bip39/ and https://learnmeabitcoin.com/technical/keys/. I have also checked the entropy-to-seed outputs of `bitcoin_math.exe` against the 256 bit entropy examples in the "english" section of https://github.com/trezor/python-mnemonic/blob/master/vectors.json, using "TREZOR" as the passphrase. The validity of P2PKH, P2SH-P2WPKH and P2WPKH addresses can be checked using a blockchain explorer such as https://www.blockchain.com/explorer/search


## Getting started with `bitcoin_math` 

Compilation: The source code of `bitcoin_math` compiles with gcc under Windows using the following simple command:

`gcc -o bitcoin_math.exe bitcoin_math.c`

The compilation command works on Linux, although you may have to append `-lm` to ensure that the `math.h` functions `log10` and `log` are recognised. Note that the `system(cls);` command in the menu functions is not recognised by Linux, so non-fatal errors will be raised on execution.

Linux developers should note that the source code has been updated to use the (allegedly) crytographically secure random number generation function `rand_s`, which is part of the Microsoft `stdlib` (see the function entitled `bnz_256_bit_rnd` under the /* BITCOIN */ heading). Linux developers will need to replace `rand_s` with functions based on `/dev/random` or `/dev/urandom`, or delete the random number based functions altogether.

I have found `bitcoin_math.exe` to be fast enough for its intended illustrative / educational purposes. However, it can be trivially speeded-up using compiler optimisation flags such as `-O3`. Conversion to a library should also be relatively simple. Obviously, many further improvements in efficiency are potentially available.

There are four menus, some with sub-menus:

**1. Master keys** This function takes 256 bits of random entropy (typed or pasted, in a specified base between 2 and 64) and generates the corresponding master private key, master chain code, and the corresponding first 20 P2PKH, P2SH-P2WPKH and P2WPKH heirarchical deterministic wallet addresses in accordance with BIP44, BIP49 and BIP84 respectively. There is an option to generate "random" entropy. However, this option uses the function `rand_s()` from the Windows `stdlib`. As such, **I CANNOT RECOMMEND RELIANCE ON rand_s AS A SOURCE OF CRYPTOGRAPHICALLY SECURE RANDOM ENTROPY AND, THEREFORE, THIS PROGRAM SHOULD NOT BE USED TO GENERATE ANY BITCOIN ADDRESSES TO WHICH ANY COINS WILL BE SENT!**

**2. Child keys** These functions take a parent private key or public key and a corresponding parent chain code (typed or pasted, in hex only), together with a numerical index. Depending on the function chosen and the value range of the index, these functions output a normal or hardened child private key and corresponding child chain code, or a child public key. The range of index values for hardened child keys is from 2147483648 to 4294967295. The function `get_child_hardened`, and the corresponding menu commands, will accept index values of less than 2147483648 and will automatically add 2147483648 if necessary. This makes it easier to use an offset rather than an absolute value, as in the 44', 49' and 84' hardened child keys generated in the `get_wallet_p2pkh_addresses`, `get_wallet_p2sh_p2wpkh` and `get_wallet_p2wpkh_addresses` functions which generate series of heirarchical deterministic wallet addresses from a master private key and master chain code in accordance with BIP44, BIP49 and BIP84.

The `get_hdk_intermediate_values` function calculates and displays the intermediate private key and chain code values derived from a master private key and master chain code pair, and a hierarchical deterministic key derivation path string e.g. m/44'/0'/0'/0/0. The function takes a master private key, a master chain code, and a string representing the derivation path. The string must start with "m" and be "/" delimited. Index values can be absolute or offset, with hardened child keys being designated by a ' character. `bitcoin_math` does not perform any validation of the derivation path string. Errors are therefore likely to cause segmentation faults.

**3. Base converter** This function takes a number of arbitrary length (typed or pasted) in any specified base between 2 and 64, and outputs a radix converted version of the number for each base between 2 and 64. Note that, in `bitcoin_math` base "-2" corresponds to a binary representation with a space between each set of eight bits, whereas base "2" corresponds to an unbroken binary string. Likewise, base "16" corresponds to lower case hex preceded by "0x", whereas base "-16" corresponds to upper case hex with no prefix. Finally, base "58" corresponds to Bitcoin base 58, whereas base "-58" corresponds to regular base 58.

**4. Functions** This menu enables some individual functions, including P2PKH, P2SH-P2WPKH and P2WPKH serialisation, two-way WIF format conversion, mnemonic phrase checksum validation, and Secp256k1 functions for point addition, point doubling, and scalar multiplication, to be independently executed. Parameters such as private keys, chain codes, and Secp256k1 coordinates must be typed or pasted in hex format. **DO NOT ENTER ANY MNEMONIC PHRASE THAT CORRESPONDS TO ANY PRIVATE KEY / BITCOIN ADDRESS TO WHICH COINS WILL BE SENT!**


## Acknowledgements

The BIP39 word list, and the source code for the cryptographic hash functions (RIPEMD160, SHA256, SHA512, HMAC-SHA512), were copied from various third party Github repositories, with a few minor modifications for readability e.g. conversion of inline functions into standalone functions.

The majority of the original source code in `bitcoin_math` relates to arbitrary precision integer math which is required to implement the elliptic curve functions used in Bitcoin to convert private keys into public keys.

This arbitrary precision integer math code was heavily influenced by the source code of the GNU Multiple Precision Arithmetic Library ("GMP", https://gmplib.org/), and DI Management Services' BigDigits multiple-precision arithmetic library (https://www.di-mgt.com.au/bigdigits.html).

My version of arbitrary precision integer division is adapted from the well known Hacker's Delight version, where the digits are processed in pairs of 16 bit integers ("half words") combined into 32 bit integers. I modified the code to use pairs of 8 bit integers combined into 16 bit integers in order to enable the uint8_t arrays that comprise the `bnz_t` digits to be consumed directly.

The algorithms for the elliptic curve functions were adapted from a paper entitled _Implementation of Elliptic Curve Cryptography in 'C'_ by Kuldeep Bhardwaj and Sanjay Chaudhary (International Journal on Emerging Technologies 3(2): 38-51 (2012)), which used GMP for the arbitrary precision integer functions. It was straightforward to adapt the algorithms to work with my own arbitrary precision integer math code.

The algorithms for the modular power and modular multiplicative inverse functions were adapted from the pseudocode provided in the corresponding Wikipedia pages.


## The source code

The source code file bitcoin_math.c is divided into the following sections:

### /* MISCELLANEOUS */
The BIP39 word list, formatted as a 2D array (2048 x 9) of type `char`, and a utility function (`init_uint8_array`) which initiates and zeroes a fixed length 1D dynamic array of type `uint8_t`.

### /* RIPEMD160 */
Standard cryptographic hash function with a 20 byte digest.

### /* SHA256 */
Standard cryptographic hash function with  32 byte digest.

### /* SHA512 */
Standard cryptographic hash function with  64 byte digest.

### /* HMAC-SHA512 */
Standard cryptographic message authentication function returning a 64 byte MAC from a combination of a message and a key, each formatted as 1D fixed array of type `uint8_t`.

### /* BNZ */
Code for implementing arbitrary precision integer math based around a custom type (`bnz_t`) and associated functions to manipulate signed integers of arbitrary size.

The 8 bit "digits" are stored, in little endian order, in the "digits" property of `bnz_t`, formatted as a 1D dynamic array of type `uint8_t`. The number of digits is stored in the "size" property, type `size_t`. The sign is stored in the "sign" property, type `size_t`, with a zero value corresponding to positive and a non-zero value corresponding to negative.

There are basic functions to initiate, free, set, align, trim, reverse, concatenate, and resize `bnz_t` integers. When resizing to a higher number of digits, new digits are zeroed and the values of existing digits are either preserved or zeroed depending on the value of the "preserve" parameter.

The `bnz_print` function is used to write a `bnz_t` number to the screen in the specified base, optionally preceded by a specified string.

Various comparison functions are implemented, returning -1, 0, or 1 according to standard C numerical comparison rules.

Functions for addition, subtraction, multiplication and division (quotient and remainder) are implemented, with pre-processing of signs as appropriate.

Finally, arbitrary precision implementations of the special functions of mod, mod power, and modular multiplicative inverse are implemented for use in the Secp256k1 elliptic curve math.


### /* SECP256K1 */
Elliptic curve math, built around two custom structs: `PT`, comprising two `bnz_t` numbers, representing a point on Secp256k1, and `SECP256K1` representing the elliptic curve itself. The `a` and `h` parameters of the curve are included for completeness, but play no role in the  functions.

### /* BITCOIN */
Bitcoin specific functions for processing entropy, generating mnemonic phrases, seeds, private keys (including two-way WIF format conversion), chain codes, public keys, and P2PKH addresses.

If a user generates a private key that is not less than the value of the order of Secp256k1, the user will be prompted to rerun the private key generation step with a different entropy value. 

### /* MENU */
Menu functions.

### /* MAIN */
Main function.
