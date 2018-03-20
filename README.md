# Naxos Key Exchange

This project implements the Naxos authenticated key exchange (AKE) Protocol:
Stronger Security of Authenticated Key Exchange - Authors: Brian LaMacchia, Kristin Lauter and Anton Mityagin

The NAXOS AKE protocol uses a mathematical group G and two hash functions, H1: {0,1}* -> Zq
and H2: {0,1}* -> {0, 1}λ  (for some constant λ). A long-term secret key of a party A is an exponent
skA ~~C~~ Zq, and the corresponding long-term public key of A is the power pkA = g^skA ~~C~~ G. In the
following description of an AKE session of NAXOS executed between the parties A and B we
assume that each party knows the other’s public key and that public keys are in the group G.
The session execution proceeds as follows. The parties pick ephemeral secret keys eskA and
eskB at random from {0,1}λ. Then the parties exchange values X=g^H1(eskA,skA) and Y=g^H1(eskB,skB),
check if received values are in the group G and only compute the session keys if the check succeeds.
The session key K ~~C~~ {0,1}λ is computed as:

H2(g^H1(eskB,skB)skA, g^H1(eskA,skA)skB, g^H1(eskA,skA)H1(eskB,skB),A, B).

The last two components in the hash are the identities of A and B, which we assume to be binary
strings.

In this implementation the group G is a finite cyclic subgroup of the NIST FIPS PUB 186-4 elliptic
curves over Prime Fields y^2 = x^3 - 3x + b (mod p) P-224, P-256, P-384, P-521.
H1 = H2 = SHA3 in order to generate keys of 224, 256, 384 and 512 bits respectively.

SHA3 functions are taken directly from the KeccaK Team official repository:
https://github.com/gvanas/KeccakCodePackage

The unix-like getrandom function is used for random number generation to get entropy from the
/dev/urandom device.
It can be substituted by analogue functions in other OSs (for instance by BCryptGenRandom
in windows).

This package implements all the mathematical operations using internal representations of
the numbers in arrays of 64 bits words to be better suitable for x64 machines.
It can be easily adapted to better perform on x86 by using arrays of 32 bits words.

The mathematical operations are not optimized for the specific NIST elliptic curves used.
They can work with any other elliptic curve over Prime fields.
The routines in this package can help to build a new curve for specific use. 

All the algorithms in this package realize always the same number of operations despite the input.
Nevertheless complete resistance to side channel attacks is not guaranteed because some processors
realize basic mathematical operations in different time intervals according to the operands.

### Prerequisites

This package makes use of the SHA3 routines from the Keccak Team official repository:
https://github.com/gvanas/KeccakCodePackage

It has been used "make FIPS202-opt64.pack" to get a tarball with the sources needed
to compile the FIPS 202 functions generically optimized for 64-bit platforms.
The functions called directly by this code are:

* SHA3_224
* SHA3_256
* SHA3_384
* KeccakWidth1600_Sponge
* SHA3_512

## How to

* selectCurve: selects the NIST curve and the length of the key
* privateKey: calculates the private key from the secret key
* randomGen: generates random numbers based on unix-like /dev/urandom device (used in calculateXY)
* calculateXY: calculates X=g^H1(eskA,skA)
* calculateKa: calculates the key for user A
* calculateKb: calculates the key for user B

## Example

Compile and run Example_Naxos.c to get an example on how to use the routines in this package.

## How to build it

The tested code has been built with GCC. 

## License

This project is of public domain and can be used by anybody under his responsibility.
