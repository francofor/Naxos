//
// References:
// [1] Guide to Elliptic Curve Cryptography - Authors: Hankerson, Darrel, Menezes, Alfred J., Vanstone, Scott
//
// [2] Co-Z Addition Formulæ and Binary Ladders on Elliptic Curves
//
// [3] FIPS PUB 186-4, Digital Signature Standard (DSS)
//
// Testing: http://point-at-infinity.org/ecc/nisttv

#ifndef _NAXOS__
#define _NAXOS__

#include <stdint.h>
#include <stdlib.h>
#include <sys/random.h>
#include <SimpleFIPS202.h>

#define COORD_NWORDS 10   // It is the maximum curve.wsize + 1
#define COORD_BYTES  72   // Is is the maximum curve.wsize*BITS8

#define NIST_P192 192    // Index for NIST curve P-192
#define NIST_P224 224    // Index for NIST curve P-224
#define NIST_P256 256    // Index for NIST curve P-256
#define NIST_P384 384    // Index for NIST curve P-384
#define NIST_P521 521    // Index for NIST curve P-521


typedef uint64_t coord[COORD_NWORDS];

typedef struct pointA    // Point with Affine coordinates
{
  coord aX;
  coord aY;
} pointA;

typedef struct ellipticCurve // Elliptic curve of type: y^2 = x^3 -ax + b mod p.
{
  uint16_t bsize;            // number of bits
  uint16_t wsize;            // number of words
  coord a;
  coord b;
  coord p;
  pointA g;                  // base point
} ellipticCurve;

typedef uint8_t keyC[COORD_BYTES]; // Coordinate X or Y of a point on the curve in byte array format

int selectCurve(ellipticCurve* curve,int index);
/* It selects the elliptic curve among the ones recommended by NIST
     FIPS PUB 186-4, Digital Signature Standard (DSS)
   The ones proposed here are the ones over Prime Fields
     with the following equation: y^2 = x^3 -ax + b mod p
   By using the routines included in this package, new curves can be built
   over different primes.
   Curve parameters are represented as in the NIST with less significant word on the right
   index = NIST_P192, NIST_P224, NIST_P256, NIST_P384, NIST_P521
*/

int generateRand(keyC num,ellipticCurve* curve);
/* It generates non cryptographic secure random numbers mod p */

void  publicKey(keyC pkx,keyC pky,keyC sk,ellipticCurve* curveN);
/* It calculates the public key pkx, pky from the secret key sk
   pk = G*sk
*/

int randomGen(uint8_t* esk,int nbits);
/* It generates a random number of nbits using the /dev/urandom device */

void calculateXY(keyC Xx,keyC Xy,keyC esk,keyC sk,ellipticCurve* curveN);
/* It generates esk and calculates X=G*H(esk,sk), using the proper SHA3 function */

int calculateKa(keyC kA,keyC Yx,keyC Yy,keyC eskA,keyC skAb, keyC pkBx, keyC pkBy,keyC idA,keyC idB,ellipticCurve* curveN);
/* It calculates kA using the x coordinates of the points on the curve
   kA = H(Y*skA, pkB*H(eskA,skA), Y*H(eskA,skA), idA, idB)
   Return:
     1 = OK
    -1 = coord of pkB are not mod p
    -2 = pkB is not on the curve
    -3 = coord of Y are not mod p
    -4 = Y is not on the curve
    -5 = internal error
*/

int calculateKb(keyC kB,keyC pkAx, keyC pkAy,keyC eskB,keyC skBb,keyC Xx,keyC Xy,keyC idA,keyC idB,ellipticCurve* curveN);
/*  It  calculates kB using the x coordinates of the points on the curve
    kB = H(pkA*H(eskB,skB), X*skB, X*H(eskB,skB), idA, idB)
    Return:
      1 = OK
     -1 = coord of pkA are not mod p
     -2 = pkA is not on the curve
     -3 = coord of X are not mod p
     -4 = X is not on the curve
     -5 = internal error
*/

#endif // #ifndef _NAXOS__
