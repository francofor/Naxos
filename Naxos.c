/*
   References:
   [1] Guide to Elliptic Curve Cryptography - Authors: Hankerson, Darrel, Menezes, Alfred J., Vanstone, Scott

   [2] Co-Z Addition Formulæ and Binary Ladders on Elliptic Curves

   [3] FIPS PUB 186-4, Digital Signature Standard (DSS)

   Testing: http://point-at-infinity.org/ecc/nisttv
*/

#include "Naxos.h"

#define DOUBLEW_BYTES 144 /* Maximum length in bytes of esk+sk */
#define FIVET_BYTES 360   /* Maximum length in bytes of input for Hash in K calculation */
#define BITS64 64         /* For operations with 64 bit words */
#define BITS63 63         /* For operations with 64 bit words */
#define BYTES8 8          /* For operations with 64 bit words, number of bytes per word */
#define BYTES7 7          /* For operations with 64 bit words */

typedef struct pointP    /* Point with Projective coordinates */
{
  coord pX;
  coord pY;
  coord pZ;
} pointP;

void coordInit(coord a)
/* It sets a = 0  */
{
  memset(a, 0, COORD_BYTES);
}

void coordCopy(coord a,coord b)
/* It sets a = b */
{
  memcpy(a, b, COORD_BYTES);
}

int coordMaxBit(coord a, int nwords)
/* It returns the position plus 1 of the maximum bit of a != 0, i.e. order of a
   Always the same number of operations
*/
{
  int i,j,n=0;

  for (i=(nwords-1);i>-1;i--)
  {
    for (j=BITS63;j>-1;j--)
    {
    	if (((a[i] >> j)&1)&(n==0)) /* if the bit is 1 and n is still 0 then it is the maximum bit */
    		{
    	      n = i*BITS64+j+1;     /* returns the first position of a bit != 0 plus 1 */
    		}
    }
  }
  return n;
}

int coordGetBit(coord a, int j)
/* It returns the the value of the bit i of a
   Always the same number of operations
*/
{
  int i;

  i = (a[j/BITS64]>>(j&BITS63))&1;
  return i;
}

int coordIsOne(coord a, int nwords)
/* It returns (a==1)
   Always the same number of operations
*/
{
  int i,j;

  if (a[0] == 1)
  {
    j = 1;                        /* First word is 1 */
  }
  else
  {
    j = 0;                        /* First word is not 1. */
  }

  for (i=1;i<nwords;++i)
  {
    j = j & (a[i] == 0);          /* If any word is not 0 then j is set to 0 */
  }
  return j;
}

int coordIsZero(coord a, int nwords)
/* It returns (a==0)
   Always the same number of operations
*/
{
  int i,j;

  j = 1;

  for (i=0;i<nwords;++i)
  {
    j = j & (a[i] == 0);          /* If any word is not 0 then j is set to 0 */
  }
  return j;
}

int coordIsEven(coord a)
/* It returns (a==even i.e. a[0].bit0=0)
   Always the same number of operations
*/
{
  if ((a[0]&1) == 0)
  {
    return 1;               /* It is even */
  }
  else
  {
    return 0;               /* It is odd  */
  }
}

int coordCmp(coord a,coord b, int nwords)
/* It compares a and b and returns:
   1 if a > b
   0 if a= b
   -1 if a< b
   Always the same number of operations
*/
{

  int i,j=1,g=0,l=0;

  for (i=(nwords-1);i>-1;i--)
  {
    j = j & (a[i] == b[i]);              /* If any word is not 0 then j is set to 0 */
    g = g|((j==0)&(a[i]>b[i])&(l==0));   /* if there is a word that it is not 0,    */
                                         /*   a[i]>b[i] and it was not found lower before it is marked greater */
    l = l|((j==0)&(a[i]<b[i])&(g==0));   /* if there is a word that it is not 0,    */
                                         /*   a[i]<b[i] and it was not found greater before it is marked lower */
  }
  return (g-l);
}

void coordHalf(coord a,coord b, int nwords)
/* It sets a = b/2
   Always the same number of operations
*/
{
  int i;

  for (i =0;i<(nwords-1);i++)         /* It just shifts one bit to the right  */
  {
    a[i]=(b[i]>>1)|(b[i+1]<<BITS63);  /* When shifting it must add the lowest bit of the higher word in pos 63 */
  }
  a[nwords-1] = b[i]>>1;
}

void coordAddAndHalf(coord c,coord a,coord b,coord p,int nwords)
/* It calculates c = (a + b)/2 mod p with a,b< p
   Since a < p and b < p, (a + b)/2 < p and it does not need
   any further operation after the right shift
   Always the same number of operations
*/
{
  uint64_t t;
  int i,r;
  coord d;

  /* It calculates c = a + b */
  r = 0;                                     /* initialize carry bit        */
  for (i=0;i<nwords;i++)
  {
    t = b[i] + r;                            /* adding b and the carry bit  */
    r = t < b[i];                            /* carry bit                   */
    t = t + a[i];                            /* adding a                    */
    r = r | (t < a[i]);                      /* calculate the result carry bit of the 2 sums */
    d[i] = t;
  }
  d[nwords] = r;

  /* It calculates c = c/2 */
  /* coordHalf is not used since it does not considers d[nwords] */
  for (i = 0; i < nwords; ++i)
  {
    c[i]=(d[i]>>1)|(d[i+1]<<BITS63);
  }
  coordInit(d);
}

void coordDouble (coord a,coord b,coord p,int nwords)
/* It calculates a = b^2 mod p with a< p
   Always the same number of operations
*/
{
  uint64_t t,t1;
  coord d;
  int i,r;

  r = b[nwords-1]>>BITS63;

  for (i=nwords-1;i>0;i--)                   /* It just shifts one bit to the left */
  {
    a[i]=(b[i]<<1)|(b[i-1]>>BITS63);         /* When shifting it must add the highest bit of the lower word in pos 0 */
  }
  a[0] = b[0]<<1;

  if ((r == 1)|(coordCmp(a,p,nwords)!=-1))   /* if r==1 or a >= p then a = a-p. See coordSub */
  {
    r = 0;                                   /* initialize carry bit                         */
    for (i=0;i<nwords;i++)
    {
      t1 = a[i]-r;                           /* calculates a - carry bit                     */
      r = t1 > a[i];                         /* carry bit                                    */
      t = t1 - p[i];                         /* now subtract p                               */
      r = r | (t > t1);                      /* calculate the result carry bit of the 2 subs */
      a[i] = t;
    }
  }
  else                                       /* in order to maintain the same number of operations */
  {
    r = 0;
    for (i=0;i<nwords;i++)
    {
      t1 = d[i]-r;                           /* calculates d - carry bit                     */
      r = t1 > a[i];                         /* carry bit                                    */
      t = t1 - p[i];                         /* now subtract p                               */
      r = r | (t > t1);                      /* calculate the result carry bit of the 2 subs */
      d[i] = t;
    }
  }
}

void coordAdd(coord c,coord a,coord b,coord p,int nwords)
/* Algorithm 2.5 Multiprecision addition
   It calculates c = a + b mod p with a,b< p
   Always the same number of operations
*/
{
  uint64_t t,t1;
  coord d;
  int i,r;

  /* It calculates a + b */
  r = 0;                                     /* initialize carry bit                         */
  for (i = 0;i<nwords;i++)
  {
    t = b[i] + r;                            /* adding b and the carry bit                   */
    r = t < b[i];                            /* carry bit                                    */
    t = t + a[i];                            /* adding a                                     */
    r = r | (t < a[i]);                      /* calculate the result carry bit of the 2 sums */
    c[i] = t;
  }
  if ((r == 1)|(coordCmp(c,p,nwords)!=-1))   /* if r==1 or c >= p then c = c-p. See coordSub */
  {
    r = 0;                                   /* initialize carry bit                         */
    for (i=0;i<nwords;i++)
    {
      t1 = c[i]-r;                           /* calculates c - carry bit                     */
      r = t1 > c[i];                         /* carry bit                                    */
      t = t1 - p[i];                         /* now subtract p                               */
      r = r | (t > t1);                      /* calculate the result carry bit of the 2 subs */
      c[i] = t;
    }
  }
  else                                       /* in order to maintain the same number of operations */
  {
    r = 0;
    for (i=0;i<nwords;i++)
    {
      t1 = d[i]-r;                           /* calculates d - carry bit                     */
      r = t1 > c[i];                         /* carry bit                                    */
      t = t1 - p[i];                         /* now subtract p                               */
      r = r | (t > t1);                      /* calculate the result carry bit of the 2 subs */
      d[i] = t;
    }
  }
}

void coordSub(coord c,coord a,coord b,coord p,int nwords)
/* Algorithm 2.6 Multiprecision subtraction
   It calculates c = a - b mod p with a,b< p
   Always the same number of operations
*/
{
  uint64_t t,t1;
  coord d;
  int i,r;

  /* It calculates a - b */
  r = 0;                                       /* initialize carry bit                         */
  for (i=0;i<nwords;i++)
  {
    t1 = a[i]-r;                               /* calculates a - carry bit                     */
    r = t1 > a[i];                             /* carry bit                                    */
    t = t1 - b[i];                             /* now subtract b                               */
    r = r | (t > t1);                          /* calculate the result carry bit of the 2 subs */
    c[i] = t;
  }

  if (r == 1)                                  /* if a - b < 0 so we need to add p. See coordAdd */
  {
    r = 0;                                     /* initialize carry bit                         */
    for (i = 0;i<nwords;i++)
    {
      t = p[i] + r;                            /* adding p and the carry bit                   */
      r = t < p[i];                            /* carry bit                                    */
      t = t + c[i];                            /* adding c                                     */
      r = r | (t < c[i]);                      /* calculate the result carry bit of the 2 sums */
      c[i] = t;
    }
  }
  else                                         /* in order to maintain the same number of operations */
  {
    r = 0;
    for (i = 0;i<nwords;i++)
    {
      t = d[i] + r;                            /* adding d and the carry bit                   */
      r = t < d[i];                            /* carry bit                                    */
      t = t + c[i];                            /* adding c                                     */
      r = r | (t < c[i]);                      /* calculate the result carry bit of the 2 sums */
      d[i] = t;
    }
  }
}


void coordMul(coord c,coord a,coord b,coord p,int nwords)
/* It calculates c = a * b mod p with a,b< p
   Always the same number of operations
*/
{
  int i,j;
  coord t1,t2,t3;

  coordCopy(t1,a);                    /* Initialized t1 to a                                */
  coordCopy(t2,a);                    /* t2 is used only to avoid time attacks              */
  coordInit(t3);                      /* Initialize t3 = 0                                  */

  for (i = 0;i<nwords;i++)            /* word by word                                       */
  {
    for (j = 0;j<BITS64;j++)          /* bit by bit of the word                             */
    {
      if((b[i]>>j)&1)                 /* if the bit j of the word b[i] is one               */
      {
        coordAdd(t3,t3,t1,p,nwords);  /* t3 = t3 + t1 mod p                                   */
      }
      else                            /* in order to maintain the same number of operations */
      {
        coordAdd(t2,t2,t1,p,nwords);
      }
      coordDouble(t1,t1,p,nwords);    /* t1 = 2t1 mod p                                     */
    }
  }
  coordCopy(c,t3);                    /* c = t3                                             */

  coordInit(t1);                      /* Clear t1                                           */
  coordInit(t2);                      /* Clear t2                                           */
  coordInit(t3);                      /* Clear t3                                           */
}

void coordInvML(coord c,coord a,coord p,int nwords)
/* It calculates c = inv(a) mod p with a < p
   In order to maintain the same number of operations it calculates
   c = a^(p-2) mod p with the Montgomery Ladder
*/
{
  coord r0, r1, k;
  int i, n, b;
  coord f0, f1;                      /* Needed to maintain the same number of operations */
  int order;                         /* Needed to maintain the same number of operations */

  order = coordMaxBit(p,nwords);     /* Needed to maintain the same number of operations */
  coordInit(r0);
  r0[0] = 2;                         /* r0 = 2                                           */
  coordSub(k,p,r0,p,nwords);         /* k = p-2                                          */
  n = coordMaxBit(k,nwords);         /* Calculates n                                     */
  r0[0] = 1;                         /* r0 = 1                                           */
  coordCopy(r1,a);                   /* r1 = a                                           */


  for (i=order-1;i>-1;i--)
  {
    b = coordGetBit(k,i);            /* b=ki                                             */
    if (i<n)
    {
      if (b == 0)
      {
        coordMul(r1,r0,r1,p,nwords); /* r1 = r0 * r1                                     */
        coordMul(r0,r0,r0,p,nwords); /* r0 = r0 * r0                                     */
      }
      else
      {
        coordMul(r0,r0,r1,p,nwords); /* r0 = r0 * r1                                     */
        coordMul(r1,r1,r1,p,nwords); /* r1 = r1 * r1                                     */
      }
    }
    else                             /* to maintain the same number of operations        */
    {
      if (b == 0)
      {
        coordMul(f1,f0,f1,p,nwords); /* r1 = r0 * r1                                     */
        coordMul(f0,f0,f0,p,nwords); /* r0 = r0 * r0                                     */
      }
      else
      {
        coordMul(f0,f0,f1,p,nwords); /* r0 = r0 * r1                                     */
        coordMul(f1,f1,f1,p,nwords); /* r1 = r1 * r1                                     */
      }
    }
  }
  coordCopy(c,r0);

  coordInit(r0);                     /* Clear r0                                         */
  coordInit(r1);                     /* Clear r1                                         */
}

void cProjToAffine(pointA* aA,pointP* bP,coord p,int nwords)
/* It converts point bP with Projective coordinates in point aA in Affine coordinates */
{
  coord d;

  coordInvML(d,bP->pZ,p,nwords);             /* d = 1/bP->pZ                                */
  coordMul(aA->aY,d,d,p,nwords);             /* aA->aY = d*d                                */
  coordMul(aA->aX,aA->aY,bP->pX,p,nwords);   /* aA->aX = aA->aY*bP->pX = bP->pX /(bP->Pz)^2 */
  coordMul(aA->aY,aA->aY,d,p,nwords);        /* aA->aY = d*d*d                              */
  coordMul(aA->aY,aA->aY,bP->pY,p,nwords);   /* aA->aY = aA->aY*bP->pY = bP->pY /(bP->Pz)^3 */

  coordInit(d);                              /* Clear d                                     */
}

void cAffineToProj(pointP* aP, pointA* bA,int nwords)
/* It converts point bA with Affine coordinates in point aP in Projective coordinates
   aP->pZ is set to 1.
*/
{
  coordCopy(aP->pX,bA->aX);           /* aP->pX = bA->aX  */
  coordCopy(aP->pY,bA->aY);           /* aP->pY = bA->aY  */
  coordInit(aP->pZ);                  /* aP->pZ = 0       */
  aP->pZ[0] = 1;                      /* aP->pZ = 1       */
}

void copyPointP(pointP* aP, pointP* bP)
/* It sets aP = bP
   Always the same number of operations
*/
{

  coordCopy(aP->pX,bP->pX);           /* aP->pX = bP->pX */
  coordCopy(aP->pY,bP->pY);           /* aP->pY = bP->pY */
  coordCopy(aP->pZ,bP->pZ);           /* aP->pY = bP->pY */
}

int aIsOnCurve(pointA* aA,coord a,coord b,coord p,int nwords)
/* It checks that the point in Affine coordinates is on the curve
   It must verify the curve equation y^2 = x^3 -ax + b mod p
   It returns:
     1 if a is on the curve
	-1 if a is not on the curve
*/
{
  coord t1,t2;

  coordMul(t1,aA->aX,aA->aX,p,nwords);   /* t1 = x^2 mod p       */
  coordMul(t1,t1,aA->aX,p,nwords);       /* t1 = x^3 mod p       */
  coordMul(t2,aA->aX,a,p,nwords);        /* t2 = ax mod p        */
  coordSub(t1,t1,t2,p,nwords);           /* t1 = t1 - t2 mod p   */
  coordAdd(t1,t1,b,p,nwords);            /* t1 = t1 + b mod p    */
  coordMul(t2,aA->aY,aA->aY,p,nwords);   /* t2 = y^2 mod p       */
  if (coordCmp(t1,t2,nwords)==0)
  {
  	return 1;                            /* the equation is verified     */
  }
  else
  {
    return -1;                           /* the equation is not verified */
  }
}

void doubleU(pointP* Q,pointP* R,pointP* P,coord a,coord p,int nwords)
/* Co-Z initial point doubling. Ch. 4.3
   It calculates Q=2P and R=(d*d*Px1:d*d*d*PY1:d) with input P with Z1=1
   and resulting R and Q same Z3
   Always the same number of operations
*/
{
  coord t1,t2,t3,t4,t5,t6,t7,t8;

  coordCopy(t1,P->pX);            /* t1 = X1                                    */
  coordCopy(t2,P->pY);            /* t2 = Y1                                    */
  coordMul(t3,t1,t1,p,nwords);    /* t3 = t1 * t1; B = X1^2                     */
  coordDouble(t4,t3,p,nwords);
  coordAdd(t4,t4,t3,p,nwords);    /* t4 = 3 * t3;  3B                           */
  coordSub(t4,t4,a,p,nwords);     /* t4 = t4 - a;  M = 3B - a (original formula with "-" because of negative representation of a) */
  coordMul(t5,t2,t2,p,nwords);    /* t5 = t2 * t2; E = Y1^2                     */
  coordMul(t6,t5,t5,p,nwords);    /* t6 = t5 * t5; L = E^2                      */
  coordAdd(t7,t1,t5,p,nwords);    /* t7 = t1 + t5; X1 + E                       */
  coordMul(t7,t7,t7,p,nwords);    /* t7 = t7 * t7; (X1 + E)^2                   */
  coordSub(t7,t7,t3,p,nwords);    /* t7 = t7 - t3; (X1 + E)^2 - B               */
  coordSub(t7,t7,t6,p,nwords);    /* t7 = t7 - t6; (X1 + E)^2 - B - L           */
  coordDouble(t7,t7,p,nwords);    /* t7 = 2 * t7;  S = 2((X1 + E)^2 - B - L)    */
  coordMul(t3,t4,t4,p,nwords);    /* t3 = t4 * t4; M^2                          */
  coordDouble(t8,t7,p,nwords);    /* t8 = 2 * t7;  2S                           */
  coordSub(t3,t3,t8,p,nwords);    /* t3 = t3 - t8; X(2P) = M^2 - 2S             */
  coordSub(t8,t7,t3,p,nwords);    /* t8 = t7 - t3; S - X(2P)                    */
  coordMul(t8,t4,t8,p,nwords);    /* t8 = t4 * t8; M * (S - X(2P))              */
  coordDouble(t4,t6,p,nwords);
  coordDouble(t4,t4,p,nwords);
  coordDouble(t4,t4,p,nwords);    /* t4 = 8 * t6;  Y(P) = 8L                    */
  coordSub(t8,t8,t4,p,nwords);    /* t8 = t8 - t4; Y(2P) = M * (S - X(2P)) - 8L */
  coordDouble(t6,t2,p,nwords);    /* t6 = 2 * t2;  Z(2P) = Z(P) = 2Y1           */
  coordDouble(t1,t1,p,nwords);
  coordDouble(t1,t1,p,nwords);    /* t1 = 4 * t1;  4X1                          */
  coordMul(t1,t1,t5,p,nwords);    /* t1 = t1 * t5; X(P)= 4X1 * E                */

  coordCopy(Q->pX,t3);            /* QX = M^2 - 2S                              */
  coordCopy(Q->pY,t8);            /* QY = M * (S - X(2P)) - 8L                  */
  coordCopy(Q->pZ,t6);            /* QZ = 2Y1                                   */
  coordCopy(R->pX,t1);            /* RX = 4X1 * E                               */
  coordCopy(R->pY,t4);            /* RY = 8L                                    */
  coordCopy(R->pZ,t6);            /* RZ = 2Y1                                   */

  coordInit(t1);                  /* Clear t1                                   */
  coordInit(t3);                  /* Clear t3                                   */
  coordInit(t4);                  /* Clear t4                                   */
  coordInit(t6);                  /* Clear t6                                   */
  coordInit(t8);                  /* Clear t8                                   */
}

void zAddC(pointP* R,pointP* S,pointP* P,pointP* Q,coord p,int nwords)
/* Algorithm 12, Conjugate co-Z point addition (register allocation).
   It calculates R=P+Q and S=P-Q with input P and Q same Z and resulting R and S same Z3
   Always the same number of operations
*/
{
  coord t1, t2, t3, t4, t5, t6, t7;

  coordCopy(t1,P->pX);           /* t1 = X1           */
  coordCopy(t2,P->pY);           /* t2 = Y1           */
  coordCopy(t3,P->pZ);           /* t3 = Z            */
  coordCopy(t4,Q->pX);           /* t4 = X2           */
  coordCopy(t5,Q->pY);           /* t5 = Y2           */

  coordSub(t6,t1,t4,p,nwords);   /* t6 = t1 - t4      */
  coordMul(t3,t3,t6,p,nwords);   /* t3 = t3 * t6      */
  coordMul(t6,t6,t6,p,nwords);   /* t6 = t6 * t6      */
  coordMul(t7,t1,t6,p,nwords);   /* t7 = t1 * t6      */
  coordMul(t6,t6,t4,p,nwords);   /* t6 = t6 * t4      */
  coordAdd(t1,t2,t5,p,nwords);   /* t1 = t2 + t5      */
  coordMul(t4,t1,t1,p,nwords);   /* t4 = t1 * t1      */
  coordSub(t4,t4,t7,p,nwords);   /* t4 = t4 - t7      */
  coordSub(t4,t4,t6,p,nwords);   /* t4 = t4 - t6      */
  coordSub(t1,t2,t5,p,nwords);   /* t1 = t2 - t5      */
  coordMul(t1,t1,t1,p,nwords);   /* t1 = t1 * t1      */
  coordSub(t1,t1,t7,p,nwords);   /* t1 = t1 - t7      */
  coordSub(t1,t1,t6,p,nwords);   /* t1 = t1 - t6      */
  coordSub(t6,t6,t7,p,nwords);   /* t6 = t6 - t7      */
  coordMul(t6,t6,t2,p,nwords);   /* t6 = t6 * t2      */
  coordSub(t2,t2,t5,p,nwords);   /* t2 = t2 - t5      */
  coordDouble(t5,t5,p,nwords);   /* t5 = 2 * t5       */
  coordAdd(t5,t2,t5,p,nwords);   /* t5 = t2 + t5      */
  coordSub(t7,t7,t4,p,nwords);   /* t7 = t7 - t4      */
  coordMul(t5,t5,t7,p,nwords);   /* t5 = t5 * t7      */
  coordAdd(t5,t5,t6,p,nwords);   /* t5 = (t5 + t6)    */
  coordAdd(t7,t4,t7,p,nwords);   /* t7 = t4 + t7      */
  coordSub(t7,t7,t1,p,nwords);   /* t7 = t7 - t1      */
  coordMul(t2,t2,t7,p,nwords);   /* t2 = t2 * t7      */
  coordAdd(t2,t2,t6,p,nwords);   /* t2 = (t2 + t6)    */

  coordCopy(R->pX,t1);           /* RX = t1           */
  coordCopy(R->pY,t2);           /* RY = t2           */
  coordCopy(R->pZ,t3);           /* RZ = t3           */
  coordCopy(S->pX,t4);           /* SX = t4           */
  coordCopy(S->pY,t5);           /* SY = t5           */
  coordCopy(S->pZ,t3);           /* SZ = t3           */

  coordInit(t1);                 /* Clear t1          */
  coordInit(t2);                 /* Clear t2          */
  coordInit(t3);                 /* Clear t3          */
  coordInit(t4);                 /* Clear t4          */
  coordInit(t5);                 /* Clear t5          */
}

void zAddU(pointP* R,pointP* P2,pointP* P,pointP* Q,coord p,int nwords)
/* Algorithm 11 Co-Z point addition with update (register allocation)
   It calculates R=P+Q and P2=(d*d*Px1:d*d*dPY1:d*PZ1) with input P and Q
   same Z1 and resulting R and P2 same Z3
   Always the same number of operations
*/
{
  coord t1, t2, t3, t4, t5, t6;

  coordCopy(t1,P->pX);           /* t1 = X1           */
  coordCopy(t2,P->pY);           /* t2 = Y1           */
  coordCopy(t3,P->pZ);           /* t3 = Z            */
  coordCopy(t4,Q->pX);           /* t4 = X2           */
  coordCopy(t5,Q->pY);           /* t5 = Y2           */

  coordSub(t6,t1,t4,p,nwords);   /* t6 = t1 - t4      */
  coordMul(t3,t3,t6,p,nwords);   /* t3 = t3 * t6      */
  coordMul(t6,t6,t6,p,nwords);   /* t6 = t6 ** 2      */
  coordMul(t1,t1,t6,p,nwords);   /* t1 = t1 * t6      */
  coordMul(t6,t6,t4,p,nwords);   /* t6 = t6 * t4      */
  coordSub(t5,t2,t5,p,nwords);   /* t5 = t2 - t5      */
  coordMul(t4,t5,t5,p,nwords);   /* t4 = t5 ** 2      */
  coordSub(t4,t4,t1,p,nwords);   /* t4 = t4 - t1      */
  coordSub(t4,t4,t6,p,nwords);   /* t4 = t4 - t6      */
  coordSub(t6,t1,t6,p,nwords);   /* t6 = t1 - t6      */
  coordMul(t2,t2,t6,p,nwords);   /* t2 = t2 * t6      */
  coordSub(t6,t1,t4,p,nwords);   /* t6 = t1 - t4      */
  coordMul(t5,t5,t6,p,nwords);   /* t5 = t5 * t6      */
  coordSub(t5,t5,t2,p,nwords);   /* t5 = t5 - t2      */

  coordCopy(R->pX,t4);           /* RX  = t4          */
  coordCopy(R->pY,t5);           /* RY  = t5          */
  coordCopy(R->pZ,t3);           /* RZ  = t3          */
  coordCopy(P2->pX,t1);          /* P2X = t1          */
  coordCopy(P2->pY,t2);          /* P2Y = t2          */
  coordCopy(P2->pZ,t3);          /* P2Z = t3          */

  coordInit(t1);                 /* Clear t1          */
  coordInit(t2);                 /* Clear t2          */
  coordInit(t3);                 /* Clear t3          */
  coordInit(t4);                 /* Clear t4          */
  coordInit(t5);                 /* Clear t5          */
  coordInit(t6);                 /* Clear t6          */
}

void scalarMult(pointA* Q,coord k,pointA* P,coord a,coord p,int nwords)
/* Algorithm 7, Montogomery ladder with co-Z addition formula for GF(p)
   Input: P belonging to E(Fq) and k = (kn-1,...,k0)2 with kn-1=1 and k < p
          P with Z=1 for initial DBLU
   Output: Q = kP
   Always the same number of operations
*/
{
  pointP R0,R1;
  pointP S0,S1;                          /* Needed to maintain the same number of operations               */
  int i, n, b;
  int order;                             /* Needed to maintain the same number of operations               */

  order = coordMaxBit(p,nwords);         /* Needed to maintain the same number of operations               */
  n = coordMaxBit(k,nwords);             /* Calculates n                                                   */
  coordCopy(R0.pX,P->aX);
  coordCopy(R0.pY,P->aY);                /* R0=P                                                           */
  doubleU(&R1,&R0,&R0,a,p,nwords);       /* (R1,R0)=DBLU(R0),i.e. R1=2R0 and R0=R0 with same Z and Z1=1    */
  for (i=order-2;i>-1;i--)
  {
    b = coordGetBit(k,i);                /* b=ki                                                           */
    if (i<n-1)
    {
      if (b == 0)
      {
        zAddC(&R1,&R0,&R0,&R1,p,nwords); /* (R1,R0) = ZADDC(R0,R1), i.e. calculate R1=R0+R1 and R0=R0-R1   */
                                         /*   with input R0 and R1 same Z and resulting R0 and r1 same Z3  */
        zAddU(&R0,&R1,&R1,&R0,p,nwords); /* (R0,R1) = ZADDU(R1,R0), i.e. R0=R1+R0 and R1=(d*d*R1x1:d*d*dR1Y1:d*R1Z1) */
                                         /*   with input R1 and R0 same Z1 and resulting R0 and R1 same Z3 */
      }
      else
      {
        zAddC(&R0,&R1,&R1,&R0,p,nwords); /* (R0,R1) = ZADDC(R1,R0)                                         */
        zAddU(&R1,&R0,&R0,&R1,p,nwords); /* (R1,R0) = ZADDU(R0,R1)                                         */
      }
    }
    else                                 /* to maintain the same number of operations                      */
    {
      if (b == 0)
      {
        zAddC(&S1,&S0,&S0,&S1,p,nwords);
        zAddU(&S0,&S1,&S1,&S0,p,nwords);
      }
      else
      {
        zAddC(&S0,&S1,&S1,&S0,p,nwords);
        zAddU(&S1,&S0,&S0,&S1,p,nwords);
      }
    }
  }

  cProjToAffine(Q,&R0,p,nwords);         /* Q = affine(R0)                                                */

  coordInit(R0.pX);                      /* Clear R0.pX                                                   */
  coordInit(R0.pY);                      /* Clear R0.pY                                                   */
  coordInit(R0.pZ);                      /* Clear R0.pZ                                                   */
  coordInit(R1.pX);                      /* Clear R1.pX                                                   */
  coordInit(R1.pY);                      /* Clear R1.pY                                                   */
  coordInit(R1.pZ);                      /* Clear R1.pZ                                                   */
}

int selectCurve(ellipticCurve* curve,int index)
/* It selects the elliptic curve among the ones recommended by NIST
     FIPS PUB 186-4, Digital Signature Standard (DSS)
   The ones proposed here are the ones over Prime Fields
     with the following equation: y^2 = x^3 -ax + b mod p
   By using the routines included in this package, new curves can be built
     over different primes.
   Curve parameters are represented as in the NIST with less significant word on the right
*/
{
  int i,j;

  const coord P192_p  = {0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFFFFFFFFFF};
  const coord P192_a  = {0x0000000000000000, 0x0000000000000000, 0x0000000000000003};
  const coord P192_b  = {0x64210519e59c80e7, 0x0fa7e9ab72243049, 0xfeb8deecc146b9b1};
  const coord P192_gX = {0x188da80eb03090f6, 0x7cbf20eb43a18800, 0xf4ff0afd82ff1012};
  const coord P192_gY = {0x07192b95ffc8da78, 0x631011ed6b24cdd5, 0x73f977a11e794811};

  const coord P224_p  = {0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFF00000000, 0x0000000000000001};
  const coord P224_a  = {0x00000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000003};
  const coord P224_b  = {0xb4050a85, 0x0c04b3abf5413256, 0x5044b0b7d7bfd8ba, 0x270b39432355ffb4};
  const coord P224_gX = {0xb70e0cbd, 0x6bb4bf7f321390b9, 0x4a03c1d356c21122, 0x343280d6115c1d21};
  const coord P224_gY = {0xbd376388, 0xb5f723fb4c22dfe6, 0xcd4375a05a074764, 0x44d5819985007e34};

  const coord P256_p  = {0xFFFFFFFF00000001, 0x0000000000000000, 0x00000000FFFFFFFF, 0xFFFFFFFFFFFFFFFF};
  const coord P256_a  = {0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000003};
  const coord P256_b  = {0x5ac635d8aa3a93e7, 0xb3ebbd55769886bc, 0x651d06b0cc53b0f6, 0x3bce3c3e27d2604b};
  const coord P256_gX = {0x6b17d1f2e12c4247, 0xf8bce6e563a440f2, 0x77037d812deb33a0, 0xf4a13945d898c296};
  const coord P256_gY = {0x4fe342e2fe1a7f9b, 0x8ee7eb4a7c0f9e16, 0x2bce33576b315ece, 0xcbb6406837bf51f5};

  const coord P384_p  = {0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFE, 0xFFFFFFFF00000000, 0x00000000FFFFFFFF};
  const coord P384_a  = {0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000003};
  const coord P384_b  = {0xb3312fa7e23ee7e4, 0x988e056be3f82d19, 0x181d9c6efe814112, 0x0314088f5013875a, 0xc656398d8a2ed19d, 0x2a85c8edd3ec2aef};
  const coord P384_gX = {0xaa87ca22be8b0537, 0x8eb1c71ef320ad74, 0x6e1d3b628ba79b98, 0x59f741e082542a38, 0x5502f25dbf55296c, 0x3a545e3872760ab7};
  const coord P384_gY = {0x3617de4a96262c6f, 0x5d9e98bf9292dc29, 0xf8f41dbd289a147c, 0xe9da3113b5f0b8c0, 0x0a60b1ce1d7e819d, 0x7a431d7c90ea0e5f};

  const coord P521_p  = {0x000001FF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF};
  const coord P521_a  = {0x00000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000000, 0x0000000000000003};
  const coord P521_b  = {0x00000051, 0x953eb9618e1c9a1f, 0x929a21a0b68540ee, 0xa2da725b99b315f3, 0xb8b489918ef109e1, 0x56193951ec7e937b, 0x1652c0bd3bb1bf07, 0x3573df883d2c34f1, 0xef451fd46b503f00};
  const coord P521_gX = {0x000000c6, 0x858e06b70404e9cd, 0x9e3ecb662395b442, 0x9c648139053fb521, 0xf828af606b4d3dba, 0xa14b5e77efe75928, 0xfe1dc127a2ffa8de, 0x3348b3c1856a429b, 0xf97e7e31c2e5bd66};
  const coord P521_gY = {0x00000118, 0x39296a789a3bc004, 0x5c8a5fb42c7d1bd9, 0x98f54449579b4468, 0x17afbd17273e662c, 0x97ee72995ef42640, 0xc550b9013fad0761, 0x353c7086a272c240, 0x88be94769fd16650};

  switch(index)
  {
    case NIST_P192:
    	curve->bsize = NIST_P192;
    	curve->wsize = (NIST_P192+BITS63)/BITS64;
      for (i=0;i<curve->wsize;i++)
      {
        /* curve parameters are represented as in the NIST with less significant word on the right */
        /* but in the arrays the less significant word is in [0] position                          */
        j = curve->wsize-1-i;
        curve->p[i]    = P192_p[j];
        curve->a[i]    = P192_a[j];
        curve->b[i]    = P192_b[j];
        curve->g.aX[i] = P192_gX[j];
        curve->g.aY[i] = P192_gY[j];
      }
      break;

    case NIST_P224:
    	curve->bsize = NIST_P224;
    	curve->wsize = (NIST_P224+BITS63)/BITS64;
      for (i=0;i<curve->wsize;i++)
      {
        /* curve parameters are represented as in the NIST with less significant word on the right */
        /* but in the arrays the less significant word is in [0] position                          */
        j = curve->wsize-1-i;
        curve->p[i]    = P224_p[j];
        curve->a[i]    = P224_a[j];
        curve->b[i]    = P224_b[j];
        curve->g.aX[i] = P224_gX[j];
        curve->g.aY[i] = P224_gY[j];
      }
      break;

    case NIST_P256:
    	curve->bsize = NIST_P256;
    	curve->wsize = (NIST_P256+BITS63)/BITS64;
      for (i=0;i<curve->wsize;i++)
      {
        /* curve parameters are represented as in the NIST with less significant word on the right */
        /* but in the arrays the less significant word is in [0] position                          */
        j = curve->wsize-1-i;
        curve->p[i]    = P256_p[j];
        curve->a[i]    = P256_a[j];
        curve->b[i]    = P256_b[j];
        curve->g.aX[i] = P256_gX[j];
        curve->g.aY[i] = P256_gY[j];
      }
      break;

    case NIST_P384:
    	curve->bsize = NIST_P384;
    	curve->wsize = (NIST_P384+BITS63)/BITS64;
      for (i=0;i<curve->wsize;i++)
      {
        /* curve parameters are represented as in the NIST with less significant word on the right */
        /* but in the arrays the less significant word is in [0] position                          */
        j = curve->wsize-1-i;
        curve->p[i]    = P384_p[j];
        curve->a[i]    = P384_a[j];
        curve->b[i]    = P384_b[j];
        curve->g.aX[i] = P384_gX[j];
        curve->g.aY[i] = P384_gY[j];
      }
      break;

    case NIST_P521:
    	curve->bsize = NIST_P521;
    	curve->wsize = (NIST_P521+BITS63)/BITS64;
      for (i=0;i<curve->wsize;i++)
      {
        /* curve parameters are represented as in the NIST with less significant word on the right */
        /* but in the arrays the less significant word is in [0] position                          */
        j = curve->wsize-1-i;
        curve->p[i]    = P521_p[j];
        curve->a[i]    = P521_a[j];
        curve->b[i]    = P521_b[j];
        curve->g.aX[i] = P521_gX[j];
        curve->g.aY[i] = P521_gY[j];
      }
      break;

    default:
      return -1;
  }
  return 1;
}

void byteToWord(coord arrayW,uint8_t *arrayB,int byteLen)
/* It converts array of bytes to array of words of 64 bits */
{
  int i,j,k,s;
  j=(byteLen)/BYTES8;

  for (i=0;i<j;i++)
  {
    s = i*BYTES8-1;
    arrayW[i] = arrayB[BYTES8+s];
    for (k=BYTES7+s;k>s;k--)
    {
      arrayW[i] = (arrayW[i]<<8) + arrayB[k];
    }
  }
  s=(byteLen+BYTES7)/BYTES8;

  if (j<s)
  {
    s = j*BYTES8-1;
    arrayW[j] = arrayB[byteLen-1];
    for (i=(byteLen-2);i>s;i--)
    arrayW[j] = (arrayW[j]<<8) + arrayB[i];
  }
}


void wordToByte(uint8_t *arrayB,coord arrayW,int wordLen)
/* It converts array of of words of 64 bits to array of bits */
{
  int i,j,k;
  uint64_t t;

  for (i=0;i<wordLen;i++)
  {
    t = arrayW[i];
    j = i*BYTES8;
    for (k=0;k<BYTES8;k++)
    {
      arrayB[j+k] = (uint8_t)(t&0xFF);
      t = t>>8;
    }
  }
}

void convPointToBytes(keyC pX,keyC pY,pointA* aP,ellipticCurve* curve)
/* It converts aP in byte arrays pX and pY */
{
  wordToByte(pX,aP->aX,curve->wsize); /* Convert coord x of aP in byte array format */
  wordToByte(pY,aP->aY,curve->wsize); /* Convert coord y of aP in byte array format */
}

int convBytesToPoint(pointA* aP,keyC pX,keyC pY,ellipticCurve* curve)
/* It converts byte arrays pX and pY in aP */
{
  int byteLen;

  byteLen = (curve->bsize+7)/8;

  byteToWord(aP->aX,pX,byteLen); /* Convert pX in coord format  */
  byteToWord(aP->aY,pY,byteLen); /* Convert pY in coord format  */

  if (coordCmp(aP->aX,curve->p,curve->wsize) != -1) return -1;  /* coordinates must be lower than p */
  if (coordCmp(aP->aY,curve->p,curve->wsize) != -1) return -1;  /* coordinates must be lower than p */

  return 1;

}


int generateRand(keyC num,ellipticCurve* curve)
/* It generates non cryptographic secure random numbers mod p
   by using rand() function and Keccak functions
*/
{
  int i,r,res,inputByteLen;
  keyC msg;
  coord h;
  uint64_t t,t1;

  inputByteLen=(curve->bsize+7)/8;

  for (i=0;i<inputByteLen;i++)                   /* random number by using rand() */
  {
    msg[i] = 0xFF&rand();
  }

  switch(curve->bsize)                           /* use Keccak routines to hash the random number */
  {
  	case NIST_P224:
  		res = SHA3_224(num,msg,inputByteLen);
  		break;

  	case NIST_P256:
  		res = SHA3_256(num,msg,inputByteLen);
  		break;

  	case NIST_P384:
  		res = SHA3_384(num,msg,inputByteLen);
  		break;

  	case NIST_P521:
  		res = KeccakWidth1600_Sponge(576, 1024, msg, inputByteLen, 0x06, num, 528/8);
  		num[65] = num[65]&1; /* NIST_521 has only 1 bit in byte[65] */
  		break;

     default:
        return -1;
  }

  if (res!=0)
    return -1;

  byteToWord(h,num,inputByteLen);

  if (coordCmp(h,curve->p,curve->wsize)==0)  /* if h = p then error                          */
	return -1;
  if (coordCmp(h,curve->p,curve->wsize)!=-1) /* if h > p then h = h - p                      */
  {
    r = 0;                                   /* initialize carry bit                         */
    for (i=0;i<curve->wsize;i++)
    {
      t1 = h[i]-r;                           /* calculates h - carry bit                     */
      r = t1 > h[i];                         /* carry bit                                    */
      t = t1 - curve->p[i];                  /* now subtract p                               */
      r = r | (t > t1);                      /* calculate the result carry bit of the 2 subs */
      h[i] = t;
    }
  }
  else
  {
    r = 0;                                   /* initialize carry bit                         */
    for (i=0;i<curve->wsize;i++)
    {
      t1 = msg[i]-r;                         /* calculates msg - carry bit                   */
      r = t1 > msg[i];                       /* carry bit                                    */
      t = t1 - curve->p[i];                  /* now subtract p                               */
      r = r | (t > t1);                      /* calculate the result carry bit of the 2 subs */
      msg[i] = t;
    }
  }

  wordToByte(num,h,curve->wsize);

  memset(msg,0,COORD_BYTES);                 /* clear msg                                    */
  coordInit(h);                              /* clear h                                      */

  return 1;
}


int randomGen(uint8_t* esk,int nbits)
/* It returns a random number of nbits
   It uses the getrandom C function based on the urandom source in linux
      (i.e., the same source as the /dev/urandom device). See <sys/random.h>
   It should be replaced by BCryptGenRandom in windows system, getentropy in OpenBSD
*/
{
  int buflen;

  buflen = (nbits+7)/8;

  if (getrandom(esk, buflen, GRND_RANDOM)<buflen)
    return -1;
  return 1;
}

void publicKey(keyC pkx,keyC pky,keyC sk,ellipticCurve* curveN)
/* It returns the public key pk from the secret key sk
   pk = G*sk
*/
{
  coord t1;
  pointA t2;
  int byteLen;

  byteLen = (curveN->bsize+7)/8;

  byteToWord(t1,sk,byteLen);                /* Convert sk to t in coord format             */
  scalarMult(&t2,t1,&curveN->g,curveN->a,curveN->p,curveN->wsize); /* t2 = G*sk            */
  wordToByte(pkx,t2.aX,curveN->wsize);      /* Convert coord x of t2 in byte array format  */
  wordToByte(pky,t2.aY,curveN->wsize);      /* Convert coord y of t2 in byte array format  */

  coordInit(t1);                            /* Clear t1                                    */
  coordInit(t2.aX);                         /* Clear t2.aX                                 */
  coordInit(t2.aY);                         /* Clear t2.aY                                 */
}

int hashAndMod(coord h,keyC esk,keyC sk,ellipticCurve* curveN)
/* It calculates h=H(esk,sk) mod p */
{
  int res,inputByteLen,r,i;
  uint8_t msg[DOUBLEW_BYTES];
  keyC hashed;
  uint64_t t,t1;
  coord h1;

  inputByteLen = (curveN->bsize+7)/8;

  for (i=0;i<inputByteLen;i++)                      /* Concatenate esk and sk in msg */
  {
    msg[i] = esk[i];
    msg[i+inputByteLen] = sk[i];
  }

  inputByteLen= inputByteLen*2;

  switch(curveN->bsize)                             /* Calculate hashed=H(esk,sk)     */
  {
  	case NIST_P224:
  		res = SHA3_224(hashed,msg,inputByteLen);
  		break;

  	case NIST_P256:
  		res = SHA3_256(hashed,msg,inputByteLen);
  		break;

  	case NIST_P384:
  		res = SHA3_384(hashed,msg,inputByteLen);
  		break;

  	case NIST_P521:
  		res = KeccakWidth1600_Sponge(576, 1024, msg, inputByteLen, 0x06, hashed, 528/8);
  		hashed[65] = hashed[65]&1; /* NIST_521 has only 1 bit in byte[65] */
  		break;

    default:
      return -1;
  }

  memset(msg,0,DOUBLEW_BYTES);              /* Clear msg                                         */

  if (res!=0)
    return -1;

  inputByteLen = inputByteLen/2;

  byteToWord(h,hashed,inputByteLen);         /* Convert hashed to h in coord format               */

  if (coordCmp(h,curveN->p,curveN->wsize)==1)/* if h > p then h = h - p                           */
  {
    r = 0;                                   /* initialize carry bit                              */
    for (i=0;i<curveN->wsize;i++)
    {
      t1 = h[i]-r;                           /* calculates h - carry bit                           */
      r = t1 > h[i];                         /* carry bit                                          */
      t = t1 - curveN->p[i];                 /* now subtract p                                     */
      r = r | (t > t1);                      /* calculate the result carry bit of the 2 subs       */
      h[i] = t;
    }
  }
  else                                       /* In order to maintain the same number of operations */
  {
    r = 0;                                   /* initialize carry bit                               */
    for (i=0;i<curveN->wsize;i++)
    {
      t1 = h1[i]-r;                          /* calculates h1 - carry bit                          */
      r = t1 > h[i];                         /* carry bit                                          */
      t = t1 - curveN->p[i];                 /* now subtract p                                     */
      r = r | (t > t1);                      /* calculate the result carry bit of the 2 subs       */
      h1[i] = t;
    }
  }

  memset(hashed,0,COORD_BYTES);              /* Clear hashed                                       */

  return 1;
}

void calculateXY(keyC Xx,keyC Xy,keyC esk,keyC sk,ellipticCurve* curveN)
/* Generate esk and calculate X=G*H(esk,sk):
     1. generate the random esk
     2. calculate H(esk,sk)
     3. if H(esk,sk)==0 goto step 1
     4. calculate X=G*H(esk,sk)
*/
{
  coord h;
  pointA X;

  do
  {
    randomGen(esk,curveN->bsize);              /* Generate eskB using an entropy source     */
    hashAndMod(h,esk,sk,curveN);               /* Calculate h = H(esk,sk)                   */
 } while (1 == coordIsZero(h,curveN->wsize));  /* h must be different than 0                */

  scalarMult(&X,h,&curveN->g,curveN->a,curveN->p,curveN->wsize); /* X = G*h = G*H(esk,sk)   */
  wordToByte(Xx,X.aX,curveN->wsize);           /* Convert coord x of X in byte array format */
  wordToByte(Xy,X.aY,curveN->wsize);           /* Convert coord y of X in byte array format */

  coordInit(h);                                /* clear h                                   */
  coordInit(X.aX);                             /* clear X.aX                                */
  coordInit(X.aY);                             /* clear X.aY                                */
}

int isOnTheCurve(pointA* pA,ellipticCurve* curveN)
/* It checks that the point in Affine coordinates is on the curve
   It must verify the curve equation y^2 = x^3 -ax + b mod p
   It returns 1 when it is verified
*/
{
  return aIsOnCurve(pA,curveN->a,curveN->b,curveN->p,curveN->wsize);
}

int calculateKa(keyC kA,keyC Yx,keyC Yy,keyC eskA,keyC skAb, keyC pkBx, keyC pkBy,keyC idA,keyC idB,ellipticCurve* curveN)
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
{
  pointA pkB,Y,t1A,t2A,t3A;        /* Temporary points on the curve   */
  coord skA,hA;                    /* Temporary coordinates           */
  uint8_t msg[FIVET_BYTES];
  int byteLen,inputByteLen,t,res,i;

  if (convBytesToPoint(&pkB,pkBx,pkBy,curveN)!= 1) return -1; /* The coords are not lower than p       */
  if (isOnTheCurve(&pkB,curveN) != 1) return -2;              /* pkB is not on the curve               */
  if (convBytesToPoint(&Y,Yx,Yy,curveN)!= 1) return -3;       /* The coords are not lower than p       */
  if (isOnTheCurve(&Y,curveN) != 1) return -4;                /* Y is not on the curve                 */

  byteLen = (curveN->bsize+7)/8;
  byteToWord(skA,skAb,byteLen);                               /* Convert skAb to skA in coord format   */
  hashAndMod(hA,eskA,skAb,curveN);                            /* Calculate hA = H(eskA,skA)            */

  scalarMult(&t1A,skA,&Y,curveN->a,curveN->p,curveN->wsize);  /* Calculate t1A=Y*skA                   */
  if (isOnTheCurve(&t1A,curveN) != 1) return -5;              /* t1A is not on the curve               */

  scalarMult(&t2A,hA,&pkB,curveN->a,curveN->p,curveN->wsize); /* Calculate t2A=pkB*hA=pkB*H(eskA,skA)  */
  if (isOnTheCurve(&t2A,curveN) != 1) return -5;              /* t2A is not on the curve               */

  scalarMult(&t3A,hA,&Y,curveN->a,curveN->p,curveN->wsize);   /* Calculate t3A=Y*hA=Y*H(eskA,skA)      */
  if (isOnTheCurve(&t3A,curveN) != 1) return -5;              /* t3A is not on the curve               */


  wordToByte(msg,t1A.aX,curveN->wsize);                       /* Append coord x of t1A to msg          */
  wordToByte(&msg[byteLen],t2A.aX,curveN->wsize);             /* Append coord x of t2A to msg          */

  inputByteLen = byteLen*2;

  wordToByte(&msg[inputByteLen],t3A.aX,curveN->wsize);        /* Append coord x of t3A to msg          */

  t = inputByteLen + byteLen;
  inputByteLen = t + byteLen;

  for (i=0;i<byteLen;i++)                                     /* Append idA and idB to msg             */
  {
  	msg[t+i] = idA[i];
  	msg[inputByteLen+i] = idB[i];
  }

  inputByteLen = inputByteLen + byteLen;

  switch(curveN->bsize)
  {
  	case NIST_P224:
  		res = SHA3_224(kA,msg,inputByteLen);
  		break;

  	case NIST_P256:
  		res = SHA3_256(kA,msg,inputByteLen);
  		break;

  	case NIST_P384:
  		res = SHA3_384(kA,msg,inputByteLen);
  		break;

  	case NIST_P521:
  		res = SHA3_512(kA,msg,inputByteLen);
  		break;

    default:
      return -1;
  }

  memset(msg, 0, FIVET_BYTES);         /* clear msg                */
  coordInit(pkB.aX);                   /* clear pkB.aX             */
  coordInit(pkB.aY);                   /* clear pkB.aY             */
  coordInit(Y.aX);                     /* clear Y.azX               */
  coordInit(Y.aY);                     /* clear Y.azY               */
  coordInit(t1A.aX);                   /* clear t1A.aX             */
  coordInit(t1A.aY);                   /* clear t1A.aY             */
  coordInit(t2A.aX);                   /* clear t2A.aX             */
  coordInit(t2A.aY);                   /* clear t2A.aY             */
  coordInit(t3A.aX);                   /* clear t3A.aX             */
  coordInit(t3A.aY);                   /* clear t3A.aY             */
  coordInit(skA);                      /* clear skA                */
  coordInit(hA);                       /* clear hA                 */

  if (res!=0)
    return -1;

  return 1;
}

int calculateKb(keyC kB,keyC pkAx, keyC pkAy,keyC eskB,keyC skBb,keyC Xx,keyC Xy,keyC idA,keyC idB,ellipticCurve* curveN)
/* It calculates kB using the x coordinates of the points on the curve
   kB = H(pkA*H(eskB,skB), X*skB, X*H(eskB,skB), idA, idB)
   Return:
     1 = OK
     -1 = coord of pkA are not mod p
     -2 = pkA is not on the curve
     -3 = coord of X are not mod p
     -4 = X is not on the curve
     -5 = internal error
*/
{
  pointA pkA,X,t1B,t2B,t3B;        /* Temporary points on the curve   */
  coord skB,hB;                    /* Temporary coordinates           */
  uint8_t msg[FIVET_BYTES];
  int byteLen,inputByteLen,t,res,i;

  if (convBytesToPoint(&pkA,pkAx,pkAy,curveN)!= 1) return -1; /* The coords are not lower than p     */
  if (isOnTheCurve(&pkA,curveN) != 1) return -2;              /* pkB is not on the curve             */
  if (convBytesToPoint(&X,Xx,Xy,curveN)!= 1) return -3;       /* The coords are not lower than p     */
  if (isOnTheCurve(&X,curveN) != 1) return -4;                /* Y is not on the curve               */

  byteLen = (curveN->bsize+7)/8;
  byteToWord(skB,skBb,byteLen);                               /* Convert skBb to skB in coord format */
  hashAndMod(hB,eskB,skBb,curveN);                            /* Calculate hB = H(eskB,skB)          */

  scalarMult(&t1B,hB,&pkA,curveN->a,curveN->p,curveN->wsize); /* Calculate t1B=pkA*hB=pkA*H(eskB,skB */
  if (isOnTheCurve(&t1B,curveN) != 1) return -5;              /* t1A is not on the curve             */

  scalarMult(&t2B,skB,&X,curveN->a,curveN->p,curveN->wsize);  /* Calculate t2B=X*skB                 */
  if (isOnTheCurve(&t2B,curveN) != 1) return -5;              /* t2B is not on the curve             */

  scalarMult(&t3B,hB,&X,curveN->a,curveN->p,curveN->wsize);   /* Calculate t2B=X*hB=X*H(eskB,skB)    */
  if (isOnTheCurve(&t3B,curveN) != 1) return -5;              /* t3B is not on the curve             */

  byteLen = (curveN->bsize+7)/8;

  wordToByte(msg,t1B.aX,curveN->wsize);                       /* Append coord x of t1B to msg        */
  wordToByte(&msg[byteLen],t2B.aX,curveN->wsize);             /* Append coord x of t2B to msg        */

  inputByteLen = byteLen*2;

  wordToByte(&msg[inputByteLen],t3B.aX,curveN->wsize);        /* Append coord x of t3B to msg        */

  t = inputByteLen + byteLen;
  inputByteLen = t + byteLen;

  for (i=0;i<byteLen;i++)                                     /* Append idA and idB to msg           */
  {
  	msg[t+i] = idA[i];
  	msg[inputByteLen+i] = idB[i];
  }

  inputByteLen = inputByteLen + byteLen;

  switch(curveN->bsize)
  {
  	case NIST_P224:
  		res = SHA3_224(kB,msg,inputByteLen);
  		break;

  	case NIST_P256:
  		res = SHA3_256(kB,msg,inputByteLen);
  		break;

  	case NIST_P384:
  		res = SHA3_384(kB,msg,inputByteLen);
  		break;

  	case NIST_P521:
  		res = SHA3_512(kB,msg,inputByteLen);
  		break;

    default:
      return -1;
  }

  memset(msg, 0, FIVET_BYTES);         /* clear msg                */
  coordInit(pkA.aX);                   /* clear pkA.aX             */
  coordInit(pkA.aY);                   /* clear pkA.aY             */
  coordInit(X.aX);                     /* clear X.aX               */
  coordInit(X.aY);                     /* clear X.aY               */
  coordInit(t1B.aX);                   /* clear t1B.aX             */
  coordInit(t1B.aY);                   /* clear t1B.aY             */
  coordInit(t2B.aX);                   /* clear t2B.aX             */
  coordInit(t2B.aY);                   /* clear t2B.aY             */
  coordInit(t3B.aX);                   /* clear t3B.aX             */
  coordInit(t3B.aY);                   /* clear t3B.aY             */
  coordInit(skB);                      /* clear skB                */
  coordInit(hB);                       /* clear hB                 */
  
  if (res==1)
    return -1;

  return 1;
}

