#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "Naxos.h"
#include <string.h>


void printW64(uint64_t word64)
{
  printf("%08X",(uint32_t)((word64>>32)&0xFFFFFFFF));
  printf("%08X",(uint32_t)((word64)&0xFFFFFFFF));
}
void printW64s(uint64_t word64)
{
  printf("%08x",(uint32_t)((word64>>32)&0xFFFFFFFF));
  printf(" ");
  printf("%08x",(uint32_t)((word64)&0xFFFFFFFF));
}

void sendToMate(char *strIn,keyC msg,int inputByteLen)
{
  int i;

  printf("%s",strIn);

  for (i=inputByteLen-1;i>-1;i--)
  {
    printf("%02X",msg[i]);
  }
  printf("\n");
}


int main()
{

  ellipticCurve curveN;                         // chosen curve
  keyC idA,idB,pkAx,pkAy,pkBx,pkBy;             // all keys or identifiers exchanged in byte array format
  keyC eskA,eskB,kA,kB,Xx,Xy,Yx,Yy;             // all keys or identifiers exchanged in byte array format
  keyC skA,skB;                                 // all internal information in coord format

  int i,res,z,indexC, nBytes;

  srand(time(0));                               // Initialize the the standard rand() function

  for (z=0;z<4;z++)
  {
    switch(z)
    {
      case (0):
        indexC = NIST_P224;
        printf("Curve is NIST P224, keys are 224 bits long\n");
        printf("==========================================\n\n");
        break;

      case (1):
        indexC = NIST_P256;
        printf("Curve is NIST P256, keys are 256 bits long\n");
        printf("==========================================\n\n");
        break;

      case (2):
        indexC = NIST_P384;
        printf("Curve is NIST P384, keys are 384 bits long\n");
        printf("==========================================\n\n");
        break;
      default:
        indexC = NIST_P521;
        printf("Curve is NIST P521, keys are 512 bits long\n");
        printf("==========================================\n\n");
    }

    clock_t start, end, startTot, endTot;
    float elapsed_time;

    // Test Naxos key exchange

    // Phase 0
    // Select curve. Use NIST_P224, NIST_P256, NIST_P384 or NIST_P521
    selectCurve(&curveN,indexC);
    nBytes = (curveN.bsize+7)/8;

    start = clock();
    startTot = start;

    // Phase 0A
    //   The identity idA and skA should be available.
    //   pkA should already be available before the key exchange.
    //   Here we generate a random idA and skA for the demo
    //   and we calculate pkA = G*skA.
    generateRand(idA,&curveN);                // Generate idA using the rand function. To be used only for demo.
    generateRand(skA,&curveN);                // Generate skA using the rand function. To be used only for demo.
    // Check that skA != 0
    publicKey(pkAx,pkAy,skA,&curveN);        // Calculate pkA from skA

    // Phase 1A
    //   Generate eskA and calculate X=G*H(eskA,skA).
    //   Done by calculateXY which also secures that H(eskA,skA) != 0
    //   This is sent to B (it could be sent together with idA and pkA).
    //   The type of curve should already be communicated, otherwise it could
    //   be another info to share
    calculateXY(Xx,Xy,eskA,skA,&curveN);

    // send to B (if not already known) idA, pkAx, pkAy
    sendToMate("IdA:  ",idA,nBytes);
    sendToMate("pkAx: ",pkAx,nBytes);
    sendToMate("pkAy: ",pkAy,nBytes);
    // send to B Xx, Xy
    sendToMate("Xx:   ",Xx,nBytes);
    sendToMate("Xy:   ",Xy,nBytes);

    end = clock();
    elapsed_time = (float)(end - start) / (float)CLOCKS_PER_SEC;
    printf("Elapsed time: %f seconds\n\n", elapsed_time);

    start = clock();

    // Phase 0B
    //   The identity idB and skB should be available.
    //   pkB should already be available before the key exchange.
    //   Here we generate a random idB and skB for the demo
    //   and we calculate pkB = G*skB.
    generateRand(idB,&curveN);                // Generate idB using the rand function. To be used only for demo.
    generateRand(skB,&curveN);                // Generate skB using the rand function. To be used only for demo.
    publicKey(pkBx,pkBy,skB,&curveN);        // Calculate pkB from skB

    // Phase 1B
    //   Generate eskB and calculate Y=G*H(eskB,skB).
    //   Done by calculateXY which also secures that H(eskB,skB) != 0
    //   It is sent to A (it could be sent together with idB and pkB)
    calculateXY(Yx,Yy,eskB,skB,&curveN);
    // send to A (if not already known) idB, pkBx, pkBy
    sendToMate("IdB:  ",idB,nBytes);
    sendToMate("pkBx: ",pkBx,nBytes);
    sendToMate("pkBy: ",pkBy,nBytes);
    // send to A Yx, Yy
    sendToMate("Yx:   ",Yx,nBytes);
    sendToMate("Yy:   ",Yy,nBytes);

    end = clock();
    elapsed_time = (float)(end - start) / (float)CLOCKS_PER_SEC;
    printf("Elapsed time: %f seconds\n\n", elapsed_time);

    start = clock();

    // Phase 2A
    // A receives Y and calculates kA:
    //     2A-0: convert pkBx and pkBy in coord format and check if it belongs to the curve
    //     2A-1: convert Yx and Yy in coord format and checks if it belongs to the curve
    //     2A-2: calculate Y*skA           => only coord x is used in the Hash function
    //     2A-3: calculate pkB*H(eskA,skA) => only coord x is used in the Hash function
    //     2A-4: calculate Y*H(eskA,skA)   => only coord x is used in the Hash function
    //     2A-5: calculate kA = H(Y*skA, pkB*H(eskA,skA), Y*H(eskA,skA), idA, idB)

    res = calculateKa(kA,Yx,Yy,eskA,skA,pkBx,pkBy,idA,idB,&curveN);  // kA is returned in array of bytes

    switch(res)
      {
        case -1:
          printf("Invalid pkB: it is not mod p\n");
          return -1;

        case -2:
          printf("Invalid pkB: it is not on the curve\n");
          return -1;

        case -3:
          printf("Invalid Y: it is not mod p\n");
          return -1;

        case -4:
          printf("Invalid Y: it is not on the curve\n");
          return -1;

        case -5:
          printf("Internal error in Ka\n");
          return -1;

        default:
          break;
      }

    if (indexC==NIST_P521) nBytes=64;                            // we provide a key of 512 bits instead

    sendToMate("kA:   ",kA,nBytes);

    end = clock();
    elapsed_time = (float)(end - start) / (float)CLOCKS_PER_SEC;
    printf("Elapsed time: %f seconds\n\n", elapsed_time);

    start = clock();

    // Phase 2B
    // B receives X and calculates kB:
    //     2B-0: convert pkAx and pkAy in coord format and check if it belongs to the curve
    //     2B-1: convert Xx and Xy in coord format and check if it belongs to the curve
    //     2B-2: calculate pkA*H(eskB,skB) => only coord x is used in the Hash function
    //     2B-3: calculate X*skB           => only coord x is used in the Hash function
    //     2B-4: calculate X*H(eskB,skB)   => only coord x is used in the Hash function
    //     2B-5: calculate kB = H(pkA*H(eskB,skB), X*skB, X*H(eskB,skB), idA, idB)
    res=calculateKb(kB,pkAx,pkAy,eskB,skB,Xx,Xy,idA,idB,&curveN);
    switch(res)
      {
        case -1:
          printf("Invalid pkB: it is not mod p\n");
          return -1;

        case -2:
          printf("Invalid pkB: it is not on the curve\n");
          return -1;

        case -3:
          printf("Invalid Y: it is not mod p\n");
          return -1;

        case -4:
          printf("Invalid Y: it is not on the curve\n");
          return -1;

        case -5:
          printf("Internal error in Kb\n");
          return -1;

        default:
          break;
      }

    sendToMate("kB:   ",kB,nBytes);

    end = clock();
    endTot = end;
    elapsed_time = (float)(end - start) / (float)CLOCKS_PER_SEC;
    printf("Elapsed time: %f seconds\n", elapsed_time);
    elapsed_time = (float)(endTot - startTot) / (float)CLOCKS_PER_SEC;
    printf("Total elapsed time: %f seconds\n\n", elapsed_time);

    for (i=0;i<nBytes;i++)
    {
    	if (kA[i] != kB[i])
    	{
    		res=0;
    		break;
    	}
    	else
    	{
    		res=1;
    	}
    }

    if (res==1) printf("Successful, kA=kB \n");
    printf("\n\n");
  }

  return 1;
}
