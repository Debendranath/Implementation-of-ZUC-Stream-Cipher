/**
 * TITLE: Implementation of ZUC M (a modified ZUC 1.4) Stream Cipher.
 * AUTHOR: Debendranath Das, SRF, Indian Statistical Institute.
 * DATE: 09.08.2023
**/

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<ctype.h>

#define MAX 4294967291 //(2^32-5)
#define MIN 1
#define CYCLIC_SHIFT(a, k) (((a) << k) | ((a) >> (32 - k)))

/* Global Variables */
unsigned char S_Box_0[16][16] = 
{
/**   0     1    2    3    4    5   6    7    8    9    A    B    C    D   E    F     **/
    {0x3e,0x72,0x5b,0x47,0xca,0xe0,0x00,0x33,0x04,0xd1,0x54,0x98,0x09,0xb9,0x6d,0xcb},//0
    {0x7b,0x1b,0xf9,0x32,0xaf,0x9d,0x6a,0xa5,0xb8,0x2d,0xfc,0x1d,0x08,0x53,0x03,0x90},//1
    {0x4d,0x4e,0x84,0x99,0xe4,0xce,0xd9,0x91,0xdd,0xb6,0x85,0x48,0x8b,0x29,0x6e,0xac},//2
    {0xcd,0xc1,0xf8,0x1e,0x73,0x43,0x69,0xc6,0xb5,0xbd,0xfd,0x39,0x63,0x20,0xd4,0x38},//3
    {0x76,0x7d,0xb2,0xa7,0xcf,0xed,0x57,0xc5,0xf3,0x2c,0xbb,0x14,0x21,0x06,0x55,0x9b},//4
    {0xe3,0xef,0x5e,0x31,0x4f,0x7f,0x5a,0xa4,0x0d,0x82,0x51,0x49,0x5f,0xba,0x58,0x1c},//5
    {0x4a,0x16,0xd5,0x17,0xa8,0x92,0x24,0x1f,0x8c,0xff,0xd8,0xae,0x2e,0x01,0xd3,0xad},//6
    {0x3b,0x4b,0xda,0x46,0xeb,0xc9,0xde,0x9a,0x8f,0x87,0xd7,0x3a,0x80,0x6f,0x2f,0xc8},//7
    {0xb1,0xb4,0x37,0xf7,0x0a,0x22,0x13,0x28,0x7c,0xcc,0x3c,0x89,0xc7,0xc3,0x96,0x56},//8
    {0x07,0xbf,0x7e,0xf0,0x0b,0x2b,0x97,0x52,0x35,0x41,0x79,0x61,0xa6,0x4c,0x10,0xfe},//9
    {0xbc,0x26,0x95,0x88,0x8a,0xb0,0xa3,0xfb,0xc0,0x18,0x94,0xf2,0xe1,0xe5,0xe9,0x5d},//A
    {0xd0,0xdc,0x11,0x66,0x64,0x5c,0xec,0x59,0x42,0x75,0x12,0xf5,0x74,0x9c,0xaa,0x23},//B
    {0x0e,0x86,0xab,0xbe,0x2a,0x02,0xe7,0x67,0xe6,0x44,0xa2,0x6c,0xc2,0x93,0x9f,0xf1},//C
    {0xf6,0xfa,0x36,0xd2,0x50,0x68,0x9e,0x62,0x71,0x15,0x3d,0xd6,0x40,0xc4,0xe2,0x0f},//D
    {0x8e,0x83,0x77,0x6b,0x25,0x05,0x3f,0x0c,0x30,0xea,0x70,0xb7,0xa1,0xe8,0xa9,0x65},//E
    {0x8d,0x27,0x1a,0xdb,0x81,0xb3,0xa0,0xf4,0x45,0x7a,0x19,0xdf,0xee,0x78,0x34,0x60} //F
}; 

unsigned char S_Box_1[16][16] = 
{
/**   0     1    2    3    4    5   6    7    8    9    A    B    C    D   E    F     **/
    {0x55,0xc2,0x63,0x71,0x3b,0xc8,0x47,0x86,0x9f,0x3c,0xda,0x5b,0x29,0xaa,0xfd,0x77},//0
    {0x8c,0xc5,0x94,0x0c,0xa6,0x1a,0x13,0x00,0xe3,0xa8,0x16,0x72,0x40,0xf9,0xf8,0x42},//1
    {0x44,0x26,0x68,0x96,0x81,0xd9,0x45,0x3e,0x10,0x76,0xc6,0xa7,0x8b,0x39,0x43,0xe1},//2
    {0x3a,0xb5,0x56,0x2a,0xc0,0x6d,0xb3,0x05,0x22,0x66,0xbf,0xdc,0x0b,0xfa,0x62,0x48},//3
    {0xdd,0x20,0x11,0x06,0x36,0xc9,0xc1,0xcf,0xf6,0x27,0x52,0xbb,0x69,0xf5,0xd4,0x87},//4
    {0x7f,0x84,0x4c,0xd2,0x9c,0x57,0xa4,0xbc,0x4f,0x9a,0xdf,0xfe,0xd6,0x8d,0x7a,0xeb},//5
    {0x2b,0x53,0xd8,0x5c,0xa1,0x14,0x17,0xfb,0x23,0xd5,0x7d,0x30,0x67,0x73,0x08,0x09},//6
    {0xee,0xb7,0x70,0x3f,0x61,0xb2,0x19,0x8e,0x4e,0xe5,0x4b,0x93,0x8f,0x5d,0xdb,0xa9},//7
    {0xad,0xf1,0xae,0x2e,0xcb,0x0d,0xfc,0xf4,0x2d,0x46,0x6e,0x1d,0x97,0xe8,0xd1,0xe9},//8
    {0x4d,0x37,0xa5,0x75,0x5e,0x83,0x9e,0xab,0x82,0x9d,0xb9,0x1c,0xe0,0xcd,0x49,0x89},//9
    {0x01,0xb6,0xbd,0x58,0x24,0xa2,0x5f,0x38,0x78,0x99,0x15,0x90,0x50,0xb8,0x95,0xe4},//A
    {0xd0,0x91,0xc7,0xce,0xed,0x0f,0xb4,0x6f,0xa0,0xcc,0xf0,0x02,0x4a,0x79,0xc3,0xde},//B
    {0xa3,0xef,0xea,0x51,0xe6,0x6b,0x18,0xec,0x1b,0x2c,0x80,0xf7,0x74,0xe7,0xff,0x21},//C
    {0x5a,0x6a,0x54,0x1e,0x41,0x31,0x92,0x35,0xc4,0x33,0x07,0x0a,0xba,0x7e,0x0e,0x34},//D
    {0x88,0xb1,0x98,0x7c,0xf3,0x3d,0x60,0x6c,0x7b,0xca,0xd3,0x1f,0x32,0x65,0x04,0x28},//E
    {0x64,0xbe,0x85,0x9b,0x2f,0x59,0x8a,0xd7,0xb0,0x25,0xac,0xaf,0x12,0x03,0xe2,0xf2} //F
};

unsigned int D[16] = 
{
    0x44D7, 0x26BC, 0x626B, 0x135E, 0x5789, 0x35E2, 0x7135, 0x09AF,
    0x4D78, 0x2F13, 0x6BC4, 0x1AF1, 0x5E26, 0x3C4D, 0x789A, 0x47AC
};

unsigned char KEY[16]; //each cell 8 bit. total = 8*16 = 128 bits. Each cell contains two hex digits.
unsigned char IV[16]; //each cell 8 bit. total = 8*16 = 128 bits. Each cell contains two hex digits.
unsigned int LFSR_S[16]; //each cell 32 bit.
unsigned int X[4]; //each cell 32 bit.
unsigned int R1,R2; //32 bit.

/* Declaration of Functions' Prototype */
unsigned char* displayBitPattern(unsigned int);
unsigned char* displayHex(unsigned int);
unsigned char getHexChar(unsigned int);
unsigned char* getHigherOrder16Bits(unsigned int);
unsigned char* getLowerOrder16Bits(unsigned int);
unsigned int toDecimal(unsigned char*);
unsigned int multiplyByPowerOfTwo(unsigned int, unsigned int);
unsigned int L1(unsigned int); 
unsigned int L2(unsigned int); 
unsigned int compute_SBox(unsigned int);
unsigned int F();
unsigned char validKey(unsigned char *);
void processKey(unsigned char *);
unsigned char validIV(unsigned char *);
void processIV(unsigned char *);
unsigned char hexToChar(unsigned char *);
void LFSRLoad();
void initialize(unsigned char *,unsigned  char *);
unsigned int* produceKeyStream(unsigned int); 

/* Function main */
int main()
{
    unsigned int outputKeyStreamSize,numberOfkeyWords,i;
    unsigned int *streamOfKeys;
    unsigned char key[35], iv[35];
    
    printf("\n****************************************************************************************************\n");
    printf("*                               ZUC M (Modified Version of ZUC 1.4)                                *");
    printf("\n****************************************************************************************************\n");
    //Getting Input: 16-Byte Key
    do
    {
        printf("\nPlease enter a 16-Byte Key in Hexadecimal Form (32 Hex Digits): ");
        scanf("%s",key);
        if(validKey(key) == '0')
        {
            printf("\nThe given Key is INVALID. Please try again!!\n");
        }    
    }while(validKey(key) != '1');
    
    //Getting Input: 16-Byte IV
    do
    {
        printf("\nPlease enter a 16-Byte IV in Hexadecimal Form (32 Hex Digits):  ");
        scanf("%s",iv);
        if(validIV(iv) == '0')
        {
            printf("\nThe given IV is INVALID. Please try again!!\n");
        }
    }while(validIV(iv) != '1');
    
    //Getting Input: Output Key Stream Size
    do
    {
        printf("\nPlease enter the required size of the Output Key Stream in Bytes (it should be multiple of 4): ");
        scanf("%u",&outputKeyStreamSize);
        if((outputKeyStreamSize%4) != 0)
        {
            printf("\nError. The size of Output Key Stream must be a multiple of 4 bytes. Please try again!!\n");
        }
    }while((outputKeyStreamSize%4) != 0);
    
    numberOfkeyWords = (outputKeyStreamSize/4);
    initialize(key,iv);
    streamOfKeys = produceKeyStream(numberOfkeyWords);
    printf("\nTotal No of Generated Key-words (4 Bytes each): %u\n",numberOfkeyWords);
    for(i=0;i<numberOfkeyWords;i++)
    {
        printf("\nKey-word %02d: %s (0x%s)",i+1,displayBitPattern(streamOfKeys[i]), displayHex(streamOfKeys[i]));
    }

    printf("\n\n****************************************************************************************************\n");
    printf("*                                OUTPUT KEY STREAM (SIZE: %u Bytes)                               *",outputKeyStreamSize);
    printf("\n****************************************************************************************************\n");
    printf("\n******************************************** In Binary *********************************************\n\n");
    for(i=0;i<numberOfkeyWords;i++)
    {
        printf("%s",displayBitPattern(streamOfKeys[i]));
    }
    printf("\n\n***************************************** In Hexadecimal *******************************************\n\n");
    printf("0x");
    for(i=0;i<numberOfkeyWords;i++)
    {
        printf("%s",displayHex(streamOfKeys[i]));
    }
    printf("\n");
    return(0);
}

/* Utility Function: Binary String Representation of an Unsigned Integer  */
unsigned char* displayBitPattern(unsigned int a)
{
    unsigned int len,b;
    int i;
    unsigned char *ptr;
    len = sizeof(int)*8 + 1; //additional 1 for Null unsigned character.
    ptr = (char*)malloc(len);
    if(ptr == NULL)
    {
        //printf("Memory can't be allocated! Malloc fails.");
        exit(0);
    }
    b = a;
    for(i=len-2;i>=0;i--)
    {
        if((b & 1) == 1)
        {
            ptr[i] = '1';
        }
        else
        {
            ptr[i] = '0';
        }
        b = b >> 1;
    }
    ptr[len-1] = '\0';
    //printf("\n%s\n",ptr);
    return(ptr);
}

/* Utility Function: Hexadecimal Representation of an unsigned Integer */
unsigned char* displayHex(unsigned int a)
{
    unsigned int nibble,len;
    int i,j;
    unsigned char *ptr = displayBitPattern(a);
    len = sizeof(unsigned int)*2 + 1;
    unsigned char *hex;
    hex = (unsigned char*)malloc(sizeof(len));
    for(i=0,j=0;i<len-1,j<32;i++,j=j+4)
    {
        nibble = (ptr[j]-'0')*8 + (ptr[j+1]-'0')*4 + (ptr[j+2] - '0')*2 + (ptr[j+3] - '0')*1;
        hex[i] = getHexChar(nibble);
    }
    hex[len-1] = '\0';
    return(hex);
}

/* Utility Function: Getting a Hex Digit from Integer belongs to [0,15] */
unsigned char getHexChar(unsigned int x)
{
    switch(x)
    {
        case 0: return('0');
        case 1: return('1');
        case 2: return('2');
        case 3: return('3');
        case 4: return('4');
        case 5: return('5');
        case 6: return('6');
        case 7: return('7');
        case 8: return('8');
        case 9: return('9');
        case 10: return('A');
        case 11: return('B');
        case 12: return('C');
        case 13: return('D');
        case 14: return('E');
        case 15: return('F');
    }
}

/* Utility Function: Extracting Higher Order 16 bits of an Unsigned Integer */
unsigned char* getHigherOrder16Bits(unsigned int a)
{
    unsigned char *ptr;
    ptr = (unsigned char*)malloc(17); //16 bits + 1 bit for null unsigned char..
    if(ptr == NULL)
    {
        //printf("Memory can't be allocated! Malloc fails.");
        exit(0);
    }
    unsigned char *bin = displayBitPattern(a);
    int i;
    for(i=0;i<16;i++)
    {
        ptr[i] = bin[i];
    }
    ptr[16] = '\0';
    return(ptr);
}

/* Utility Function: Extracting Lower Order 16 bits of an Unsigned Integer */
unsigned char* getLowerOrder16Bits(unsigned int a)
{
    unsigned char *ptr;
    ptr = (unsigned char*)malloc(17); //16 bits + 1 bit for null unsigned char..
    if(ptr == NULL)
    {
        //printf("Memory can't be allocated! Malloc fails.");
        exit(0);
    }
    unsigned char *bin = displayBitPattern(a);
    int i;
    for(i=16;i<32;i++)
    {
        ptr[i-16] = bin[i];
    }
    ptr[16] = '\0';
    return(ptr);
}

/* Utility Function: Converting a Binary string to equivalent Integer value */
unsigned int toDecimal(unsigned char *ptr)
{
    unsigned int sum,len;
    int i,j;
    len = strlen(ptr);
    sum = 0;
    for(i=len-1,j=0;i>=0;i--,j++)
    {
        if(ptr[i]=='1')
        {
            sum += (1<<j);
        }
    }
    return(sum);
}

/* Computing (a*2^b)%(2^32-5) */
unsigned int multiplyByPowerOfTwo(unsigned int a, unsigned int b) {
    unsigned long  mul = ((unsigned long)a << b)%MAX;
    return (unsigned int)mul;
}

/* Top Layer of ZUC: LFSR with initialization mode */
void LFSRWithInitializationMode(unsigned int u)
{
    unsigned long v,term1,term2,term3,term4,s_16;
    int i;
    v = 0;
    //Evaluating v = 2^23*LFSR_S[5] + 2^8*LFSR_S[3] + 2^9*LFSR_S[1] + LFSR_S[0];
    
    term1 = LFSR_S[0]%MAX; //LFSR_S[0]
    v = term1;

    term2 = multiplyByPowerOfTwo(LFSR_S[1],9); //2^9*LFSR_S[1]
    v = (v + term2)%MAX;

    term3 = multiplyByPowerOfTwo(LFSR_S[3],8); //2^8*LFSR_S[3]
    v = (v + term3)%MAX;

    term4 = multiplyByPowerOfTwo(LFSR_S[5],23); //2^23*LFSR_S[5]
    v = (v + term4)%MAX;

    //Computing LFSR_S[16] i.e. feedback.
    s_16 = (u+v)%MAX;
    if(s_16 == 0)
    {
        s_16 = MAX;
    }

    //Updating LFSR State..
    for(i=0;i<15;i++)
    {
        LFSR_S[i] = LFSR_S[i+1];
    }
    LFSR_S[15] = (unsigned int)s_16;
}

/* Top Layer of ZUC: LFSR with working mode */
void LFSRWithWorkMode()
{
    unsigned long s_16,term1,term2,term3,term4;
    int i;
    s_16 = 0;

    //Evaluating v = 2^23*LFSR_S[5] + 2^8*LFSR_S[3] + 2^9*LFSR_S[1] + LFSR_S[0];
    term1 = LFSR_S[0]%MAX; // LFSR_S[0]
    s_16 = term1;

    term2 = multiplyByPowerOfTwo(LFSR_S[1],9); //2^9*LFSR_S[1]
    s_16 = (s_16 + term2)%MAX;

    term3 = multiplyByPowerOfTwo(LFSR_S[3],8); //2^8*LFSR_S[3]
    s_16 = (s_16 + term3)%MAX;

    term4 = multiplyByPowerOfTwo(LFSR_S[5],23); //2^23*LFSR_S[5]
    s_16 = (s_16 + term4)%MAX;

    if(s_16 == 0)
    {
        s_16 = MAX;
    }

    //Updating LFSR State..
    for(i=0;i<15;i++)
    {
        LFSR_S[i] = LFSR_S[i+1];
    }
    LFSR_S[15] = (unsigned int)s_16;
}

/* Middle Layer of ZUC: Bit Reorganization */
void bitReorganization()
{
    unsigned char *x[4];

    x[0] = strcat(getHigherOrder16Bits(LFSR_S[15]), getHigherOrder16Bits(LFSR_S[14]));
    X[0] = toDecimal(x[0]);
    //printf("\nx[0] = %s (len = %ld) \nx[0] = %u\n",x[0],strlen(x[0]),X[0]);

    x[1] = strcat(getHigherOrder16Bits(LFSR_S[13]), getLowerOrder16Bits(LFSR_S[11]));
    X[1] = toDecimal(x[1]);
    //printf("\nx[1] = %s (len = %ld) \nx[1] = %u\n",x[1],strlen(x[1]),X[1]);

    x[2] = strcat(getHigherOrder16Bits(LFSR_S[7]), getLowerOrder16Bits(LFSR_S[5]));
    X[2] = toDecimal(x[2]);
    //printf("\nx[2] = %s (len = %ld) \nx[2] = %u\n",x[1],strlen(x[2]),X[2]);

    x[3] = strcat(getLowerOrder16Bits(LFSR_S[3]), getLowerOrder16Bits(LFSR_S[1]));
    X[3] = toDecimal(x[3]);
    //printf("\nx[3] = %s (len = %ld) \nx[3] = %u\n",x[3],strlen(x[3]),X[3]);
}

/* Bottom Layer of ZUC: Non Linear Function F */
unsigned int F()
{
    unsigned int W,W1,W2;
    unsigned long temp;

    temp = ( (((unsigned long)X[0] + R1) % MAX) + R2 ) % (1<<31); //2^32 = (1<<31) = 4294967296
    W = (unsigned int)temp;
    //printf("\nW = %u (%X)",W,W);

    temp = ((unsigned long)R1 + X[1]) % (1<<31); //2^32 = (1<<31) = 4294967296
    W1 = (unsigned int)temp;
    //printf("\nW1 = %u (%x)",W1,W1); 

    temp = ((unsigned long)R2 + X[2]) % MAX;
    W2 = (unsigned int)temp;
    //printf("\nW2 = %u (%x)",W2,W2);

    char *p1 = strcat(getLowerOrder16Bits(W1),getHigherOrder16Bits(W2));
    char *p2 = strcat(getLowerOrder16Bits(W2),getHigherOrder16Bits(W1));
    /** 
    printf("\nW1 = %s",displayBitPattern(W1));
    printf("\nW1 = %s%s",getHigherOrder16Bits(W1),getLowerOrder16Bits(W1));
    printf("\nW2 = %s",displayBitPattern(W2));
    printf("\nW2 = %s%s",getHigherOrder16Bits(W2),getLowerOrder16Bits(W2));
    printf("\np1 = %s (%u)",p1,toDecimal(p1));
    printf("\np2 = %s (%u)\n",p2,toDecimal(p2)); 
    **/

    unsigned int c1,c2;
    c1 = L1(toDecimal(p1));
    c2 = L2(toDecimal(p2));

    R1 = compute_SBox(c1);
    R2 = compute_SBox(c2);

    return(W);
}

/* linear transformation L1 */
unsigned int L1(unsigned int x) 
{
    return (x ^ CYCLIC_SHIFT(x, 2) ^ CYCLIC_SHIFT(x, 10) ^ CYCLIC_SHIFT(x, 18) ^ CYCLIC_SHIFT(x, 24));
}

/* linear transformation L2 */
unsigned int L2(unsigned int x) 
{
    return (x ^ CYCLIC_SHIFT(x, 8) ^ CYCLIC_SHIFT(x, 14) ^ CYCLIC_SHIFT(x, 22) ^ CYCLIC_SHIFT(x, 30));
}

/* SBox Computation */
unsigned int compute_SBox(unsigned int x)
{
    unsigned int x_nibble[8]; //higher order nibble index = 0.
    x_nibble[0] = (x & 0xF0000000)>>28;
    x_nibble[1] = (x & 0x0F000000)>>24;
    x_nibble[2] = (x & 0x00F00000)>>20;
    x_nibble[3] = (x & 0x000F0000)>>16;
    x_nibble[4] = (x & 0x0000F000)>>12;
    x_nibble[5] = (x & 0x00000F00)>>8;
    x_nibble[6] = (x & 0x000000F0)>>4;
    x_nibble[7] = (x & 0x0000000F);

    unsigned int y[4];
    y[0] = (unsigned int)S_Box_0[x_nibble[0]][x_nibble[1]];
    y[1] = (unsigned int)S_Box_1[x_nibble[2]][x_nibble[3]];
    y[2] = (unsigned int)S_Box_0[x_nibble[4]][x_nibble[5]];
    y[3] = (unsigned int)S_Box_1[x_nibble[6]][x_nibble[7]];
    
    //printf("\nS_Box_0[%x][%x] = %x\nS_Box_1[%x][%x] = %x\nS_Box_0[%x][%x] = %x\nS_Box_1[%x][%x] = %x\n",x_nibble[0],x_nibble[1],y[0],x_nibble[2],x_nibble[3],y[1],x_nibble[4],x_nibble[5],y[2],x_nibble[6],x_nibble[7],y[3]);
    
    unsigned int output;
    output = ((y[0]<<24)|(y[1]<<16)|(y[2]<<8)|y[3]);
    
    //printf("\n%x\n",output);
    return(output);
}

/* Check for valid input key */
unsigned char validKey(unsigned char *k)
{
    if(k[1] == 'x' || k[1] == 'X')
    {
        k = &k[2];
    }
    //printf("\nKey = %s (%ld)\n",k,strlen(k));
    unsigned int len,i;
    char ch;
    len = strlen(k);
    if(len != 32)
    {
        return('0');
    }
    for(i=0;i<32;i++)
    {
        k[i] = tolower(k[i]);
        ch = k[i];
        if ( (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') )
        {
            return('0');
        }
    }
    return('1');
}

/* Check for valid input IV */
unsigned char validIV(unsigned char *iv)
{
    if(iv[1] == 'x' || iv[1] == 'X')
    {
        iv = &iv[2];
    }
    unsigned int len,i;
    char ch;
    len = strlen(iv);
    if(len != 32)
    {
        return('0');
    }
    for(i=0;i<32;i++)
    {
        iv[i] = tolower(iv[i]);
        ch = iv[i];
        if ( (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') )
        {
            return('0');
        }
    }
    return('1');
}

/* Conversion from hex string of 2 digit (e.g. "ab") to unsigned char 0xab */
unsigned char hexToChar(unsigned char *hex) 
{
    unsigned char result = 0;
    unsigned char c;
    for (int i = 0; i < 2; i++) 
    {
        c = hex[i];
        if (c >= '0' && c <= '9') 
        {
            result = (result << 4) | (c - '0');
        } 
        else if(c >= 'a' && c <= 'f') 
        {
            result = (result << 4) | (c - 'a' + 10);
        }
    }
    return result;
}

/* Segmenting the 16 bytes Key into 16 parts, each of 1 byte */
void processKey(unsigned char *k)
{
    int i;
    unsigned char temp[3];
    for(i=0;i<16;i++)
    {
        temp[0] = k[2*i];
        temp[1] = k[2*i+1];
        temp[2] = '\0';
        KEY[i] = hexToChar(temp);
        //printf("\n%x",KEY[i]);
    }
}

/* Segmenting the 16 bytes IV into 16 parts, each of 1 byte */
void processIV(unsigned char *iv)
{
    int i;
    unsigned char temp[3];
    for(i=0;i<16;i++)
    {
        temp[0] = iv[2*i];
        temp[1] = iv[2*i+1];
        temp[2] = '\0';
        IV[i] = hexToChar(temp);
        //printf("\n%x",IV[i]);
    }
}

/* Loading the LFSR Register Words with initial values */
void LFSRLoad() 
{
    int i;
    for(i=0;i<16;i++)
    {
        LFSR_S[i] = ((unsigned int)KEY[i]<<23)|((unsigned int)D[i]<<8)|(unsigned int)IV[i] ; //concat(KEY[i]||D[i]||IV[i])
        /* 
        printf("\nKEY[%d]:    %s",i,displayBitPattern((unsigned int)KEY[i]<<23));
        printf("\nD[%d]:      %s",i,displayBitPattern((unsigned int)D[i]<<8));
        printf("\nIV[%d]:     %s",i,displayBitPattern((unsigned int)IV[i]));
        printf("\nLFSR_S[%d]:  %s",i,displayBitPattern(LFSR_S[i]));
        */
    }
}

/* Initialization of ZUC Process */ 
void initialize(unsigned char *key, unsigned char *iv)
{
    int i;
    unsigned int w;
    //printf("\nKey: %s",key); //key = ABCDEF01234567899876543210ABCDEF
    processKey(key);
    //printf("\nIV: %s",iv); //iv = 1234567890FEDCBA0123456789ABCDEF
    processIV(iv);
    LFSRLoad();
    R1 = 0;
    R2 = 0;
    for(i=0;i<32;i++)
    {
        bitReorganization();
        w = F();
        LFSRWithInitializationMode(w>>1);
    }
}

/* Generating Key Stream */
unsigned int* produceKeyStream(unsigned int no_of_keys)
{
    int i;
    bitReorganization();
    F();
    LFSRWithWorkMode();

    unsigned int *keyStream;
    keyStream = (unsigned int*)malloc(sizeof(unsigned int)*no_of_keys);
    if(keyStream == NULL)
    {
        exit(0);
    }
    for(i=0;i<no_of_keys;i++)
    {
        bitReorganization();
        keyStream[i] = F() ^ X[3];
        LFSRWithWorkMode();
    }
    return(keyStream);
}
