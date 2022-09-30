#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "src/aes.h"

void printCharInHexadecimal(const unsigned char* str, int len) {
  for (int i = 0; i < len; ++ i) {

    unsigned char val = str[i];

    char tbl[] = "0123456789ABCDEF";
    //printf("0x");
    printf("%c", tbl[val / 16]);
    printf("%c", tbl[val % 16]);
    //printf(" ");
  }
  printf("\n");
}
//hex[] = "E848D8FFFF8B0D";
unsigned char* convertToHex(char* hex){
    char *p;
    unsigned char c;
    int cnt = strlen(hex)/2;

    unsigned char *result = (unsigned char *)malloc(cnt), *r;
    for (p = hex, r = result; *p; p += 2) {
        if (sscanf(p, "%02X", (unsigned int *)&c) != 1) {
            return result;
            break; // Didn't parse as expected
        }
        else{
            //printf("Converted char: %x\n", c);
        }
        *r++ = c;
    }
    return result;
}

void test2(){

    char hex[] = "2b7e151628aed2a6abf7158809cf4f3c";
    unsigned char* r = convertToHex(hex);
    if(r == NULL){
        printf("result is null\n");
    }
    printCharInHexadecimal(r, strlen(hex)/2);

}

void test1(){
    /*
    mode=aes-128
    key=2b7e151628aed2a6abf7158809cf4f3c
    iv=000102030405060708090A0B0C0D0E0F
    plain=6bc1bee22e409f96e93d7e117393172a
    cipher=7649abac8119b246cee98e9b12e9197d
    */
    const BYTE key[16] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
    BYTE plain[16] = {0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a};
    BYTE iv[16] = {0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F};
    BYTE cipher[16];
    WORD w[80];

    aes_key_setup(key,w,128);

    aes_encrypt_cbc(plain,
                    16,
                    cipher,
                    w,
                    128,
                    iv);

    printCharInHexadecimal(cipher,16);

    aes_encrypt_cbc(plain,
                    16,
                    plain,
                    w,
                    128,
                    iv);
    printCharInHexadecimal(plain,16);

}

int main() {
    test2();
}

