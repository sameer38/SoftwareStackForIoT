#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#define u8 uint8_t
#define u32 uint32_t
#define u64 uint64_t

#define ROTL32(x, r) (((x) << (r)) | (x >> (32 - (r))))
#define ROTR32(x, r) (((x) >> (r)) | ((x) << (32 - (r))))
#define ROTL64(x, r) (((x) << (r)) | (x >> (64 - (r))))
#define ROTR64(x, r) (((x) >> (r)) | ((x) << (64 - (r))))

#define ER64(x, y, k) (x = ROTR64(x, 8), x += y, x ^= k, y = ROTL64(y, 3), y ^= x)
#define DR64(x, y, k) (y ^= x, y = ROTR64(y, 3), x ^= k, x -= y, x = ROTL64(x, 8))

void Words64ToBytes(u64 words[], u8 bytes[], int numwords)
{
    int i, j = 0;
    for (i = 0; i < numwords; i++)
    {
        bytes[j] = (u8)words[i];
        bytes[j + 1] = (u8)(words[i] >> 8);
        bytes[j + 2] = (u8)(words[i] >> 16);
        bytes[j + 3] = (u8)(words[i] >> 24);
        bytes[j + 4] = (u8)(words[i] >> 32);
        bytes[j + 5] = (u8)(words[i] >> 40);
        bytes[j + 6] = (u8)(words[i] >> 48);
        bytes[j + 7] = (u8)(words[i] >> 56);
        j += 8;
    }
}

void BytesToWords64(u8 bytes[], u64 words[], int numbytes)
{
    int i, j = 0;
    for (i = 0; i < numbytes / 8; i++)
    {
        words[i] = (u64)bytes[j] | ((u64)bytes[j + 1] << 8) | ((u64)bytes[j + 2] << 16) |
                   ((u64)bytes[j + 3] << 24) | ((u64)bytes[j + 4] << 32) | ((u64)bytes[j + 5] << 40) |
                   ((u64)bytes[j + 6] << 48) | ((u64)bytes[j + 7] << 56);
        j += 8;
    }
}

void Speck128128KeySchedule(u64 K[], u64 rk[])
{
    u64 i, B = K[1], A = K[0];
    for (i = 0; i < 31;)
    {
        rk[i] = A;
        ER64(B, A, i++);
    }
    rk[i] = A;
}

void Speck128128Encrypt(u64 Pt[], u64 Ct[], u64 rk[])
{
    u64 i;
    Ct[0] = Pt[0];
    Ct[1] = Pt[1];
    for (i = 0; i < 32;)
        ER64(Ct[1], Ct[0], rk[i++]);
}

void Speck128128Decrypt(u64 Pt[], u64 Ct[], u64 rk[])
{
    int i;
    Pt[0] = Ct[0];
    Pt[1] = Ct[1];
    for (i = 31; i >= 0;)
        DR64(Pt[1], Pt[0], rk[i--]);
}

void encrypt(char *plaintext, int length, u64 rk[], u64 cyphertext[])
{
    int index_pt = 0;
    int index_ct = 0;
    u8 pt[16];
    u64 Ct[2];

    for (int i = 0; index_pt < length; i++)
    {
        int j = 0;
        for (; j < 16 && index_pt < length; j++)
        {
            pt[j] = plaintext[index_pt];
            index_pt++;
        }

        for (; j < 16; j++)
        {
            pt[j] = 0;
        }
        u64 Pt[] = {0, 0};

        BytesToWords64(pt, Pt, 16);
        Speck128128Encrypt(Pt, Ct, rk);

        cyphertext[index_ct++] = Ct[0];
        cyphertext[index_ct++] = Ct[1];
    }
}

void decrypt(u64 rk[], u64 cypher[], int cypher_length, char plaintext[])
{
    int index_pt = 0;
    int index_ct = 0;
    u8 pt[16];
    u64 Pt[] = {0, 0};
    u64 Ct[] = {0, 0};

    for (int i = 0; i < cypher_length;)
    {
        Ct[0] = cypher[i++];
        Ct[1] = cypher[i++];

        Speck128128Decrypt(Pt, Ct, rk);
        Words64ToBytes(Pt, pt, 2);

        for (int j = 0; j < 16; j++)
        {
            plaintext[index_pt++] = pt[j];
        }
    }
}

int main()
{
    u64 K[] = {1, 2};
    u64 rk[32];

    Speck128128KeySchedule(K, rk);

    for (int i = 0; i < 32; i++)
    {
        printf("%lx\n", rk[i]);
    }

    char *text = "This is _a test to check if encryption and decryption are working or not";
    int length = strlen(text);
    int size = length / 8;

    u64 Cypher[size];

    encrypt(text, length, rk, Cypher);

    for (int i = 0; i < size; i++)
    {
        printf("%lx\n", Cypher[i]);
    }

    char plaintext[100];

    decrypt(rk, Cypher, size, plaintext);
}