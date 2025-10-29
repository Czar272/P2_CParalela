// encrypt_openssl.c - DES-ECB + PKCS#5 padding (Linux/WSL)
// Uso: ./encrypt_openssl <plain.txt> <cipher.bin> <key_decimal>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/des.h>



static void u64_to_des_key(uint64_t k, DES_cblock *key) {
    for (int i = 0; i < 8; ++i) {          // LSB primero
        (*key)[i] = (unsigned char)(k & 0xFF);
        k >>= 8;
    }
    DES_set_odd_parity(key);
}

static unsigned char* pkcs5_pad(const unsigned char* in, size_t len, size_t *out_len) {
    size_t pad = 8 - (len % 8);
    if (pad == 0) pad = 8;
    *out_len = len + pad;
    unsigned char *out = (unsigned char*)malloc(*out_len);
    if (!out) return NULL;
    memcpy(out, in, len);
    memset(out + len, (int)pad, pad);
    return out;
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "Uso: %s <plain.txt> <cipher.bin> <key_decimal>\n", argv[0]);
        return 1;
    }

    const char *in_path  = argv[1];
    const char *out_path = argv[2];
    uint64_t key_dec = strtoull(argv[3], NULL, 10);

    // leer archivo de entrada
    FILE *fi = fopen(in_path, "rb");
    if (!fi) { perror("fopen plain"); return 1; }
    fseek(fi, 0, SEEK_END);
    long n = ftell(fi);
    fseek(fi, 0, SEEK_SET);
    if (n < 0) { perror("ftell"); fclose(fi); return 1; }

    unsigned char *buf = (unsigned char*)malloc((size_t)n);
    if (!buf) { perror("malloc"); fclose(fi); return 1; }
    if (fread(buf, 1, (size_t)n, fi) != (size_t)n) { perror("fread"); free(buf); fclose(fi); return 1; }
    fclose(fi);

    // padding PKCS#5
    size_t plen;
    unsigned char *padded = pkcs5_pad(buf, (size_t)n, &plen);
    free(buf);
    if (!padded) { fprintf(stderr, "Error padding\n"); return 1; }

    // preparar clave DES (paridad impar)
    DES_cblock key;
    u64_to_des_key(key_dec, &key);
    DES_key_schedule ks;
    if (DES_set_key_checked(&key, &ks) != 0) {
        fprintf(stderr, "Clave DES inválida tras paridad (weak key)\n");
        free(padded);
        return 1;
    }

    // cifrar en ECB bloque a bloque (8 bytes)
    for (size_t i = 0; i < plen; i += 8) {
        DES_cblock in_blk, out_blk;
        memcpy(in_blk, padded + i, 8);
        DES_ecb_encrypt(&in_blk, &out_blk, &ks, DES_ENCRYPT);
        memcpy(padded + i, out_blk, 8);
    }

    // escribir salida
    FILE *fo = fopen(out_path, "wb");
    if (!fo) { perror("fopen cipher"); free(padded); return 1; }
    if (fwrite(padded, 1, plen, fo) != plen) { perror("fwrite"); fclose(fo); free(padded); return 1; }
    fclose(fo);
    free(padded);

    printf("OK. Generado %s con llave decimal %s\n", out_path, argv[3]);
    return 0;
}
