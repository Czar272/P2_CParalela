/* Cifrado DES - Proyecto 2 Computación Paralela
 * Compilar: make sequential  
 * Uso: ./build/encrypt <archivo_entrada> <archivo_salida> <clave_decimal>
 * 
 * Ejemplo:
 *   ./build/encrypt files/plain.txt files/cipher.bin 123456
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <CommonCrypto/CommonCryptor.h>

unsigned char *read_file(const char *path, size_t *out_size) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror("fopen"); return NULL; }
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return NULL; }
    rewind(f);
    unsigned char *buf = malloc(sz);
    if (!buf) { fclose(f); return NULL; }
    if (fread(buf, 1, sz, f) != (size_t)sz) { free(buf); fclose(f); return NULL; }
    fclose(f);
    *out_size = (size_t)sz;
    return buf;
}

int write_file(const char *path, unsigned char *buf, size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f) { perror("fopen write"); return -1; }
    if (fwrite(buf, 1, len, f) != len) { perror("fwrite"); fclose(f); return -1; }
    fclose(f);
    return 0;
}

// Padding PKCS#5 para bloques de 8 bytes
unsigned char *apply_pkcs5(unsigned char *in, size_t in_len, size_t *out_len) {
    size_t block = 8;
    size_t pad = block - (in_len % block);
    if (pad == 0) pad = block;
    *out_len = in_len + pad;
    unsigned char *out = malloc(*out_len);
    if (!out) return NULL;
    memcpy(out, in, in_len);
    memset(out + in_len, (unsigned char)pad, pad);
    return out;
}

// Convertir uint64 a clave DES de 8 bytes
void uint64_to_deskey(uint64_t v, unsigned char key[8]) {
    for (int i = 0; i < 8; ++i) {
        key[i] = (unsigned char)(v & 0xFFULL);
        v >>= 8;
    }
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "Uso: %s <input_txt> <output_cipher_bin> <key_decimal>\n", argv[0]);
        return 1;
    }

    const char *inpath = argv[1];
    const char *outpath = argv[2];
    uint64_t key_val = strtoull(argv[3], NULL, 10);

    printf("Usando clave: %llu (decimal)\n", (unsigned long long)key_val);

    size_t in_len;
    unsigned char *plain = read_file(inpath, &in_len);
    if (!plain) {
        fprintf(stderr, "Error leyendo %s\n", inpath);
        return 1;
    }

    size_t padded_len;
    unsigned char *padded = apply_pkcs5(plain, in_len, &padded_len);
    if (!padded) {
        free(plain);
        fprintf(stderr, "Error aplicando padding\n");
        return 1;
    }

    unsigned char key[8];
    uint64_to_deskey(key_val, key);

    printf("Clave DES (hex): ");
    for (int i = 0; i < 8; ++i) printf("%02X", key[i]);
    printf("\n");

    // Cifrar usando CommonCrypto
    size_t dataOutMoved = 0;
    CCCryptorStatus status = CCCrypt(kCCEncrypt,           // operation
                                     kCCAlgorithmDES,      // algorithm
                                     kCCOptionECBMode,     // options
                                     key,                  // key
                                     8,                    // key length
                                     NULL,                 // IV
                                     padded,               // input
                                     padded_len,           // input length
                                     padded,               // output (in-place)
                                     padded_len,           // output buffer size
                                     &dataOutMoved);       // output bytes

    if (status != kCCSuccess) {
        fprintf(stderr, "Error en cifrado DES: %d\n", status);
        free(plain);
        free(padded);
        return 1;
    }

    if (write_file(outpath, padded, padded_len) != 0) {
        fprintf(stderr, "Error escribiendo %s\n", outpath);
        free(plain);
        free(padded);
        return 1;
    }

    printf("Archivo cifrado escrito en: %s (%zu bytes)\n", outpath, padded_len);

    free(plain);
    free(padded);
    return 0;
}