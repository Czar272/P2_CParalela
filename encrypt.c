/* Compilar: gcc -O2 -o encrypt encrypt.c -lcrypto
 * Corer: ./encrypt <input_txt> <output_cipher_bin> <key_hex|random>
 *
 * Ejemplos:
 *   ./encrypt plain.txt cipher.bin 133457799BBCDFF1
 *   ./encrypt plain.txt cipher.bin random
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <openssl/des.h>

// Leer todo el archivo de texto en memoria
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

// Escribir buffer a archivo
int write_file(const char *path, unsigned char *buf, size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f) { perror("fopen write"); return -1; }
    if (fwrite(buf, 1, len, f) != len) { perror("fwrite"); fclose(f); return -1; }
    fclose(f);
    return 0;
}

// Funcion por si dan key
// Convierte string hex (16 hex chars) a DES_cblock (8 bytes).
int hex_to_desblock(const char *hex, DES_cblock *out) {
    if (strlen(hex) != 16) return -1;
    for (int i = 0; i < 8; ++i) {
        char byte_hex[3] = { hex[i*2], hex[i*2+1], 0 };
        unsigned int b;
        if (sscanf(byte_hex, "%02x", &b) != 1) return -1;
        (*out)[i] = (unsigned char)(b & 0xFF);
    }
    DES_set_odd_parity(out);
    return 0;
}

// Funcion para generar key
// Genera clave aleatoria de 8 bytes y ajusta paridad
void random_desblock(DES_cblock *out) {
    srand((unsigned)time(NULL) ^ (unsigned)getpid());
    for (int i = 0; i < 8; ++i) {
        (*out)[i] = (unsigned char)(rand() & 0xFF);
    }
    DES_set_odd_parity(out);
}

// Padding PKCS#5 (para bloque 8 bytes). Devuelve nuevo buffer y tamaño por referencia
unsigned char *apply_pkcs5(unsigned char *in, size_t in_len, size_t *out_len) {
    size_t block = 8;
    size_t pad = block - (in_len % block);
    if (pad == 0) pad = block;
    *out_len = in_len + pad;
    unsigned char *out = malloc(*out_len);
    if (!out) return NULL;
    memcpy(out, in, in_len);
    // Relleno: cada byte con el valor 'pad'
    memset(out + in_len, (unsigned char)pad, pad);
    return out;
}

// Cifrado DES ECB in-place (buf length multiplo de 8), usando key schedule
void des_ecb_encrypt_buffer(unsigned char *buf, size_t len, DES_key_schedule *ks) {
    DES_cblock inblk, outblk;
    for (size_t off = 0; off < len; off += 8) {
        memcpy(inblk, buf + off, 8);
        DES_ecb_encrypt(&inblk, &outblk, ks, DES_ENCRYPT);
        memcpy(buf + off, outblk, 8);
    }
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "Uso: %s <input_txt> <output_cipher_bin> <key_hex|random>\n", argv[0]);
        return 1;
    }

    const char *inpath = argv[1];
    const char *outpath = argv[2];
    const char *keyarg = argv[3];

    size_t in_len;
    unsigned char *plain = read_file(inpath, &in_len);
    if (!plain) { fprintf(stderr, "Error leyendo %s\n", inpath); return 1; }

    size_t padded_len;
    unsigned char *padded = apply_pkcs5(plain, in_len, &padded_len);
    if (!padded) { free(plain); fprintf(stderr, "Error al aplicar padding\n"); return 1; }

    DES_cblock key;
    if (strcmp(keyarg, "random") == 0) {
        random_desblock(&key);
        printf("Clave aleatoria generada (hex): ");
        for (int i = 0; i < 8; ++i) printf("%02X", key[i]);
        printf("\n");
    } else {
        if (hex_to_desblock(keyarg, &key) != 0) {
            fprintf(stderr, "key_hex invalida. Debe ser 16 hex chars (ej: 133457799BBCDFF1) o 'random'\n");
            free(plain); free(padded); return 1;
        }
    }

    DES_key_schedule ks;
    DES_set_key_unchecked(&key, &ks);

    des_ecb_encrypt_buffer(padded, padded_len, &ks);

    if (write_file(outpath, padded, padded_len) != 0) {
        fprintf(stderr, "Error escribiendo %s\n", outpath);
        free(plain); free(padded); return 1;
    }

    printf("Archivo cifrado escrito en: %s (tamaño %zu bytes)\n", outpath, padded_len);

    free(plain);
    free(padded);
    return 0;
}
