/* Bruteforce DES Secuencial - Proyecto 2 Computación Paralela
 * Compilar: make sequential
 * Uso: ./build/bruteforce_seq <archivo_cifrado> "<frase_clave>" <bits_clave> [inicio] [fin]
 *
 * Ejemplo:
 *   ./build/bruteforce_seq files/cipher.bin "es una prueba de" 24
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 199309L
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <CommonCrypto/CommonCryptor.h>

#define PROGRESS_STEP 1000000ULL

// Implementación de memmem para macOS
void *memmem(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen) {
    if (needlelen == 0) return (void *)haystack;
    if (haystacklen < needlelen) return NULL;
    
    const char *h = (const char *)haystack;
    const char *n = (const char *)needle;
    
    for (size_t i = 0; i <= haystacklen - needlelen; i++) {
        if (memcmp(h + i, n, needlelen) == 0) {
            return (void *)(h + i);
        }
    }
    return NULL;
}

/* set_odd_parity: asegura paridad impar por byte en un bloque de 8 bytes */
static void set_odd_parity(unsigned char out[8]) {
    for (int i = 0; i < 8; ++i) {
#ifdef __GNUC__
        int ones = __builtin_popcount((unsigned int)(out[i] >> 1));
#else
        unsigned char v = out[i] >> 1;
        int ones = 0;
        while (v) { ones += v & 1; v >>= 1; }
#endif
        unsigned char parity_bit = (ones % 2 == 0) ? 1 : 0;
        out[i] = (out[i] & 0xFE) | parity_bit;
    }
}

// lee todo el archivo en memoria, devuelve tamaño en out_size 
unsigned char *read_file(const char *path, size_t *out_size) {
    FILE *f = fopen(path, "rb");

    if (!f) {
        perror("fopen");
        return NULL;
    }

    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f); return NULL; 
    }

    long sz = ftell(f);
    if (sz < 0) {
        fclose(f);
        return NULL;
    }

    rewind(f);
    unsigned char *buf = malloc(sz);
    if (!buf) {
        fclose(f);
        return NULL;
    }

    if (fread(buf, 1, sz, f) != (size_t)sz) {
        free(buf);
        fclose(f);
        return NULL;
    }

    fclose(f);
    *out_size = (size_t)sz;
    return buf;
}

// convierte un entero de 0..(2^56-1) a clave DES (8 bytes)
void uint64_to_desblock(uint64_t v, unsigned char *out) {
    // Llenamos los 8 bytes con el valor
    for (int i = 0; i < 8; ++i) {
        out[i] = (unsigned char)(v & 0xFFULL);
        v >>= 8;
    }
    // Luego establecemos bits de paridad (DES espera parity bits por byte)
    set_odd_parity(out);
}

// descifra buffer (en lugar) usando CommonCrypto DES ECB
void des_ecb_decrypt_buffer(unsigned char *buf, size_t len, unsigned char *key) {
    // CommonCrypto no soporta operaciones in-place con ECB muy bien,
    // así que usamos un buffer temporal
    unsigned char *temp = malloc(len);
    if (!temp) return;
    
    size_t dataOutMoved = 0;
    CCCryptorStatus status = CCCrypt(kCCDecrypt,           // operation
                                     kCCAlgorithmDES,      // algorithm  
                                     kCCOptionECBMode,     // options
                                     key,                  // key
                                     8,                    // key length
                                     NULL,                 // IV
                                     buf,                  // input
                                     len,                  // input length
                                     temp,                 // output
                                     len,                  // output buffer size
                                     &dataOutMoved);       // output bytes
    
    if (status == kCCSuccess) {
        memcpy(buf, temp, len);
    }
    
    free(temp);
}

double now_seconds() {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec + t.tv_nsec*1e-9;
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "Uso: %s <cipher_file> \"<key_phrase>\" <key_bits> [start] [end]\n", argv[0]);
        return 1;
    }

    const char *cipher_path = argv[1];
    const char *key_phrase = argv[2];
    int key_bits = atoi(argv[3]);
    if (key_bits <= 0 || key_bits > 56) {
        fprintf(stderr, "key_bits debe ser entre 1 y 56.\n");
        return 1;
    }

    uint64_t start = 0;
    uint64_t end = 0;
    if (argc >= 5) start = strtoull(argv[4], NULL, 10);
    if (argc >= 6) end = strtoull(argv[5], NULL, 10);

    uint64_t max = (key_bits == 64) ? 0xFFFFFFFFFFFFFFFFULL : (1ULL << key_bits);
    if (end == 0) end = max;
    if (start >= end) {
        fprintf(stderr, "Rango invalido: start >= end\n");
        return 1;
    }
    uint64_t range = end - start;

    size_t cipher_len;
    unsigned char *cipher = read_file(cipher_path, &cipher_len);
    if (!cipher) {
        fprintf(stderr, "Error leyendo archivo cifrado.\n");
        return 1;
    }
    
    if (cipher_len % 8 != 0) {
        fprintf(stderr, "El archivo cifrado debe tener longitud multiplo de 8 bytes (bloques DES).\n");
        free(cipher);
        return 1;
    }

    printf("Archivo: %s, %zu bytes\n", cipher_path, cipher_len);
    printf("Frase clave: \"%s\"\n", key_phrase);
    printf("Probando %llu llaves (bits = %d) desde %llu hasta %llu (excl.)\n",
           (unsigned long long)range, key_bits, (unsigned long long)start, (unsigned long long)end);

    double t0 = now_seconds();

    unsigned char *workbuf = malloc(cipher_len);
    if (!workbuf) {
        free(cipher);
        return 1;
    }

    unsigned char keyblock[8];
    uint64_t checked = 0;

    for (uint64_t k = start; k < end; ++k) {
        // convertir k a bloque DES y setear paridad 
        uint64_to_desblock(k, keyblock);

        // copiar buffer cifrado y descifrarlo en workbuf 
        memcpy(workbuf, cipher, cipher_len);
        des_ecb_decrypt_buffer(workbuf, cipher_len, keyblock);

        // buscar frase clave
        if (memmem(workbuf, cipher_len, key_phrase, strlen(key_phrase)) != NULL) {
            double t1 = now_seconds();
            printf("\n>>> LLAVE ENCONTRADA: k = %llu (decimal)\n", (unsigned long long)k);
            printf("Tiempo transcurrido: %.6f segundos. Intentos: %llu\n", t1 - t0, (unsigned long long)(k - start + 1));
            // mostrar primer bloque descifrado como texto 
            printf("Primeros 128 bytes del plaintext (hex/ASCII):\n");
            size_t show = cipher_len < 128 ? cipher_len : 128;
            for (size_t i = 0; i < show; ++i) {
                unsigned char c = workbuf[i];
                if (c >= 32 && c < 127) putchar(c); else putchar('.');
            }
            putchar('\n');
            free(workbuf);
            free(cipher);
            return 0;
        }

        checked++;
        if ((checked % PROGRESS_STEP) == 0) {
            double tnow = now_seconds();
            double rate = checked / (tnow - t0);
            printf("Probadas %llu llaves... (%.2f keys/s)\n", (unsigned long long)checked, rate);
            fflush(stdout);
        }
    }

    double t_end = now_seconds();
    printf("Busqueda terminada. No se encontro la llave en el rango dado.\n");
    printf("Tiempo total: %.6f s. Llaves probadas: %llu\n", t_end - t0, (unsigned long long)checked);

    free(workbuf);
    free(cipher);
    return 0;
}