/* Compilar:
 *   gcc -O2 -o build/encrypt src/encrypt.c -lcrypto
 *
 * Uso:
 *  ./build/encrypt files/plain.txt files/cipher.bin 0x00ABCDEF
 *
 * Ejemplo:
 *   echo "Esta es una prueba de encriptacion" > plain.txt
 *   ./encrypt plain.txt cipher.bin 0x00ABCDEF
 */

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/des.h>
#include <openssl/err.h>
#include <openssl/provider.h>


static unsigned char *read_file(const char *path, size_t *out_size){
    FILE *f = fopen(path, "rb");
    if(!f){ perror("fopen"); return NULL; }
    if(fseek(f, 0, SEEK_END)!=0){ fclose(f); return NULL; }
    long sz = ftell(f);
    if(sz < 0){ fclose(f); return NULL; }
    rewind(f);
    unsigned char *buf = malloc(sz);
    if(!buf){ fclose(f); return NULL; }
    if(fread(buf,1,sz,f)!=(size_t)sz){ free(buf); fclose(f); return NULL; }
    fclose(f); *out_size = (size_t)sz; return buf;
}

static int write_file(const char *path, const unsigned char *buf, size_t len){
    FILE *f = fopen(path, "wb");
    if(!f){ perror("fopen write"); return -1; }
    if(fwrite(buf,1,len,f)!=len){ perror("fwrite"); fclose(f); return -1; }
    fclose(f); return 0;
}

// PKCS#5/PKCS#7 padding helper 
static unsigned char *apply_pkcs5(const unsigned char *in, size_t in_len, size_t *out_len){
    size_t block=8, pad = block - (in_len % block);
    if(pad==0) pad=block;
    *out_len = in_len + pad;
    unsigned char *out = malloc(*out_len);
    if(!out) return NULL;
    memcpy(out, in, in_len);
    memset(out + in_len, (unsigned char)pad, pad);
    return out;
}

// out: DES_cblock (8 bytes) 
static void set_odd_parity(unsigned char out[8]) {
    for (int i = 0; i < 8; ++i) {
        // Contar 1s en los 7 bits de mayor peso (excluyendo el LSB que usaremos como bit de paridad)
        unsigned char without_lsb = out[i] >> 1; // desplaza para quitar LSB
        int ones = __builtin_popcount((unsigned int)without_lsb);

        // Si el numero de 1s en los 7 bits es par -> poner LSB=1 sino LSB=0 (para que total sea impar).
        unsigned char parity_bit = (ones % 2 == 0) ? 1 : 0;
        out[i] = (out[i] & 0xFE) | parity_bit;
    }
}

// mismo mapping: entero -> 8 bytes little-endian, luego odd parity 
static void uint64_to_desblock(uint64_t v, DES_cblock *out){
    for (int i = 0; i < 8; ++i) {
        (*out)[i] = (unsigned char)(v & 0xFFULL);
        v >>= 8;
    }
    // Ajustar bits de paridad (odd parity)
    set_odd_parity(*out);
}

static int parse_u64(const char *s, uint64_t *out){
    char *end = NULL;
    uint64_t v = strtoull(s, &end, 0);
    if (end == s || *end != '\0') return -1;
    *out = v; return 0;
}

int main(int argc, char **argv){
    // Cargar legacy provider 
    OSSL_PROVIDER *prov = NULL;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    prov = OSSL_PROVIDER_load(NULL, "legacy");
    if (!prov) {
        fprintf(stderr, "Advertencia: no se pudo cargar legacy provider de OpenSSL. "
                        "DES podria no estar disponible.\n");
        ERR_print_errors_fp(stderr);
    }
#endif

    if(argc!=4){
        fprintf(stderr, "Uso: %s <input_txt> <output_cipher_bin> <key_int>\n", argv[0]);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        if (prov) OSSL_PROVIDER_unload(prov);
#endif
        return 1;
    }

    const char *inpath = argv[1];
    const char *outpath = argv[2];
    const char *keyarg = argv[3];

    uint64_t k;
    if (parse_u64(keyarg, &k) != 0) {
        fprintf(stderr, "key_int invalida. Usa decimal (123) o hex (0x123)\n");
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        if (prov) OSSL_PROVIDER_unload(prov);
#endif
        return 1;
    }

    // Leer archivo de entrada
    size_t in_len = 0;
    unsigned char *plain = read_file(inpath, &in_len);
    if (!plain) {
        fprintf(stderr, "Error leyendo %s\n", inpath);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        if (prov) OSSL_PROVIDER_unload(prov);
#endif
        return 1;
    }

    // Aplicar padding PKCS#5/7
    size_t padded_len = 0;
    unsigned char *padded = apply_pkcs5(plain, in_len, &padded_len);
    if (!padded) {
        fprintf(stderr, "Error aplicando padding\n");
        free(plain);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        if (prov) OSSL_PROVIDER_unload(prov);
#endif
        return 1;
    }

    // Generar la clave DES a partir del entero k (little-endian + parity)
    DES_cblock keyblk;
    uint64_to_desblock(k, &keyblk); // esto llama a set_odd_parity internamente

    printf("k = %llu -> key = ", (unsigned long long)k);
    for (int i = 0; i < 8; ++i) printf("%02X", keyblk[i]);
    printf("\n");

    // Inicializar EVP y obtener el cipher DES-ECB
    ERR_clear_error();
    const EVP_CIPHER *cipher = EVP_des_ecb();
    if (!cipher) {
        fprintf(stderr, "EVP_des_ecb() devolvio NULL — DES puede no estar disponible.\n");
        ERR_print_errors_fp(stderr);
        free(plain); free(padded);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        if (prov) OSSL_PROVIDER_unload(prov);
#endif
        return 1;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Error creando EVP_CIPHER_CTX\n");
        ERR_print_errors_fp(stderr);
        free(plain); free(padded);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        if (prov) OSSL_PROVIDER_unload(prov);
#endif
        return 1;
    }

    // Inicializar cifrado (nota: EVP activa padding PKCS#7 por defecto)
    if (EVP_EncryptInit_ex(ctx, cipher, NULL, (const unsigned char*)keyblk, NULL) != 1) {
        unsigned long err = ERR_get_error();
        char buf[256];
        ERR_error_string_n(err, buf, sizeof(buf));
        fprintf(stderr, "EVP_EncryptInit_ex fallo: %s\n", buf);
        ERR_print_errors_fp(stderr);
        EVP_CIPHER_CTX_free(ctx);
        free(plain); free(padded);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        if (prov) OSSL_PROVIDER_unload(prov);
#endif
        return 1;
    }

    // Cifrar todo el buffer padded (ya es multiplo de 8)
    int block_size = EVP_CIPHER_block_size(cipher);
    unsigned char *outbuf = malloc(padded_len + block_size);
    if (!outbuf) {
        fprintf(stderr, "Error al reservar memoria para outbuf\n");
        EVP_CIPHER_CTX_free(ctx);
        free(plain); free(padded);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        if (prov) OSSL_PROVIDER_unload(prov);
#endif
        return 1;
    }

    int outlen1 = 0;
    if (EVP_EncryptUpdate(ctx, outbuf, &outlen1, padded, (int)padded_len) != 1) {
        fprintf(stderr, "EVP_EncryptUpdate fallo\n");
        ERR_print_errors_fp(stderr);
        free(outbuf);
        EVP_CIPHER_CTX_free(ctx);
        free(plain); free(padded);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        if (prov) OSSL_PROVIDER_unload(prov);
#endif
        return 1;
    }

    int outlen2 = 0;
    if (EVP_EncryptFinal_ex(ctx, outbuf + outlen1, &outlen2) != 1) {
        fprintf(stderr, "EVP_EncryptFinal_ex fallo\n");
        ERR_print_errors_fp(stderr);
        free(outbuf);
        EVP_CIPHER_CTX_free(ctx);
        free(plain); free(padded);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        if (prov) OSSL_PROVIDER_unload(prov);
#endif
        return 1;
    }

    size_t total_out = (size_t)(outlen1 + outlen2);

    // Escribir archivo cifrado 
    if (write_file(outpath, outbuf, total_out) != 0) {
        fprintf(stderr, "Error escribiendo %s\n", outpath);
        free(outbuf);
        EVP_CIPHER_CTX_free(ctx);
        free(plain); free(padded);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        if (prov) OSSL_PROVIDER_unload(prov);
#endif
        return 1;
    }

    printf("Archivo cifrado escrito en: %s (%zu bytes)\n", outpath, total_out);

    // Liberar recursos 
    free(outbuf);
    EVP_CIPHER_CTX_free(ctx);
    free(plain);
    free(padded);

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    if (prov) OSSL_PROVIDER_unload(prov);
#endif

    return 0;
}

