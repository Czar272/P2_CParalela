/* Bruteforce DES Paralelo con MPI - Proyecto 2 Computación Paralela
 * Compilar: make parallel
 * Uso: mpirun -np <num_procesos> ./build/bruteforce_mpi <archivo_cifrado> "<frase_clave>" <bits_clave>
 *
 * Ejemplo:
 *   mpirun -np 4 ./build/bruteforce_mpi files/cipher.bin "es una prueba de" 24
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
#include <mpi.h>

#ifdef __APPLE__
  #include <CommonCrypto/CommonCryptor.h>
#else
  #include <openssl/des.h>
#endif

#define PROGRESS_STEP 100000ULL
#define TAG_FOUND 1
#define TAG_TERMINATE 2

/* ------------------ util: memmem portable ------------------ */
#if defined(__APPLE__) || defined(_WIN32)
static void *memmem_portable(const void *haystack, size_t haystacklen, const void *needle, size_t needlelen) {
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
  #define MEMMEM(h,hl,n,nl) memmem_portable((h),(hl),(n),(nl))
#else
  #define MEMMEM(h,hl,n,nl) memmem((h),(hl),(n),(nl))
#endif

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

// ------------------ clave DES desde entero + paridad ------------------
static void set_odd_parity_bytes(unsigned char key[8]) {
    for (int i = 0; i < 8; ++i) {
        unsigned char v7 = key[i] >> 1; // excluye LSB
        int ones =
#ifdef __GNUC__
            __builtin_popcount((unsigned)v7);
#else
            0;
        while (v7) { ones += (v7 & 1); v7 >>= 1; }
#endif
        unsigned char parity_bit = (ones % 2 == 0) ? 1 : 0;
        key[i] = (key[i] & 0xFE) | parity_bit;
    }
}

// convierte un entero de 0..(2^56-1) a clave DES (8 bytes)
void uint64_to_deskey(uint64_t v, unsigned char key[8]) {
    for (int i = 0; i < 8; ++i) {
        key[i] = (unsigned char)(v & 0xFFULL);
        v >>= 8;
    }
    set_odd_parity_bytes(key);
}

/* ------------------ DES ECB decrypt (sin padding) ------------------ */
#ifdef __APPLE__
// descifra buffer usando CommonCrypto DES ECB
int des_decrypt_buffer(unsigned char *buf, size_t len, unsigned char key[8]) {
    unsigned char *temp = malloc(len);
    if (!temp) return -1;

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
    return (status == kCCSuccess) ? 0 : -1;
}

#else
static void des_ecb_decrypt_buffer(unsigned char *buf, size_t len, DES_key_schedule *ks) {
    DES_cblock inblk, outblk;
    for (size_t off = 0; off < len; off += 8) {
        memcpy(inblk, buf + off, 8);
        DES_ecb_encrypt(&inblk, &outblk, ks, DES_DECRYPT);
        memcpy(buf + off, outblk, 8);
    }
}
#endif

double now_seconds() {
    struct timespec t;
#ifdef CLOCK_MONOTONIC
    clock_gettime(CLOCK_MONOTONIC, &t);
#else
    clock_gettime(CLOCK_REALTIME, &t);
#endif
    return t.tv_sec + t.tv_nsec*1e-9;
}

int main(int argc, char **argv) {
    int rank, size;
    MPI_Status status;
    MPI_Request req;
    int flag = 0;
    
    // Inicializar MPI
    MPI_Init(&argc, &argv);
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &size);
    
    if (argc < 4) {
        if (rank == 0) {
            fprintf(stderr, "Uso: mpirun -np <procs> %s <cipher_file> \"<key_phrase>\" <key_bits>\n", argv[0]);
        }
        MPI_Finalize();
        return 1;
    }

    const char *cipher_path = argv[1];
    const char *key_phrase = argv[2];
    int key_bits = atoi(argv[3]);

    if (key_bits <= 0 || key_bits > 56) {
        if (rank == 0) {
            fprintf(stderr, "key_bits debe ser entre 1 y 56.\n");
        }
        MPI_Finalize();
        return 1;
    }

    // Solo el proceso 0 lee el archivo y lo distribuye
    size_t cipher_len = 0;
    unsigned char *cipher = NULL;

    if (rank == 0) {
        cipher = read_file(cipher_path, &cipher_len);
        if (!cipher) {
            fprintf(stderr, "Error leyendo archivo cifrado.\n");
            fprintf(stderr, "%s\n", cipher_path);
            MPI_Abort(MPI_COMM_WORLD, 1);
        }

        if (cipher_len % 8 != 0) {
            fprintf(stderr, "El archivo cifrado debe tener longitud multiplo de 8 bytes (bloques DES).\n");
            free(cipher);
            MPI_Abort(MPI_COMM_WORLD, 1);
        }
    }
    
    // Broadcast del tamaño del archivo
    MPI_Bcast(&cipher_len, sizeof(size_t), MPI_BYTE, 0, MPI_COMM_WORLD);
    
    // Todos los procesos reservan memoria para el archivo cifrado
    if (rank != 0) {
        cipher = malloc(cipher_len);
        if (!cipher) {
            fprintf(stderr, "Proceso %d: Error reservando memoria\n", rank);
            MPI_Abort(MPI_COMM_WORLD, 1);
        }
    }
    
    // Broadcast del contenido del archivo
    MPI_Bcast(cipher, cipher_len, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);
    
    // Calcular rango de búsqueda para cada proceso
    uint64_t total_keys = (key_bits == 64) ? 0xFFFFFFFFFFFFFFFFULL : (1ULL << key_bits);
    uint64_t keys_per_process = total_keys / size;
    uint64_t start = rank * keys_per_process;
    uint64_t end = (rank == size - 1) ? total_keys : start + keys_per_process;
    
    if (rank == 0) {
        printf("Archivo: %s, %zu bytes\n", cipher_path, cipher_len);
        printf("Frase clave: \"%s\"\n", key_phrase);
        printf("Total de claves: %llu (bits = %d)\n", (unsigned long long)total_keys, key_bits);
        printf("Procesos: %d, claves por proceso: ~%llu\n", size, (unsigned long long)keys_per_process);
        printf("Proceso %d: rango [%llu, %llu)\n", rank, (unsigned long long)start, (unsigned long long)end);
    } else {
        printf("Proceso %d: rango [%llu, %llu)\n", rank, (unsigned long long)start, (unsigned long long)end);
    }
    
    // Buffer de trabajo
    unsigned char *workbuf = malloc(cipher_len);
    if (!workbuf) {
        free(cipher);
        MPI_Abort(MPI_COMM_WORLD, 1);
    }
    
    // Variables para el proceso de búsqueda
    uint64_t checked = 0;
    int found = 0;
    uint64_t found_key = 0;
    double t0 = now_seconds();
    
    // Configurar comunicación no bloqueante para recibir señal de terminación
    int terminate = 0;
    MPI_Irecv(&terminate, 1, MPI_INT, MPI_ANY_SOURCE, TAG_TERMINATE, MPI_COMM_WORLD, &req);

#ifndef __APPLE__
    DES_key_schedule ks;
    DES_cblock keyblk;
#endif
    unsigned char key8[8];

    // Búsqueda paralela
    for (uint64_t k = start; k < end && !found; ++k) {
        // Verificar si otro proceso encontró la clave
        MPI_Test(&req, &flag, &status);
        if (flag && terminate) {
            break;
        }

        // convertir k a clave DES
        uint64_to_deskey(k, key8);

        // copiar buffer cifrado y descifrarlo en workbuf
        memcpy(workbuf, cipher, cipher_len);

#ifdef __APPLE__
        if (des_decrypt_buffer(workbuf, cipher_len, key8) != 0) {
            checked++;
            continue;
        }

#else
        memcpy(keyblk, key8, 8);
        DES_set_key_unchecked(&keyblk, &ks);
        des_ecb_decrypt_buffer(workbuf, cipher_len, &ks);
#endif
        // buscar frase clave
        if (MEMMEM(workbuf, cipher_len, key_phrase, strlen(key_phrase)) != NULL) {
            found = 1;
            found_key = k;

            int one = 1;
            // Notificar a todos los procesos que se encontró la clave
            for (int i = 0; i < size; i++) {
                if (i != rank) {
                    MPI_Send(&one, 1, MPI_INT, i, TAG_TERMINATE, MPI_COMM_WORLD);
                }
            }
            break;
        }

        checked++;
        if (rank == 0 && (checked % PROGRESS_STEP) == 0) {
            double tnow = now_seconds();
            double rate = checked / (tnow - t0);
            printf("Proceso 0: probadas %llu llaves... (%.2f keys/s)\n", 
                   (unsigned long long)checked, rate);
            fflush(stdout);
        }
    }

    // Cancelar receive pendiente si no se completó
    if (!flag) {
        MPI_Cancel(&req);
        MPI_Request_free(&req);
    }

    double t_local = now_seconds() - t0;

    // Recolectar resultados de todos los procesos
    typedef struct {
        int found;
        uint64_t key;
        uint64_t checked;
        double time;
        int rank;
    } Result;

    Result local_result = {found, found_key, checked, t_local, rank};
    Result *all_results = NULL;

    if (rank == 0) {
        all_results = malloc(size * sizeof(Result));
    }
    
    MPI_Gather(&local_result, sizeof(Result), MPI_BYTE,
    all_results, sizeof(Result), MPI_BYTE, 0, MPI_COMM_WORLD);

    // El proceso 0 muestra los resultados
    if (rank == 0) {
        int winner = -1;
        uint64_t total_checked = 0;
        double max_time = 0;

        for (int i = 0; i < size; i++) {
            total_checked += all_results[i].checked;
            if (all_results[i].time > max_time) {
                max_time = all_results[i].time;
            }
            if (all_results[i].found && winner == -1) {
                winner = i;
            }
        }

        if (winner >= 0) {
           printf("\n>>> LLAVE ENCONTRADA por proceso %d: k = %llu (decimal)\n", 
                   winner, (unsigned long long)all_results[winner].key);
            printf("Tiempo paralelo: %.6f segundos\n", max_time);
            printf("Total de claves probadas: %llu\n", (unsigned long long)total_checked);
            printf("Speedup teórico vs secuencial: %.2fx\n", (double)total_checked / all_results[winner].checked);

            // Mostrar texto descifrado
            uint64_to_deskey(all_results[winner].key, key8);
            memcpy(workbuf, cipher, cipher_len);
#ifdef __APPLE__
            (void)des_decrypt_buffer(workbuf, cipher_len, key8);
#else
            memcpy(keyblk, key8, 8);
            DES_set_key_unchecked(&keyblk, &ks);
            des_ecb_decrypt_buffer(workbuf, cipher_len, &ks);
#endif
            printf("Primeros 128 bytes del plaintext:\n");
            size_t show = cipher_len < 128 ? cipher_len : 128;
            for (size_t i = 0; i < show; ++i) {
                unsigned char c = workbuf[i];
                if (c >= 32 && c < 127) putchar(c); else putchar('.');
            }
            putchar('\n');
        } else {
            printf("No se encontró la llave en el espacio de búsqueda.\n");
            printf("Tiempo total: %.6f segundos\n", max_time);
            printf("Total de claves probadas: %llu\n", (unsigned long long)total_checked);
        }

        free(all_results);
    }

    free(workbuf);
    free(cipher);

    int any_found = 0;
    MPI_Allreduce(&found, &any_found, 1, MPI_INT, MPI_LOR, MPI_COMM_WORLD);

    MPI_Finalize();
    return any_found ? 0 : 1;
}