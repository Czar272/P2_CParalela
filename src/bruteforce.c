// src/bruteforce.c
// Uso: mpirun -np P ./bruteforce <cipher.bin> "<frase a buscar>" <bits>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <mpi.h>
#include <openssl/des.h>

#define DES_DECRYPT 0
#define DES_ENCRYPT 1

// --------- Compatibilidad "rpc/des_crypt.h" sobre OpenSSL ---------
static void des_setparity(char *key) { DES_set_odd_parity((DES_cblock*)key); }

static void ecb_crypt(char *key, char *data, int len, int mode) {
    DES_key_schedule schedule;
    DES_cblock *blocks = (DES_cblock*)data;
    int num_blocks = len / 8;

    DES_set_key_unchecked((DES_cblock*)key, &schedule);

    for (int i = 0; i < num_blocks; i++) {
        DES_ecb_encrypt(&blocks[i], &blocks[i], &schedule,
                        (mode == DES_DECRYPT) ? DES_DECRYPT : DES_ENCRYPT);
    }
}

// --------- Mapeo entero -> clave DES (7 bits/byte + paridad impar) ---------
static void u64_to_des_key(uint64_t key_in, DES_cblock *out) {
    // Empaqueta 56 bits en 8 bytes dejando 1 bit de paridad por byte (LSB).
    uint64_t k = 0;
    for (int i = 0; i < 8; ++i) {
        key_in <<= 1;
        k += (key_in & (0xFEULL << (8*i))); // 0xFE = 11111110
    }
    memcpy(out, &k, 8);
    DES_set_odd_parity(out);
}

static void decrypt_u64(uint64_t key, unsigned char *buf, size_t len) {
    DES_cblock kblk;
    u64_to_des_key(key, &kblk);
    ecb_crypt((char*)&kblk, (char*)buf, (int)len, DES_DECRYPT);
}

// --------- Utilidades de E/S ---------
static unsigned char* read_bin(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END); long L = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (L <= 0) { fclose(f); return NULL; }

    unsigned char *buf = (unsigned char*)malloc((size_t)L);
    if (!buf) { fclose(f); return NULL; }

    size_t rd = fread(buf, 1, (size_t)L, f);
    fclose(f);
    if (rd != (size_t)L) { free(buf); return NULL; }

    // Asegurar múltiplo de 8 bytes para DES
    *out_len = ((size_t)L / 8) * 8;
    if (*out_len == 0) { free(buf); return NULL; }
    return buf;
}

// --------- Búsqueda ---------
static char *search_phrase = NULL;

static int try_key(uint64_t key, const unsigned char *cipher, size_t clen, const char *phrase) {
    unsigned char *tmp = (unsigned char*)malloc(clen + 1);
    if (!tmp) return 0;

    memcpy(tmp, cipher, clen);
    tmp[clen] = '\0';

    decrypt_u64(key, tmp, clen);
    int ok = (strstr((char*)tmp, phrase) != NULL);

    free(tmp);
    return ok;
}

int main(int argc, char *argv[]) {
    MPI_Init(&argc, &argv);
    MPI_Comm comm = MPI_COMM_WORLD;

    int size = 1, rank = 0;
    MPI_Comm_size(comm, &size);
    MPI_Comm_rank(comm, &rank);

    if (argc < 4) {
        if (rank == 0) {
            fprintf(stderr, "Uso: %s <cipher.bin> \"<frase a buscar>\" <bits>\n", argv[0]);
        }
        MPI_Finalize();
        return 1;
    }

    // rank 0 carga archivo y parámetros
    unsigned char *cipher = NULL;
    size_t clen = 0;
    int bits = atoi(argv[3]);
    if (bits < 1) bits = 1;
    if (bits > 56) bits = 56;
    unsigned long long upper = (bits == 56) ? (1ULL << 56) : (1ULL << bits);

    int ok = 1;
    if (rank == 0) {
        cipher = read_bin(argv[1], &clen);
        if (!cipher) ok = 0;
        if (ok) {
            search_phrase = argv[2];
            if (!search_phrase || search_phrase[0] == '\0') ok = 0;
        }
    }

    // Broadcast de 'ok' para abortar coordinadamente si algo falló
    MPI_Bcast(&ok, 1, MPI_INT, 0, comm);
    if (!ok) {
        if (rank == 0) fprintf(stderr, "Error: no se pudieron cargar argumentos/archivos.\n");
        MPI_Finalize();
        return 1;
    }

    // Broadcast de upper y del cipher
    MPI_Bcast(&upper, 1, MPI_UNSIGNED_LONG_LONG, 0, comm);

    unsigned long long clen64 = (unsigned long long)clen;
    MPI_Bcast(&clen64, 1, MPI_UNSIGNED_LONG_LONG, 0, comm);
    if (rank != 0) cipher = (unsigned char*)malloc((size_t)clen64);
    MPI_Bcast(cipher, (int)clen64, MPI_BYTE, 0, comm);
    clen = (size_t)clen64;

    // Broadcast de la frase (como string)
    int slen = (rank == 0) ? (int)strlen(argv[2]) : 0;
    MPI_Bcast(&slen, 1, MPI_INT, 0, comm);
    if (rank != 0) search_phrase = (char*)malloc((size_t)slen + 1);
    if (rank == 0) {
        MPI_Bcast((void*)argv[2], slen + 1, MPI_CHAR, 0, comm);
    } else {
        MPI_Bcast(search_phrase, slen + 1, MPI_CHAR, 0, comm);
    }

    // Partición de rango [mylower, myupper) (EXCLUSIVO)
    unsigned long long total   = upper;
    unsigned long long chunk   = total / (unsigned long long)size;
    unsigned long long mylower = chunk * (unsigned long long)rank;
    unsigned long long myupper = (rank == size - 1) ? upper : (mylower + chunk);

    // ------- PRIMITIVAS MPI: Irecv / Send / Wait + Bcast de stop -------
    long found_msg = 0;                 // valor recibido por rank 0 cuando algún rank encuentra
    MPI_Request req = MPI_REQUEST_NULL; // request para Irecv
    int have_recv_posted = 0;

    if (rank == 0) {
        MPI_Irecv(&found_msg, 1, MPI_LONG, MPI_ANY_SOURCE, 101, comm, &req);
        have_recv_posted = 1;
    }

    int stop = 0; // bandera de parada (se propaga con Bcast)
    long found_local = 0; // llave encontrada por este rank (0 = no)

    double t0 = MPI_Wtime();

    for (unsigned long long k = mylower; k < myupper && !stop; ++k) {
        // progreso opcional
        if ((k - mylower) % 100000ULL == 0ULL) {
            printf("[rank %d] probando k=%llu (rango [%llu, %llu))\n",
                   rank, (unsigned long long)k,
                   (unsigned long long)mylower, (unsigned long long)myupper);
            fflush(stdout);
        }

        // probar llave
        if (!found_local && try_key(k, cipher, clen, search_phrase)) {
            found_local = (long)k;
            // notificar a rank 0
            MPI_Send(&found_local, 1, MPI_LONG, 0, 101, comm);
        }

        // rank 0: checa si ya recibió una llave
        if (rank == 0 && have_recv_posted) {
            int done = 0;
            MPI_Status st;
            MPI_Test(&req, &done, &st);
            if (done) {
                // Aceptar formalmente
                MPI_Wait(&req, &st);  // <- uso explícito de MPI_Wait
                stop = 1;
            }
        }

        // sincronizar la bandera de parada para todos
        MPI_Bcast(&stop, 1, MPI_INT, 0, comm);
    }

    double t1 = MPI_Wtime();

    // Decidir la llave ganadora
    long winner_key = 0;
    int  winner_rank = -1;

    if (rank == 0) {
        if (stop && found_msg != 0) {
            winner_key = found_msg;
    
        }
    }

    // Broadcast de la llave ganadora a todos para imprimir consistente
    MPI_Bcast(&winner_key, 1, MPI_LONG, 0, comm);

    if (rank == 0) {
        if (winner_key != 0) {
            unsigned char *tmp = (unsigned char*)malloc(clen + 1);
            memcpy(tmp, cipher, clen); tmp[clen] = '\0';
            decrypt_u64((uint64_t)winner_key, tmp, clen);

            printf("RESULT: KEY FOUND\n");
            printf("Key     : %ld\n", winner_key);
            printf("Plain   : %.200s\n", (char*)tmp);
            printf("\nTime(s) : %.6f\n", (t1 - t0));
            free(tmp);
        } else {
            printf("RESULT: NOT FOUND\n");
            printf("\nTime(s) : %.6f\n", (t1 - t0));
        }
        printf("Tiempo de ejecucion del algoritmo : %.6f\n", (t1 - t0));
    }

    free(cipher);
    if (rank != 0) free(search_phrase);
    MPI_Finalize();
    return 0;
}
