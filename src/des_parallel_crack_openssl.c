// des_parallel_crack.c - Brute force DES paralelo usando OpenSSL
// Uso: mpirun -np P ./des_parallel_crack <cipher.bin> "<frase>" <bits>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <mpi.h>
#include <openssl/des.h>

// Conversión de clave decimal a DES_cblock con paridad
static void u64_to_des_key(uint64_t k, DES_cblock *key) {
    for (int i = 0; i < 8; ++i) {
        (*key)[i] = (unsigned char)(k & 0xFF);
        k >>= 8;
    }
    DES_set_odd_parity(key);
}

// Desencriptar buffer completo en modo ECB
static void des_decrypt_buffer(unsigned char *data, size_t len, uint64_t key_decimal) {
    DES_cblock key;
    u64_to_des_key(key_decimal, &key);
    
    DES_key_schedule ks;
    if (DES_set_key_checked(&key, &ks) != 0) {
        return; // Clave débil, skip
    }
    
    for (size_t i = 0; i < len; i += 8) {
        DES_cblock in_blk, out_blk;
        memcpy(in_blk, data + i, 8);
        DES_ecb_encrypt(&in_blk, &out_blk, &ks, DES_DECRYPT);
        memcpy(data + i, out_blk, 8);
    }
}

// Remover padding PKCS#5
static int remove_pkcs5_padding(unsigned char *data, size_t *len) {
    if (*len == 0 || *len % 8 != 0) return 0;
    unsigned char pad = data[*len - 1];
    if (pad == 0 || pad > 8) return 0;
    for (size_t i = *len - pad; i < *len; i++) {
        if (data[i] != pad) return 0;
    }
    *len -= pad;
    return 1;
}

// Función para probar una clave
static int try_key(uint64_t key_decimal, const unsigned char *cipher, size_t clen, const char *phrase) {
    // Crear copia del cifrado
    unsigned char *tmp = (unsigned char*)malloc(clen + 1);
    if (!tmp) return 0;
    memcpy(tmp, cipher, clen);
    tmp[clen] = '\0';
    
    // Desencriptar
    des_decrypt_buffer(tmp, clen, key_decimal);
    
    // Remover padding
    size_t decrypted_len = clen;
    remove_pkcs5_padding(tmp, &decrypted_len);
    
    // Asegurar null terminator
    if (decrypted_len < clen) {
        tmp[decrypted_len] = '\0';
    }
    
    // Buscar frase
    int found = (strstr((char*)tmp, phrase) != NULL);
    
    free(tmp);
    return found;
}

int main(int argc, char *argv[]) {
    MPI_Init(&argc, &argv);
    MPI_Comm comm = MPI_COMM_WORLD;

    int size = 1, rank = 0;
    MPI_Comm_size(comm, &size);
    MPI_Comm_rank(comm, &rank);

    if (argc < 4) {
        if (rank == 0) {
            fprintf(stderr, "Uso: %s <cipher.bin> \"<frase>\" <bits>\n", argv[0]);
        }
        MPI_Finalize();
        return 1;
    }

    // Leer archivo y parámetros
    unsigned char *cipher = NULL;
    size_t clen = 0;
    int bits = atoi(argv[3]);
    if (bits < 1) bits = 1;
    if (bits > 56) bits = 56;
    uint64_t upper = (bits == 56) ? (1ULL << 56) : (1ULL << bits);

    int ok = 1;
    if (rank == 0) {
        FILE *f = fopen(argv[1], "rb");
        if (!f) ok = 0;
        if (ok) {
            fseek(f, 0, SEEK_END);
            clen = ftell(f);
            fseek(f, 0, SEEK_SET);
            cipher = (unsigned char*)malloc(clen);
            if (fread(cipher, 1, clen, f) != clen) ok = 0;
            fclose(f);
        }
    }

    // Broadcast de ok
    MPI_Bcast(&ok, 1, MPI_INT, 0, comm);
    if (!ok) {
        if (rank == 0) fprintf(stderr, "Error al cargar archivo.\n");
        MPI_Finalize();
        return 1;
    }

    // Broadcast de datos
    uint64_t clen64 = (uint64_t)clen;
    MPI_Bcast(&upper, 1, MPI_UNSIGNED_LONG_LONG, 0, comm);
    MPI_Bcast(&clen64, 1, MPI_UNSIGNED_LONG_LONG, 0, comm);
    
    if (rank != 0) {
        clen = (size_t)clen64;
        cipher = (unsigned char*)malloc(clen);
    }
    MPI_Bcast(cipher, (int)clen, MPI_BYTE, 0, comm);

    // Broadcast de la frase
    int slen = (rank == 0) ? (int)strlen(argv[2]) : 0;
    MPI_Bcast(&slen, 1, MPI_INT, 0, comm);
    char *search_phrase = (rank == 0) ? argv[2] : (char*)malloc((size_t)slen + 1);
    if (rank == 0) {
        MPI_Bcast((void*)argv[2], slen + 1, MPI_CHAR, 0, comm);
    } else {
        MPI_Bcast(search_phrase, slen + 1, MPI_CHAR, 0, comm);
    }

    if (rank == 0) {
        printf("═══════════════════════════════════════════\n");
        printf("  DES PARALLEL CRACKER (OpenSSL)\n");
        printf("═══════════════════════════════════════════\n");
        printf("Archivo: %s (%zu bytes)\n", argv[1], clen);
        printf("Frase búsqueda: \"%s\"\n", search_phrase);
        printf("Procesos: %d\n", size);
        printf("Espacio: 2^%d = %llu claves\n", bits, (unsigned long long)upper);
        printf("═══════════════════════════════════════════\n\n");
        printf("Iniciando búsqueda paralela...\n\n");
    }

    // Partición de rango
    uint64_t chunk = upper / (uint64_t)size;
    uint64_t mylower = chunk * (uint64_t)rank;
    uint64_t myupper = (rank == size - 1) ? upper : (mylower + chunk);

    // MPI primitives
    long found_msg = 0;
    MPI_Request req = MPI_REQUEST_NULL;
    int have_recv_posted = 0;

    if (rank == 0) {
        MPI_Irecv(&found_msg, 1, MPI_LONG, MPI_ANY_SOURCE, 101, comm, &req);
        have_recv_posted = 1;
    }

    int stop = 0;
    long found_local = 0;
    double t0 = MPI_Wtime();

    for (uint64_t k = mylower; k < myupper && !stop; ++k) {
        // Progreso
        if ((k - mylower) % 10000ULL == 0ULL && k > mylower) {
            printf("[rank %d] probando k=%llu (rango [%llu, %llu))\n",
                   rank, (unsigned long long)k, (unsigned long long)mylower, (unsigned long long)myupper);
            fflush(stdout);
        }

        // Probar clave
        if (!found_local && try_key(k, cipher, clen, search_phrase)) {
            found_local = (long)k;
            printf("[rank %d] ¡ENCONTRADA! k=%llu\n", rank, (unsigned long long)k);
            fflush(stdout);
            MPI_Send(&found_local, 1, MPI_LONG, 0, 101, comm);
        }

        // Rank 0: checa si ya recibió
        if (rank == 0 && have_recv_posted) {
            int done = 0;
            MPI_Status st;
            MPI_Test(&req, &done, &st);
            if (done) {
                MPI_Wait(&req, &st);
                stop = 1;
            }
        }

        // Sincronizar parada
        MPI_Bcast(&stop, 1, MPI_INT, 0, comm);
    }

    double t1 = MPI_Wtime();

    // Asegurar que todos los mensajes hayan llegado
    MPI_Barrier(comm);

    // Si rank 0 tiene un request pendiente, esperarlo
    if (rank == 0 && have_recv_posted && !stop) {
        MPI_Status st;
        int flag;
        MPI_Test(&req, &flag, &st);
        if (!flag) {
            // Esperar un poco más por si hay mensaje en tránsito
            MPI_Wait(&req, &st);
        }
    }

    // Decidir ganador
    long winner_key = 0;
    if (rank == 0) {
        if (found_msg != 0) {
            winner_key = found_msg;
        }
    }

    MPI_Bcast(&winner_key, 1, MPI_LONG, 0, comm);

    if (rank == 0) {
        printf("\n");
        if (winner_key != 0) {
            // Desencriptar con la clave encontrada
            unsigned char *result = (unsigned char*)malloc(clen + 1);
            memcpy(result, cipher, clen);
            result[clen] = '\0';
            
            des_decrypt_buffer(result, clen, (uint64_t)winner_key);
            
            size_t result_len = clen;
            remove_pkcs5_padding(result, &result_len);
            result[result_len] = '\0';
            
            printf("RESULT: KEY FOUND\n");
            printf("Key     : %ld\n", winner_key);
            printf("Plain   : %s\n", result);
            printf("\nTime(s) : %.6f\n", (t1 - t0));
            printf("Tiempo de ejecucion del algoritmo : %.6f\n", (t1 - t0));
            
            free(result);
        } else {
            printf("RESULT: NOT FOUND\n");
            printf("\nTime(s) : %.6f\n", (t1 - t0));
            printf("Tiempo de ejecucion del algoritmo : %.6f\n", (t1 - t0));
        }
    }

    free(cipher);
    if (rank != 0) free(search_phrase);
    MPI_Finalize();
    return 0;
}
