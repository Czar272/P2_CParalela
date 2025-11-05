/**
 * Compilar:
 * mpicc -O2 -std=c11 -o mw_bruteforce mw_bruteforce.c -lcrypto
 *
 * Correr:
 * mpirun -np 4 ./mw_bruteforce \
  --cipher ciphertext.bin \
  --keyword "es una prueba de" \
  --start 0 --end 72057594037927935 \
  --chunk 1048576
 */

#include <errno.h>
#include <inttypes.h>
#include <mpi.h>
#include <openssl/des.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// Tipos y tags
typedef unsigned long long u64; // portable con MPI_UNSIGNED_LONG_LONG

enum {
  TAG_REQ = 1,   // worker -> master: pide trabajo
  TAG_WORK = 2,  // master -> worker: {start,len,seed}
  TAG_DONE = 3,  // master -> worker: no hay mas trabajo
  TAG_FOUND = 4, // worker -> master: reporta key encontrada
  TAG_STOP = 5   // master -> all: detener, payload = winner key (o ULLONG_MAX)
};

// Utilidades
static void die(const char *msg) {
  fprintf(stderr, "FATAL: %s\n", msg);
  MPI_Abort(MPI_COMM_WORLD, 1);
  exit(1);
}

static int read_file(const char *path, unsigned char **buf, size_t *len) {
  FILE *f = fopen(path, "rb");
  if (!f)
    return -1;
  fseek(f, 0, SEEK_END);
  long L = ftell(f);
  if (L < 0) {
    fclose(f);
    return -2;
  }
  fseek(f, 0, SEEK_SET);
  *buf = (unsigned char *)malloc((size_t)L);
  if (!*buf) {
    fclose(f);
    return -3;
  }
  if (fread(*buf, 1, (size_t)L, f) != (size_t)L) {
    fclose(f);
    free(*buf);
    return -4;
  }
  fclose(f);
  *len = (size_t)L;
  return 0;
}

// hash para semillas.
static inline u64 splitmix64(u64 x) {
  x += 0x9e3779b97f4a7c15ULL;
  x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
  x = (x ^ (x >> 27)) * 0x94d049bb133111ebULL;
  return x ^ (x >> 31);
}

// gcd rapido
static u64 ugcd(u64 a, u64 b) {
  while (b) {
    u64 t = a % b;
    a = b;
    b = t;
  }
  return a;
}

// stride coprimo con len (para recorrer 0..len-1 sin repetir)
static u64 pick_stride(u64 len, u64 seed) {
  if (len <= 2)
    return 1;
  // intenta hasta 64 candidates basados en la semilla
  for (int k = 0; k < 64; ++k) {
    u64 cand = (splitmix64(seed + k) % (len - 1)) + 1;
    if (ugcd(cand, len) == 1)
      return cand;
  }

  return 1;
}

// OpenSSL DES-based try_key y helpers

// Búsqueda simple de patrón
static int contains_subsequence(const unsigned char *hay, size_t haylen,
                                const char *needle, size_t needlen) {
  if (needlen == 0)
    return 1;
  if (haylen < needlen)
    return 0;
  for (size_t i = 0; i + needlen <= haylen; ++i) {
    if (hay[i] == (unsigned char)needle[0]) {
      size_t j = 1;
      for (; j < needlen; ++j)
        if (hay[i + j] != (unsigned char)needle[j])
          break;
      if (j == needlen)
        return 1;
    }
  }
  return 0;
}

// Convierte u64 key (56 bits) a DES_cblock (8 bytes) y ajusta paridad
static void u64_to_des_key(u64 key, DES_cblock *out) {
  // rellenamos los 8 bytes con los 64 bits de 'key'
  for (int i = 0; i < 8; ++i) {
    // Extraemos de MSB a LSB para formar el bloque en orden de bytes
    (*out)[7 - i] = (unsigned char)((key >> (i * 8)) & 0xFFULL);
  }
  // Ajusta bits de paridad en el bloque
  DES_set_odd_parity(out);
}

static int try_key(u64 key, const unsigned char *cipher, size_t clen,
                   const char *keyword) {
  if (!cipher || clen == 0 || !keyword)
    return 0;

  size_t nblocks = clen / 8;
  if (nblocks == 0)
    return 0;

  DES_cblock key_block;
  u64_to_des_key(key, &key_block);

  DES_key_schedule ks;
  if (DES_set_key_checked(&key_block, &ks) != 0) {
    return 0;
  }

  unsigned char *plain = (unsigned char *)malloc(nblocks * 8);
  if (!plain)
    return 0;

  DES_cblock in, out;
  for (size_t i = 0; i < nblocks; ++i) {
    memcpy(in, cipher + i * 8, 8);
    DES_ecb_encrypt(&in, &out, &ks, DES_DECRYPT);
    memcpy(plain + i * 8, out, 8);
  }

  size_t klen = strlen(keyword);
  int found = contains_subsequence(plain, nblocks * 8, keyword, klen);

  free(plain);
  return found;
}

// Recorrido pseudoaleatorio dentro del chunk
// Devuelve 1 si encontro.
static int search_chunk_random(u64 start, u64 len, u64 seed,
                               const unsigned char *cipher, size_t clen,
                               const char *keyword, u64 *found_key, int rank) {
  if (len == 0)
    return 0;

  // Elegimos un “stride” coprimo con len y un desplazamiento a partir de la
  // semilla
  u64 stride = pick_stride(len, seed ^ (u64)rank);
  u64 off0 = splitmix64(seed + 0xABCDEF) % len;

  // Bucle: keys = start + ((off0 + i*stride) % len)
  for (u64 i = 0; i < len; ++i) {
    u64 off = (off0 + i * stride) % len;
    u64 key = start + off;
    if (try_key(key, cipher, clen, keyword)) {
      *found_key = key;
      return 1;
    }
  }
  return 0;
}

// Main
int main(int argc, char **argv) {
  MPI_Init(&argc, &argv);
  int world, rank;
  MPI_Comm_size(MPI_COMM_WORLD, &world);
  MPI_Comm_rank(MPI_COMM_WORLD, &rank);

  const char *cipher_path = NULL;
  const char *keyword = NULL;
  u64 key_start = 0, key_end = 0;
  u64 chunk_size = 1ULL << 20;

  for (int i = 1; i < argc; ++i) {
    if (!strcmp(argv[i], "--cipher") && i + 1 < argc)
      cipher_path = argv[++i];
    else if (!strcmp(argv[i], "--keyword") && i + 1 < argc)
      keyword = argv[++i];
    else if (!strcmp(argv[i], "--start") && i + 1 < argc)
      key_start = (u64)strtoull(argv[++i], NULL, 10);
    else if (!strcmp(argv[i], "--end") && i + 1 < argc)
      key_end = (u64)strtoull(argv[++i], NULL, 10);
    else if (!strcmp(argv[i], "--chunk") && i + 1 < argc)
      chunk_size = (u64)strtoull(argv[++i], NULL, 10);
    else if (!strcmp(argv[i], "--help")) {
      if (rank == 0) {
        fprintf(stderr, "Uso: mpirun -np P ./mw_bruteforce --cipher FILE "
                        "--keyword \"...\" --start A --end B [--chunk N]\n");
      }
      MPI_Finalize();
      return 0;
    }
  }
  if (rank == 0) {
    printf("[DEBUG master] cipher_path=%s keyword=%s start=%" PRIu64
           " end=%" PRIu64 " chunk=%" PRIu64 "\n",
           cipher_path ? cipher_path : "<NULL>", keyword ? keyword : "<NULL>",
           key_start, key_end, chunk_size);
    fflush(stdout);
  } else {
    printf("[DEBUG worker %d] inicio\n", rank);
    fflush(stdout);
  }

  if (!cipher_path || !keyword || key_end <= key_start) {
    if (rank == 0) {
      fprintf(stderr, "Parametros invalidos. Usa --help.\n");
    }
    MPI_Finalize();
    return 1;
  }

  unsigned char *cipher = NULL;
  size_t clen = 0;
  if (rank == 0) {
    if (read_file(cipher_path, &cipher, &clen) != 0)
      die("No se pudo leer el archivo cifrado.");
  }

  // Broadcast del tamaño y contenido a todos:
  size_t clen64[1] = {clen};
  if (rank == 0) {
    printf("[DEBUG master] after bcast clen=%zu\n", clen);
    fflush(stdout);
  } else {
    printf("[DEBUG worker %d] after recv clen=%zu\n", rank, (size_t)clen64[0]);
    fflush(stdout);
  }

  MPI_Bcast(clen64, 1, MPI_UNSIGNED_LONG_LONG, 0, MPI_COMM_WORLD);
  if (rank == 0) {
    printf("[DEBUG master] cipher size bytes = %zu\n", clen);
    fflush(stdout);
  }

  clen = (size_t)clen64[0];
  if (rank != 0) {
    cipher = (unsigned char *)malloc(clen);
    if (!cipher)
      die("malloc cipher");
  }
  MPI_Bcast(cipher, (int)clen, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);
  if (rank == 0) {
    printf("[DEBUG master] after bcast cipher bytes sent\n");
    fflush(stdout);
  } else {
    printf("[DEBUG worker %d] after recv cipher first_byte=0x%02x len=%zu\n",
           rank, clen > 0 ? (unsigned int)cipher[0] : 0, clen);
    fflush(stdout);
  }

  // Limites de espacio de llaves
  u64 total = key_end - key_start + 1ULL;

  int found_flag = 0;
  u64 winner = UINT64_MAX;

  if (rank == 0) {
    // ===================== MASTER =====================
    u64 next = 0;
    int live = world - 1;

    // Semilla base
    u64 base_seed = (u64)time(NULL) ^ 0x9E3779B97F4A7C15ULL;

    while (live > 0) {
      MPI_Status st;
      int fflag = 0;
      MPI_Iprobe(MPI_ANY_SOURCE, TAG_FOUND, MPI_COMM_WORLD, &fflag, &st);
      if (fflag) {
        u64 k;
        MPI_Recv(&k, 1, MPI_UNSIGNED_LONG_LONG, st.MPI_SOURCE, TAG_FOUND,
                 MPI_COMM_WORLD, MPI_STATUS_IGNORE);
        int req_rank = st.MPI_SOURCE;
        printf("[DEBUG master] pedido de trabajo recibido de %d\n", req_rank);
        fflush(stdout);

        found_flag = 1;
        winner = k;
        for (int r = 1; r < world; ++r) {
          MPI_Send(&winner, 1, MPI_UNSIGNED_LONG_LONG, r, TAG_STOP,
                   MPI_COMM_WORLD);
        }
        break;
      }

      int req_rank;
      unsigned char req_byte;
      MPI_Recv(&req_byte, 1, MPI_UNSIGNED_CHAR, MPI_ANY_SOURCE, TAG_REQ,
               MPI_COMM_WORLD, &st);
      req_rank = st.MPI_SOURCE;

      // Si ya hubo ganador, manda STOP
      if (found_flag) {
        MPI_Send(&winner, 1, MPI_UNSIGNED_LONG_LONG, req_rank, TAG_STOP,
                 MPI_COMM_WORLD);
        continue;
      }

      if (next >= total) {
        MPI_Send(NULL, 0, MPI_BYTE, req_rank, TAG_DONE, MPI_COMM_WORLD);
        live--;
      } else {
        u64 len = chunk_size;
        if (len > total - next)
          len = total - next;
        u64 start = key_start + next;
        u64 seed = splitmix64(base_seed ^ start);
        u64 triple[3] = {start, len, seed};
        MPI_Send(triple, 3, MPI_UNSIGNED_LONG_LONG, req_rank, TAG_WORK,
                 MPI_COMM_WORLD);
        next += len;

        static u64 last_report = 0;
        if ((next - last_report) >= (chunk_size * 100)) { // cada 100 chunks
          printf("[MASTER] next offset=%" PRIu64 " / total=%" PRIu64 "\n", next,
                 total);
          fflush(stdout);
          last_report = next;
        }
      }
    }

    // Si terminamos sin ganador, manda STOP con ULLONG_MAX para cerrar a los
    // que sigan vivos
    if (!found_flag) {
      winner = UINT64_MAX;
      for (int r = 1; r < world; ++r) {
        MPI_Send(&winner, 1, MPI_UNSIGNED_LONG_LONG, r, TAG_STOP,
                 MPI_COMM_WORLD);
      }
    }

    // Imprimir resultado
    if (winner != UINT64_MAX) {
      printf("[MASTER] FOUND key = %" PRIu64 "\n", winner);
    } else {
      printf("[MASTER] NOT FOUND in range\n");
    }

  } else {
    // ===================== WORKER =====================
    for (;;) {
      unsigned char req = 1;
      static int req_counter = 0;
      req_counter++;
      if (req_counter % 100 == 0) {
        printf("[DEBUG worker %d] pidiendo trabajo (cnt=%d)\n", rank,
               req_counter);
        fflush(stdout);
      }
      MPI_Send(&req, 1, MPI_UNSIGNED_CHAR, 0, TAG_REQ, MPI_COMM_WORLD);

      MPI_Status st;
      MPI_Probe(0, MPI_ANY_TAG, MPI_COMM_WORLD, &st);

      if (st.MPI_TAG == TAG_DONE) {
        MPI_Recv(NULL, 0, MPI_BYTE, 0, TAG_DONE, MPI_COMM_WORLD,
                 MPI_STATUS_IGNORE);
        break; // sin mas trabajo espera STOP
      }
      if (st.MPI_TAG == TAG_STOP) {
        MPI_Recv(&winner, 1, MPI_UNSIGNED_LONG_LONG, 0, TAG_STOP,
                 MPI_COMM_WORLD, MPI_STATUS_IGNORE);
        found_flag = (winner != UINT64_MAX);
        break;
      }
      if (st.MPI_TAG == TAG_WORK) {
        // debug: vimos que el maestro tiene TAG_WORK listo
        printf("[DEBUG worker %d] probe saw TAG_WORK from master\n", rank);
        fflush(stdout);

        u64 triple[3];
        MPI_Recv(triple, 3, MPI_UNSIGNED_LONG_LONG, 0, TAG_WORK, MPI_COMM_WORLD,
                 MPI_STATUS_IGNORE);
        u64 start = triple[0], len = triple[1], seed = triple[2];

        printf("[DEBUG worker %d] recv work start=%" PRIu64 " len=%" PRIu64
               " seed=%" PRIu64 "\n",
               rank, start, len, seed);
        fflush(stdout);

        // Recorre el chunk en orden pseudoaleatorio
        u64 kfound = 0;
        int ok = search_chunk_random(start, len, seed, cipher, clen, keyword,
                                     &kfound, rank);
        if (ok) {
          // Reporta a master y termina
          MPI_Send(&kfound, 1, MPI_UNSIGNED_LONG_LONG, 0, TAG_FOUND,
                   MPI_COMM_WORLD);
          // Espera STOP para conocer la llave ganadora global
          MPI_Recv(&winner, 1, MPI_UNSIGNED_LONG_LONG, 0, TAG_STOP,
                   MPI_COMM_WORLD, MPI_STATUS_IGNORE);
          found_flag = 1;
          break;
        }

        // Chequeo no bloqueante de STOP cada chunk
        int sf = 0;
        MPI_Iprobe(0, TAG_STOP, MPI_COMM_WORLD, &sf, &st);
        if (sf) {
          MPI_Recv(&winner, 1, MPI_UNSIGNED_LONG_LONG, 0, TAG_STOP,
                   MPI_COMM_WORLD, MPI_STATUS_IGNORE);
          found_flag = (winner != UINT64_MAX);
          break;
        }
      }
    }

    if (found_flag && winner != UINT64_MAX) {
      printf("[WORKER %d] winner=%" PRIu64 "\n", rank, winner);
    }
  }

  free(cipher);
  MPI_Finalize();
  return 0;
}
