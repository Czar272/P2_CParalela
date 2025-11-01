/* src/mw_bruteforce.c
 *
 * Compile:
 *   mpicc -O2 -std=c11 -o build/mw_bruteforce src/mw_bruteforce.c -lcrypto
 *
 * Run:
 *   mpirun -np P ./build/mw_bruteforce --cipher ./files/cipher.bin --keyword "..." --start A --end B [--chunk N]
 * 
 * Quick Exmample:
 * mpirun -np 4 ./build/mw_bruteforce \
 * --cipher ./files/cipher_test.bin \
 * --keyword "es una prueba de" \
 * --start 0 --end 1000000 \
 * --chunk 262144
 *
 */

#include <mpi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <limits.h>
#include <errno.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/provider.h>

typedef unsigned long long u64;
#define TAG_REQ  1
#define TAG_WORK 2
#define TAG_STOP 3
#define TAG_DONE 4

// Default chunk size: ~262k keys. Ajusta con --chunk
#define DEFAULT_CHUNK ((u64)1<<18)

// Heartbeat: master prints progreso cada HEARTBEAT_CHUNKS * chunk_size bytes
#define HEARTBEAT_CHUNKS 1000

// DEBUG macro: activar con -DDEBUG al compilar
#ifdef DEBUG
  #define DPRINTF(...) do { fprintf(stderr, __VA_ARGS__); fflush(stderr); } while(0)
#else
  #define DPRINTF(...) do {} while(0)
#endif

static u64 splitmix64_next(u64 *state) {
  u64 z = (*state += 0x9e3779b97f4a7c15ULL);
  z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9ULL;
  z = (z ^ (z >> 27)) * 0x94d049bb133111ebULL;
  return z ^ (z >> 31);
}

static u64 pick_stride(u64 seed, u64 len) {
  u64 s = (seed >> 1) | 1ULL; // odd
  s = s % (len | 1ULL);       // avoid >= len
  if (s == 0) s = 1;
  return s;
}

/* ========== DES helper using EVP (DES-ECB, no padding) ========== */
static void set_odd_parity_manual(unsigned char keyblock[8]) {
  for (int i = 0; i < 8; ++i) {
    unsigned char b = keyblock[i];
    int ones = 0;
    for (int j = 1; j < 8; ++j) if (b & (1u<<j)) ones++;
    keyblock[i] = (b & 0xFE) | ((ones & 1) ? 0x00 : 0x01);
  }
}

static void u64_to_8bytes(u64 key, unsigned char out[8]) {
  for (int i = 0; i < 8; ++i) out[7 - i] = (unsigned char)((key >> (i * 8)) & 0xFFULL);
  set_odd_parity_manual(out);
}

static int contains_subsequence(const unsigned char *hay, size_t haylen,
                                const char *needle, size_t needlen) {
  if (needlen == 0) return 1;
  if (haylen < needlen) return 0;
  for (size_t i = 0; i + needlen <= haylen; ++i) {
    if (hay[i] == (unsigned char)needle[0]) {
      size_t j = 1;
      for (; j < needlen; ++j) if (hay[i+j] != (unsigned char)needle[j]) break;
      if (j == needlen) return 1;
    }
  }
  return 0;
}

static int try_key(u64 key,
                   const unsigned char* cipher, size_t clen,
                   const char* keyword) {
  if (!cipher || clen == 0 || !keyword) return 0;
  size_t klen = strlen(keyword);
  if (klen == 0) return 0;

  size_t nbytes = (clen / 8) * 8;
  if (nbytes == 0) return 0;

  unsigned char keyblock[8];
  u64_to_8bytes(key, keyblock);

  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx) return 0;

  if (EVP_DecryptInit_ex(ctx, EVP_des_ecb(), NULL, keyblock, NULL) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    return 0;
  }
  EVP_CIPHER_CTX_set_padding(ctx, 0);

  unsigned char *plain = (unsigned char*)malloc(nbytes);
  if (!plain) { EVP_CIPHER_CTX_free(ctx); return 0; }

  int outlen = 0, tmplen = 0;
  if (EVP_DecryptUpdate(ctx, plain, &outlen, cipher, (int)nbytes) != 1) {
    free(plain); EVP_CIPHER_CTX_free(ctx); return 0;
  }
  if (EVP_DecryptFinal_ex(ctx, plain + outlen, &tmplen) != 1) {
    tmplen = 0;
  }
  int plain_len = outlen + tmplen;

  int found = contains_subsequence(plain, (size_t)plain_len, keyword, klen);

  free(plain);
  EVP_CIPHER_CTX_free(ctx);
  return found;
}

static u64 search_chunk_random(u64 start, u64 len, u64 seed,
                               const unsigned char *cipher, size_t clen,
                               const char *keyword) {
  if (len == 0) return 0;
  u64 state = seed ^ 0x9e3779b97f4a7c15ULL;
  u64 stride = pick_stride(splitmix64_next(&state), len);
  u64 pos = (splitmix64_next(&state) % len);
  for (u64 i = 0; i < len; ++i) {
    u64 idx = (pos + i * stride) % len;
    u64 key = start + idx;
    if (try_key(key, cipher, clen, keyword)) {
      return key;
    }
  }
  return 0;
}

int main(int argc, char **argv) {
  MPI_Init(&argc, &argv);

  int rank = -1, size = -1;
  MPI_Comm_rank(MPI_COMM_WORLD, &rank);
  MPI_Comm_size(MPI_COMM_WORLD, &size);

  const char *cipher_path = NULL;
  const char *keyword = NULL;
  u64 key_start = 0, key_end = 0;
  u64 chunk_size = DEFAULT_CHUNK;

  for (int i = 1; i < argc; ++i) {
    if (!strcmp(argv[i], "--cipher") && i+1 < argc) cipher_path = argv[++i];
    else if (!strcmp(argv[i], "--keyword") && i+1 < argc) keyword = argv[++i];
    else if (!strcmp(argv[i], "--start") && i+1 < argc) key_start = (u64)strtoull(argv[++i], NULL, 10);
    else if (!strcmp(argv[i], "--end") && i+1 < argc) key_end = (u64)strtoull(argv[++i], NULL, 10);
    else if (!strcmp(argv[i], "--chunk") && i+1 < argc) chunk_size = (u64)strtoull(argv[++i], NULL, 10);
    else if (!strcmp(argv[i], "--help")) {
      if (rank == 0) {
        fprintf(stderr, "Uso: mpirun -np P ./mw_bruteforce --cipher FILE --keyword \"...\" --start A --end B [--chunk N]\n");
      }
      MPI_Finalize();
      return 0;
    }
  }

  DPRINTF("[DEBUG rank %d] cipher_path=%s keyword=%s start=%" PRIu64 " end=%" PRIu64 " chunk=%" PRIu64 "\n",
          rank, cipher_path?cipher_path:"<NULL>", keyword?keyword:"<NULL>", key_start, key_end, chunk_size);

  if (!cipher_path || !keyword || key_end <= key_start) {
    if (rank == 0) fprintf(stderr, "Parámetros inválidos. Usa --help.\n");
    MPI_Finalize();
    return 1;
  }

  unsigned char *cipher = NULL;
  size_t clen = 0;
  if (rank == 0) {
    FILE *f = fopen(cipher_path, "rb");
    if (!f) {
      perror("fopen(cipher)");
      MPI_Abort(MPI_COMM_WORLD, 1);
    }
    if (fseek(f, 0, SEEK_END) != 0) { perror("fseek"); fclose(f); MPI_Abort(MPI_COMM_WORLD,1); }
    long s = ftell(f);
    if (s < 0) { perror("ftell"); fclose(f); MPI_Abort(MPI_COMM_WORLD,1); }
    rewind(f);
    clen = (size_t)s;
    cipher = (unsigned char*)malloc(clen);
    if (!cipher) { fprintf(stderr, "malloc cipher\n"); fclose(f); MPI_Abort(MPI_COMM_WORLD,1); }
    if (fread(cipher, 1, clen, f) != clen) { perror("fread"); free(cipher); fclose(f); MPI_Abort(MPI_COMM_WORLD,1); }
    fclose(f);
  }

  unsigned long long clen64 = (unsigned long long)clen;
  MPI_Bcast(&clen64, 1, MPI_UNSIGNED_LONG_LONG, 0, MPI_COMM_WORLD);
  DPRINTF("[DEBUG rank %d] after bcast clen=%llu\n", rank, (unsigned long long)clen64);
  if (rank != 0) {
    clen = (size_t)clen64;
    if (clen > 0) cipher = (unsigned char*)malloc(clen);
    else cipher = NULL;
  }
  MPI_Bcast(cipher, (int)clen, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);
  DPRINTF("[DEBUG rank %d] after bcast cipher bytes=%zu\n", rank, clen);

  OSSL_PROVIDER *prov = NULL;
  prov = OSSL_PROVIDER_load(NULL, "legacy");
  if (!prov) {
    DPRINTF("[DEBUG rank %d] OSSL_PROVIDER_load(legacy) failed (maybe not available)\n", rank);
  } else {
    DPRINTF("[DEBUG rank %d] legacy provider loaded\n", rank);
  }

  /* MASTER */
  if (rank == 0) {
    u64 next = key_start;
    u64 total = key_end - key_start + 1;
    u64 last_report = 0;
    int workers_alive = size - 1;

    while (workers_alive > 0) {
      unsigned char req;
      MPI_Status st;
      MPI_Recv(&req, 1, MPI_UNSIGNED_CHAR, MPI_ANY_SOURCE, TAG_REQ, MPI_COMM_WORLD, &st);
      int src = st.MPI_SOURCE;
      DPRINTF("[DEBUG master] pedido de trabajo recibido de %d\n", src);
      if (req == 1) {
        if (next > key_end) {
          MPI_Send(NULL, 0, MPI_BYTE, src, TAG_DONE, MPI_COMM_WORLD);
        } else {
          u64 remaining = key_end - next + 1;
          u64 len = (remaining > chunk_size) ? chunk_size : remaining;
          u64 seed = (u64)time(NULL) ^ (next * 0x9e3779b97f4a7c15ULL);
          u64 triple[3] = { next, len, seed };
          MPI_Send(triple, 3, MPI_UNSIGNED_LONG_LONG, src, TAG_WORK, MPI_COMM_WORLD);

          next += len;

          if ((next - last_report) >= (chunk_size * HEARTBEAT_CHUNKS)) {
            printf("[MASTER] progreso: next=%" PRIu64 " / total=%" PRIu64 "\n", next, total);
            fflush(stdout);
            last_report = next;
          }
        }
      } else if (req == 2) {
        u64 winner;
        MPI_Recv(&winner, 1, MPI_UNSIGNED_LONG_LONG, src, TAG_STOP, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
        if (winner != (u64)UINT64_MAX) {
          printf("[MASTER] FOUND key = %llu\n", (unsigned long long)winner);
          fflush(stdout);
          for (int r = 1; r < size; ++r) {
            if (r == src) continue;
            MPI_Send(&winner, 1, MPI_UNSIGNED_LONG_LONG, r, TAG_STOP, MPI_COMM_WORLD);
          }
        }
      } else {
        DPRINTF("[DEBUG master] unknown req=%u from %d\n", (unsigned)req, src);
      }

    }

    printf("[MASTER] NOT FOUND in range\n");
    fflush(stdout);

  } else {
    /* WORKER */
    int found_flag = 0;
    u64 winner = (u64)UINT64_MAX;

    while (!found_flag) {
      unsigned char req_byte = 1;
      MPI_Send(&req_byte, 1, MPI_UNSIGNED_CHAR, 0, TAG_REQ, MPI_COMM_WORLD);

      MPI_Status st;
      MPI_Probe(0, MPI_ANY_TAG, MPI_COMM_WORLD, &st);

      if (st.MPI_TAG == TAG_DONE) {
        MPI_Recv(NULL, 0, MPI_BYTE, 0, TAG_DONE, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
        DPRINTF("[DEBUG worker %d] received TAG_DONE\n", rank);
        break;
      }
      if (st.MPI_TAG == TAG_STOP) {
        MPI_Recv(&winner, 1, MPI_UNSIGNED_LONG_LONG, 0, TAG_STOP, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
        if (winner != (u64)UINT64_MAX) {
          found_flag = 1;
          printf("[WORKER %d] winner=%llu\n", rank, (unsigned long long)winner);
          fflush(stdout);
        }
        break;
      }
      if (st.MPI_TAG == TAG_WORK) {
        DPRINTF("[DEBUG worker %d] probe saw TAG_WORK\n", rank);

        u64 triple[3];
        MPI_Recv(triple, 3, MPI_UNSIGNED_LONG_LONG, 0, TAG_WORK, MPI_COMM_WORLD, MPI_STATUS_IGNORE);
        u64 start = triple[0], len = triple[1], seed = triple[2];
        DPRINTF("[DEBUG worker %d] recv work start=%" PRIu64 " len=%" PRIu64 " seed=%" PRIu64 "\n",
                rank, start, len, seed);

        /* search chunk */
        u64 found = search_chunk_random(start, len, seed, cipher, clen, keyword);
        if (found) {
          unsigned char found_signal = 2;
          MPI_Send(&found_signal, 1, MPI_UNSIGNED_CHAR, 0, TAG_REQ, MPI_COMM_WORLD);
          MPI_Send(&found, 1, MPI_UNSIGNED_LONG_LONG, 0, TAG_STOP, MPI_COMM_WORLD);
          printf("[WORKER %d] winner=%llu\n", rank, (unsigned long long)found);
          fflush(stdout);
          found_flag = 1;
          break;
        }
      }
    }
    DPRINTF("[DEBUG worker %d] finalizing\n", rank);
  }

  /* cleanup */
  if (cipher) free(cipher);
  if (prov) {
    OSSL_PROVIDER_unload(prov);
    DPRINTF("[DEBUG rank %d] legacy provider unloaded\n", rank);
  }

  MPI_Finalize();
  return 0;
}
