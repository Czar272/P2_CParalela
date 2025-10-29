# Makefile para flujo: compilar -> cifrar -> brute-force
# Uso rápido:
#   make             # compila todo
#   make run         # genera plain, cifra (KEY) y corre brute-force (KEY_BITS)
#   make encrypt     # sólo cifra (usa KEY)
#   make bruteforce  # sólo corre bruteforce (usa KEY_BITS)

# Variables ajustables al invocar make:
#   make run KEY=0xA5 KEY_BITS=12
#   make encrypt KEY=0x00ABCDEF

# ----- Config -----
CC        := gcc
CFLAGS    := -O2 -Wall -Wextra -Iinclude
LDFLAGS   := -lcrypto

# Si quieres ocultar advertencias deprecated de OpenSSL (opcional)
# Añádelo a CFLAGS al compilar (por ejemplo en sistemas con OpenSSL3)
SUPPRESS_DEPREC := -Wno-deprecated-declarations

# Binaries / paths
SRCDIR    := src
BUILDDIR  := build
BINDIR    := build
FILESDIR  := files

ENCRYPT_SRC := $(SRCDIR)/encrypt.c
BRUTE_SRC   := $(SRCDIR)/bruteforce_seq.c

ENCRYPT_BIN := $(BINDIR)/encrypt
BRUTE_BIN   := $(BINDIR)/bruteforce_seq

# Default values (puedes sobrescribir al llamar make)
KEY        ?= 0xA5
KEY_BITS   ?= 12
PLAINTEXT  ?= "Esta es una prueba de encriptacion"
PLAIN_FILE := $(FILESDIR)/plain.txt
CIPHER_FILE := $(FILESDIR)/cipher.bin

# ----- Targets -----
.PHONY: all build dirs encrypt bruteforce run run_clean clean rebuild

all: build

build: dirs $(ENCRYPT_BIN) $(BRUTE_BIN)

dirs:
	@mkdir -p $(BUILDDIR) $(FILESDIR)

# compile encrypt
$(ENCRYPT_BIN): $(ENCRYPT_SRC)
	$(CC) $(CFLAGS) $(SUPPRESS_DEPREC) -o $@ $< $(LDFLAGS)

# compile brute 
$(BRUTE_BIN): $(BRUTE_SRC)
	$(CC) $(CFLAGS) $(SUPPRESS_DEPREC) -o $@ $< $(LDFLAGS)

# write plain text file (only if not present)
$(PLAIN_FILE):
	@mkdir -p $(dir $@)
	@echo -n $(PLAINTEXT) > $@
	@echo "Created $(PLAIN_FILE):"
	@stat -c "%s bytes" $@ || true

encrypt: $(ENCRYPT_BIN) $(PLAIN_FILE)
	@echo "Encrypting $(PLAIN_FILE) -> $(CIPHER_FILE) using KEY=$(KEY)"
	@./$(ENCRYPT_BIN) $(PLAIN_FILE) $(CIPHER_FILE) $(KEY)

bruteforce: $(BRUTE_BIN)
	@echo "Running brute-force on $(CIPHER_FILE) looking for phrase \"es una prueba de\" with KEY_BITS=$(KEY_BITS)"
	@./$(BRUTE_BIN) $(CIPHER_FILE) "es una prueba de" $(KEY_BITS)

# full demo: create plain (if needed), encrypt with KEY, then brute-force with KEY_BITS
run: encrypt bruteforce

# Same as run but forces regenerate plain and re-encrypt with the KEY, then brute
run_clean:
	@rm -f $(PLAIN_FILE) $(CIPHER_FILE)
	$(MAKE) PLAIN_FILE=$(PLAIN_FILE) encrypt
	$(MAKE) bruteforce

# rebuild from scratch
rebuild: clean all

clean:
	@rm -rf $(BUILDDIR) $(FILESDIR)/*.bin $(FILESDIR)/plain.txt
	@echo "Cleaned build and files (kept src/)"

