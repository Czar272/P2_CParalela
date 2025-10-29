# Makefile para Proyecto 2 - Computación Paralela y Distribuida
# Bruteforce DES con MPI

CC = gcc
MPICC = mpicc
CFLAGS = -O2 -Wall
BUILDDIR = build
SRCDIR = src

OS := $(shell uname -s)

ifeq ($(OS),Darwin)
    CRYPTO_LIBS = -framework Security
else
    CRYPTO_LIBS = -lcrypto
endif

# Targets
.PHONY: all clean sequential parallel bruteforce

all: sequential

sequential: $(BUILDDIR)/bruteforce_seq $(BUILDDIR)/encrypt

parallel: $(BUILDDIR)/bruteforce_mpi

# Bruteforce del catedrático (adaptado para macOS)
bruteforce: $(BUILDDIR)/bruteforce

$(BUILDDIR):
	mkdir -p $(BUILDDIR)

$(BUILDDIR)/bruteforce: $(SRCDIR)/bruteforce.c | $(BUILDDIR)
	$(MPICC) $(CFLAGS) -o $@ $< $(CRYPTO_LIBS)

# Bruteforce secuencial
$(BUILDDIR)/bruteforce_seq: $(SRCDIR)/bruteforce_seq.c | $(BUILDDIR)
	$(CC) $(CFLAGS) -o $@ $< $(CRYPTO_LIBS)

# Programa de cifrado
$(BUILDDIR)/encrypt: $(SRCDIR)/encrypt.c | $(BUILDDIR)
	$(CC) $(CFLAGS) -o $@ $< $(CRYPTO_LIBS)

# Bruteforce paralelo con MPI (por implementar)
$(BUILDDIR)/bruteforce_mpi: $(SRCDIR)/bruteforce_mpi.c | $(BUILDDIR)
	$(MPICC) $(CFLAGS) -o $@ $< $(CRYPTO_LIBS)

# Limpiar
clean:
	rm -f $(BUILDDIR)/*

# Limpiar archivos generados
clean-files:
	rm -f files/cipher*.bin

# Limpiar todo
clean-all: clean clean-files

# Pruebas
test: sequential
	@echo "=== Generando archivo cifrado de prueba ==="
	./$(BUILDDIR)/encrypt files/plain.txt files/cipher.bin 123456
	@echo "=== Probando bruteforce secuencial ==="
	./$(BUILDDIR)/bruteforce_seq files/cipher.bin "es una prueba de" 20

# Generar archivos cifrados para las pruebas del proyecto
test-project: sequential
	@echo "=== Generando archivos cifrados para Parte B del proyecto ==="
	./$(BUILDDIR)/encrypt files/plain.txt files/cipher_123456.bin 123456
	./$(BUILDDIR)/encrypt files/plain.txt files/cipher_big1.bin 18014398509481983
	./$(BUILDDIR)/encrypt files/plain.txt files/cipher_big2.bin 18014398509481984
	@echo "=== Archivos generados: cipher_123456.bin, cipher_big1.bin, cipher_big2.bin ==="

# Pruebas específicas del proyecto con 4 procesos
test-parte-b: sequential parallel test-project
	@echo "=== PRUEBAS PARTE B DEL PROYECTO (4 procesos) ==="
	@echo "Parte B.2.a - Clave 123456L (secuencial):"
	time ./$(BUILDDIR)/bruteforce_seq files/cipher_123456.bin "es una prueba de" 24
	@echo ""
	@echo "Parte B.2.a - Clave 123456L (paralelo 4 procesos):"
	time mpirun -np 4 ./$(BUILDDIR)/bruteforce_mpi files/cipher_123456.bin "es una prueba de" 24

# Análisis de speedup con diferentes números de procesos
speedup-analysis: sequential parallel test-project
	@echo "=== ANÁLISIS DE SPEEDUP ==="
	@echo "1 proceso:"
	time mpirun -np 1 ./$(BUILDDIR)/bruteforce_mpi files/cipher_123456.bin "es una prueba de" 20
	@echo ""
	@echo "2 procesos:"
	time mpirun -np 2 ./$(BUILDDIR)/bruteforce_mpi files/cipher_123456.bin "es una prueba de" 20
	@echo ""
	@echo "4 procesos:"
	time mpirun -np 4 ./$(BUILDDIR)/bruteforce_mpi files/cipher_123456.bin "es una prueba de" 20