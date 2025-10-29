# Makefile para Proyecto 2 - Computación Paralela y Distribuida
# Bruteforce DES con MPI

CC = gcc
MPICC = mpicc
CFLAGS = -O2 -Wall
FRAMEWORKS = -framework Security
BUILDDIR = build
SRCDIR = src

# Targets
.PHONY: all clean sequential parallel

all: sequential

sequential: $(BUILDDIR)/bruteforce_seq $(BUILDDIR)/encrypt

parallel: $(BUILDDIR)/bruteforce_mpi

# Bruteforce secuencial
$(BUILDDIR)/bruteforce_seq: $(SRCDIR)/bruteforce_seq.c
	$(CC) $(CFLAGS) -o $@ $< $(FRAMEWORKS)

# Programa de cifrado
$(BUILDDIR)/encrypt: $(SRCDIR)/encrypt.c
	$(CC) $(CFLAGS) -o $@ $< $(FRAMEWORKS)

# Bruteforce paralelo con MPI (por implementar)
$(BUILDDIR)/bruteforce_mpi: $(SRCDIR)/bruteforce_mpi.c
	$(MPICC) $(CFLAGS) -o $@ $< $(FRAMEWORKS)

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