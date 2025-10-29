# P2_CParalela
Proyecto # 2 - Computación Paralela y Distribuida

## Descripción
Implementación de un algoritmo de fuerza bruta (bruteforce) para descifrar textos cifrados con DES, utilizando Open MPI para distribución de trabajo en memoria distribuida.

## Objetivos
- Implementar programas paralelos con memoria distribuida usando Open MPI
- Optimizar el uso de recursos distribuidos y mejorar el speedup
- Descubrir llaves privadas usando fuerza bruta
- Analizar el comportamiento del speedup de forma estadística

## Estructura del Proyecto
```
P2_CParalela/
├── src/
│   ├── bruteforce_seq.c      # Versión secuencial del bruteforce
│   └── encrypt.c             # Programa de cifrado DES
├── build/                    # Ejecutables compilados
├── files/
│   └── plain.txt            # Archivo de texto de prueba
└── Makefile                  # Script de compilación
```

## Compilación
```bash
# Compilar versión secuencial
make sequential

# Compilar versión paralela (cuando esté implementada)
make parallel

# Limpiar archivos compilados
make clean

# Limpiar archivos generados (.bin)
make clean-files

# Limpiar todo
make clean-all

# Ejecutar pruebas básicas
make test

# Generar archivos cifrados para pruebas del proyecto
make test-project
```

## Uso

### Cifrado
```bash
./build/encrypt <archivo_entrada> <archivo_salida> <clave_decimal>
```

### Bruteforce Secuencial
```bash
./build/bruteforce_seq <archivo_cifrado> "<frase_clave>" <bits_clave> [inicio] [fin]
```

### Bruteforce Paralelo
```bash
mpirun -np <num_procesos> ./build/bruteforce_mpi <archivo_cifrado> "<frase_clave>" <bits_clave>
```

## Ejemplos
```bash
# Cifrar archivo
./build/encrypt files/plain.txt files/cipher.bin 123456

# Buscar clave con bruteforce (24 bits = 16M posibles claves)
./build/bruteforce_seq files/cipher.bin "es una prueba de" 24

# Paralelo con 4 procesos
mpirun -np 4 ./build/bruteforce_mpi files/cipher.bin "es una prueba de" 24
```

## Requisitos del Sistema
- GCC compiler
- OpenMPI (para versión paralela)
- macOS con CommonCrypto framework
- Al menos 8GB RAM recomendado

## Texto de Prueba
Según especificaciones del proyecto:
- **Texto**: "Esta es una prueba de proyecto 2"
- **Frase clave**: "es una prueba de"
- **Claves de prueba**: 123456L, 18014398509481983L, 18014398509481984L
