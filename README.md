# P2_CParalela
Proyecto # 2 - Computación Paralela y Distribuida


## Estructura del repositorio
```
.
├─ src/
│  ├─ encrypt.c            # cifrador (usa EVP + legacy provider)
│  └─ bruteforce_seq.c    # búsqueda secuencial (DES ECB, brute force)
├─ build/                 # binarios compilados
├─ files/                 # plain.txt (ejemplos de texto a encriptar) y cipher.bin (encriptados)
├─ Makefile               # automatizacion
└─ README.md              # este archivo
```

### Requirements
- Compilador gcc
- Open SSL
    ```
    sudo apt update
    sudo apt install build-essential libssl-dev pkg-config
    ```

### Compilar

Desde la raiz del proyecto

Con Makefile:

```
make
```

Sin Makefile:
```
gcc -O2 -o build/encrypt src/encrypt.c -lcrypto
gcc -O2 -o build/bruteforce_seq src/bruteforce_seq.c -lcrypto -Wno-deprecated-declarations
```

### Makefile

#### Make encrypt
- Si files/plain.txt no existe:

```
mkdir -p files
echo -n "Esta es una prueba de encriptacion" > files/plain.txt
```

```
./build/encrypt files/plain.txt files/cipher.bin 0xA5
```

#### Make bruteforce
```
./build/bruteforce_seq files/cipher.bin "es una prueba de" 12
```


#### Make run
- Si files/plain.txt no existe:
```
mkdir -p files
echo -n "Esta es una prueba de encriptacion" > files/plain.txt  # (si no existe)
```
```
./build/encrypt files/plain.txt files/cipher.bin 0xA5

./build/bruteforce_seq files/cipher.bin "es una prueba de" 12
```


#### Para personalizar llave y tamaño de espacio
```
make run KEY=0x00ABCDEF KEY_BITS=24
```

Que equivale a: 
```
./build/encrypt files/plain.txt files/cipher.bin 0x00ABCDEF

./build/bruteforce_seq files/cipher.bin "es una prueba de" 24
```