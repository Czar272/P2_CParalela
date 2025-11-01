#!/usr/bin/env bash

# chmod +x tools/experiments.sh

# (opcional) Cambia procesos o chunk por env vars:
# export NPROCS=8
# export CHUNK=1048576

# ./experiments.sh

set -euo pipefail

NPROCS="${NPROCS:-4}"
CHUNK="${CHUNK:-262144}"
KEYWORD="${KEYWORD:-es una prueba de}"
PLAINTXT="${PLAINTXT:-Hola UVG, es una prueba de DES paralelo}"
CIPHER_DIR="files"
LOG_DIR="logs"
CSV_FILE="${LOG_DIR}/perf.csv"

mkdir -p "$CIPHER_DIR" "$LOG_DIR"

# Verifica binarios
if [[ ! -x tools/gen_des_test ]]; then
  echo "ERROR: tools/gen_des_test no existe o no es ejecutable."
  exit 1
fi
if [[ ! -x build/mw_bruteforce ]]; then
  echo "ERROR: build/mw_bruteforce no existe o no es ejecutable."
  exit 1
fi

# Computa 2^56 y llaves pedidas con bc (enteros 64-bit exactos)
TWO56="$(echo '2^56' | bc)"
EASY_KEY="$(echo "$TWO56/2 + 1" | bc)"                            # 2^55 + 1
MED_KEY="$(echo "$TWO56/2 + $TWO56/8" | bc)"                      # 2^55 + 2^53 = 5*2^53
HARD_KEY="$(echo "($TWO56+6)/7 + ($TWO56+12)/13" | bc)"           # ceil(2^56/7) + ceil(2^56/13)

# Rango de búsqueda 0..(2^56-1)
START="0"
END="$(echo "$TWO56 - 1" | bc)"                                   # 72057594037927935

stamp() { date +"%Y-%m-%d %H:%M:%S"; }
ts() { date +%s; }

gen_cipher() {
  local key="$1"; local out="$2"
  echo "[$(stamp)] Generando cipher '${out}' con key=${key} ..."
  ./tools/gen_des_test "$(pwd)/${out}" "${key}" "${KEYWORD}" "${PLAINTXT}"
}

run_case() {
  local name="$1"    # easy | medium | hard
  local key="$2"
  local cipher="${CIPHER_DIR}/cipher_${name}.bin"
  local log="${LOG_DIR}/run_${name}_$(date +%Y%m%d-%H%M%S).log"

  # Generar cifrado
  gen_cipher "${key}" "${cipher}"

  echo "[$(stamp)] Ejecutando brute-force (${name}) NPROCS=${NPROCS} CHUNK=${CHUNK}"
  echo "           Rango: ${START} .. ${END}"
  local t0="$(ts)"

  mpirun -np "${NPROCS}" ./build/mw_bruteforce \
    --cipher "./${cipher}" \
    --keyword "${KEYWORD}" \
    --start "${START}" --end "${END}" \
    --chunk "${CHUNK}" | tee "${log}"
  local t1="$(ts)"
  local elapsed=$(( t1 - t0 ))

  local found_line
  found_line="$(grep -Eo '\[MASTER\] FOUND key = [0-9]+' "${log}" || true)"
  local found_key="NA"
  if [[ -n "${found_line}" ]]; then
    found_key="$(echo "${found_line}" | awk '{print $5}')"
  fi

  # Métricas
  local keys_total="${TWO56}"   # buscamos todo el espacio 2^56
  local throughput
  throughput="$(echo "scale=2; ${keys_total} / ${elapsed}" | bc)"

  if [[ ! -f "${CSV_FILE}" ]]; then
    echo "timestamp,case,key,np,chunk,start,end,elapsed_s,keys_total,throughput_keys_per_s,cipher,found_key,log" > "${CSV_FILE}"
  fi

  echo "$(stamp),${name},${key},${NPROCS},${CHUNK},${START},${END},${elapsed},${keys_total},${throughput},${cipher},${found_key},${log}" >> "${CSV_FILE}"

  echo "[$(stamp)] Listo (${name}): elapsed=${elapsed}s throughput=${throughput} keys/s found_key=${found_key}"
  echo "           Log: ${log}"
}

# Ejecuta las tres corridas
run_case "easy"   "${EASY_KEY}"
run_case "medium" "${MED_KEY}"
run_case "hard"   "${HARD_KEY}"

echo
echo "Resumen CSV -> ${CSV_FILE}"
column -s, -t "${CSV_FILE}" | sed 's/^/  /'
