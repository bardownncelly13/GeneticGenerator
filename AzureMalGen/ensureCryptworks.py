import os
import shutil
import subprocess
import re

# Compile flags for MinGW, without -mwindows
LINK_FLAGS = [
    "-static", "-static-libgcc", "-static-libstdc++",
    "-lgdiplus", "-luser32", "-lgdi32", "-lole32", "-luuid",
    "-lcrypt32"
]

def test(cpp_path, compiler="x86_64-w64-mingw32-g++", key=77, block_size=1024):
    if not os.path.exists(cpp_path):
        print(f"❌ File not found: {cpp_path}")
        return 0

    test_cpp = cpp_path.replace(".cpp", "_test.cpp")
    shutil.copy(cpp_path, test_cpp)

    # Remove existing main()
    with open(test_cpp, "r", encoding="utf-8") as f:
        code = f.read()
    main_pattern = re.compile(r'\bint\s+main\s*\([^)]*\)\s*\{[\s\S]*?\}', re.MULTILINE)
    code = re.sub(main_pattern, "// main() removed for testing\n", code)
    with open(test_cpp, "w", encoding="utf-8") as f:
        f.write(code)

    # Append test main
    test_main = f"""
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <windows.h>

void encryptFile(const std::string& inputFile, const std::string& outputFile, char key);
void decryptFile(BYTE* data, DWORD size, BYTE key);

int main() {{
    const char* test_input = "test_input.bin";
    const char* test_enc = "test_enc.bin";
    const char* test_dec = "test_dec.bin";

    // create random test input
    {{
        std::ofstream ofs(test_input, std::ios::binary);
        for (size_t i = 0; i < {block_size}; ++i) {{
            char b = rand() % 256;
            ofs.put(b);
        }}
    }}

    char k = static_cast<char>({key} & 0xFF);

    encryptFile(test_input, test_enc, k);

    // read encrypted file
    std::ifstream ifs(test_enc, std::ios::binary | std::ios::ate);
    if (!ifs) return 0;
    std::streamsize size = ifs.tellg();
    ifs.seekg(0, std::ios::beg);
    std::vector<BYTE> buffer(static_cast<size_t>(size));
    ifs.read(reinterpret_cast<char*>(buffer.data()), size);
    ifs.close();

    decryptFile(buffer.data(), static_cast<DWORD>(size), static_cast<BYTE>(k));

    // write decrypted file
    std::ofstream ofs(test_dec, std::ios::binary);
    if (!ofs) return 0;
    ofs.write(reinterpret_cast<const char*>(buffer.data()), size);
    ofs.close();

    // compare input and decrypted
    std::ifstream orig(test_input, std::ios::binary);
    std::ifstream dec(test_dec, std::ios::binary);
    if (!orig || !dec) return 0;

    std::vector<char> orig_data((std::istreambuf_iterator<char>(orig)),
                                std::istreambuf_iterator<char>());
    std::vector<char> dec_data((std::istreambuf_iterator<char>(dec)),
                               std::istreambuf_iterator<char>());

    return orig_data == dec_data ? 1 : 0;
}}
"""
    with open(test_cpp, "a", encoding="utf-8") as f:
        f.write("\n")
        f.write(test_main)

    exe_test = test_cpp.replace(".cpp", ".exe")

    print(f"🧪 Compiling test: {test_cpp}")
    compile_cmd = [compiler, "-std=c++17", test_cpp, "-o", exe_test] + LINK_FLAGS
    result = subprocess.run(compile_cmd, capture_output=True, text=True)

    if result.returncode != 0:
        print("❌ Compilation failed:\n", result.stderr)
        _cleanup(test_cpp, exe_test)
        return 0

    # Use Wine if not Windows
    if os.name != "nt":
        run_cmd = ["wine", exe_test]
    else:
        run_cmd = [exe_test]

    print("🚀 Running encryption/decryption roundtrip test...")
    run_result = subprocess.run(run_cmd, capture_output=True, text=True)
    passed = run_result.returncode == 1

    if not passed:
        print("❌ Roundtrip failed.")
    else:
        print("✅ Roundtrip passed.")

    _cleanup(test_cpp, exe_test, "test_input.bin", "test_enc.bin", "test_dec.bin")
    return 1 if passed else 0

def _cleanup(*paths):
    for p in paths:
        if os.path.exists(p):
            try: os.remove(p)
            except: pass
