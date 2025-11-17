import os
import subprocess
import argparse
import random
import re

parser = argparse.ArgumentParser(description="Compile a C++ encryption script and use it on binaries")
parser.add_argument("--cpp", required=True, help="Path to the C++ file to compile")
parser.add_argument("--binaries", nargs="+", required=True, help="List of binaries or folders to encrypt")
parser.add_argument("--key", type=int, default=random.randint(1, 255), help="Encryption key")
parser.add_argument("--output", type=str, default="generated/encrypted_binaries", help="outputdir")
args = parser.parse_args()

cpp_file = args.cpp
exe_file = cpp_file.replace(".cpp", ".out")
key = args.key

output_dir = args.output
os.makedirs(output_dir, exist_ok=True)

binaries = []
for path in args.binaries:
    if os.path.isdir(path):
        files = [os.path.join(path, f) for f in os.listdir(path)
                 if os.path.isfile(os.path.join(path, f))]
        binaries.extend(files)
    elif os.path.isfile(path):
        binaries.append(path)

if not binaries:
    raise FileNotFoundError("No binaries found to encrypt!")

with open(cpp_file, "r", encoding="utf-8") as f:
    code = f.read()


main_pattern = r'int\s+main\s*\([^)]*\)\s*\{[\s\S]*?\}'
code = re.sub(main_pattern, "", code)

wrapper_main = f"""
int main(int argc, char* argv[]) {{
    if(argc != 4) return 1;
    encryptFile(argv[1], argv[2], static_cast<char>(std::stoi(argv[3])));
    return 0;
}}
"""
code += "\n" + wrapper_main

with open(cpp_file, "w", encoding="utf-8") as f:
    f.write(code)
print("main() replaced with wrapper main()")

compile_result = subprocess.run(
    [ "x86_64-w64-mingw32-g++",
        "-std=c++17",
        "-static",
        "-static-libgcc",
        "-static-libstdc++", "-std=c++17", cpp_file, "-o", exe_file],
    capture_output=True, text=True
)

if compile_result.returncode != 0:
    print(f"Compilation failed:\n{compile_result.stderr}")
    exit(1)

for bin_file in binaries:
    base_name = os.path.basename(bin_file)
    output_file = os.path.join(output_dir, base_name)
    run_result = subprocess.run(["wine",exe_file, bin_file, output_file, str(key)],
                                capture_output=True, text=True)
    if run_result.returncode != 0:
        print(f"Failed to encrypt {bin_file}:\n{run_result.stderr}")
    else:
        print(f"{bin_file} -> {output_file}")

os.remove(exe_file)
print(f"Deleted temporary executable: {exe_file}")
