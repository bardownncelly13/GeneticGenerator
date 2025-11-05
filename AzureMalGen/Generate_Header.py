import re
import argparse
import os

def generate_header(cpp_file):
    # Derive output folder and filenames
    base_name = os.path.splitext(os.path.basename(cpp_file))[0]  # e.g., "generated_script_20251103"
    folder = os.path.dirname(cpp_file) or "."                    # folder where cpp lives
    header_file = os.path.join(folder, f"{base_name}.h")         # same folder, .h extension
    guard_macro = f"{base_name.upper()}_H"                       # e.g., GENERATED_SCRIPT_20251103_H

    # Read the C++ source
    try:
        with open(cpp_file, "r") as f:
            code = f.read()
    except FileNotFoundError:
        print(f"❌ File not found: {cpp_file}")
        return

    # Find function definitions (simple regex for C++ types)
    pattern = r"\b(?:void|int|bool|float|double|std::string|char)\s+\w+\s*\([^)]*\)"
    functions = re.findall(pattern, code)

    if not functions:
        print(f"⚠️ No function definitions found in {cpp_file}.")
        return

    # Write header file in same directory
    with open(header_file, "w") as h:
        h.write(f"#ifndef {guard_macro}\n#define {guard_macro}\n\n#include <string>\n\n#include <Windows.h>\n\n")
        for func in functions:
            h.write(func + ";\n")
        h.write("\n#endif\n")

    print(f"✅ Generated header: {header_file} with guard {guard_macro}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Auto-generate a C++ header from a .cpp file.")
    parser.add_argument("--file", required=True, help="C++ source file to process")
    args = parser.parse_args()
    generate_header(args.file)
