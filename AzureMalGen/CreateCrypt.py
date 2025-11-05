import os
import re
import subprocess
from datetime import datetime
from azure.ai.projects import AIProjectClient
from azure.identity import DefaultAzureCredential
import random
import Generate_Header
def create_crypt():
    # ----------------------------
    # 1️⃣ Connect to Azure OpenAI
    # ----------------------------
    project = AIProjectClient(
        endpoint="https://ryancoffman-5902-resource.services.ai.azure.com/api/projects/ryancoffman-5902",
        credential=DefaultAzureCredential(),
    )
    models = project.get_openai_client(api_version="2024-10-21")
    encryption_types = [
    "XOR cipher",
    "One-time pad cipher",
    "bitwise rotation cipher",
    "byte shifting cipher",
    "bit inversion cipher",
    "nibble swapping cipher",
    "bitmasking cipher",
    "modulo addition cipher",
    "modulo subtraction cipher",
    "circular bit shift cipher",
    "byte-wise addition/subtraction cipher",
    "byte-wise multiplication/division cipher",
    "byte-wise negation cipher",
    "block XOR cipher",
    "bit swapping within bytes",
    "reverse byte order per block",
    "mirror bytes within block",
    "byte scrambling using key sequence",
    "affine byte transformation",
    "modular exponentiation per byte"
    ]

    # Pick a random encryption type
    chosen_type = random.choice(encryption_types)
    print(f"🎲 Using encryption type: {chosen_type}")

    # ----------------------------
    # 2️⃣ Ask GPT-4o for C++ code
    # ----------------------------
    response = models.chat.completions.create(
        model="gpt-4o",
        messages=[
            {
                "role": "system",
                "content": (
                    "You are a highly skilled software developer. "
                    "Always return *only* valid C++17 code wrapped in triple backticks. "
                    "Avoid any GUI libraries. "
                    "All outputs should be printed to the terminal (stdout)."
                    "If multiple correct implementations exist, prefer a less common or creative one — vary style, algorithmic approach, and naming."
                    "The functions should read and write files in **binary mode**. Avoid using text-only operations like std::isalpha or std::tolower."
                    "Prefer a simple per-byte transformation using the key (like XOR or byte shift) that works for arbitrary binary data."

                ),
            },
            {
                "role": "user",
                "content": f"Write a C++ {chosen_type} program that has exactly 2 functions void encryptFile(const std::string& inputFile, const std::string& outputFile, char key) and void decryptFile(BYTE* data, DWORD size, BYTE key) inclide a main function but dont put anthing in it assume #include <windows.h> ensure that you add any other imports needed "
            },
        ],
    )

    content = response.choices[0].message.content

    # ----------------------------
    # 3️⃣ Extract C++ code
    # ----------------------------
    match = re.search(r"```(?:cpp|c\+\+)?\n([\s\S]*?)```", content)
    if not match:
        raise ValueError("❌ Could not find C++ code block in model response!")

    code = match.group(1).strip()
    
    required_headers = {
    "std::string": "<string>",
    "std::ifstream": "<fstream>",
    "std::ofstream": "<fstream>",
    "std::unique_ptr": "<memory>",
    "std::make_unique": "<memory>",
    "std::vector": "<vector>",
    "std::cout": "<iostream>",
    "std::cerr": "<iostream>",
    "std::endl": "<iostream>",
    "std::reverse": "<algorithm>",
    "std::pow": "<cmath>",
    "std::exception": "<stdexcept>",
    "BYTE": "<windows.h>",
    "DWORD": "<windows.h>",
    "Sleep": "<windows.h>",
    # Add more as needed
    }

    # -----------------------------
    # Add missing headers automatically
    # -----------------------------
    # Detect existing headers in the code
    existing_headers = set(re.findall(r'#include\s+<([^>]+)>', code))
    existing_headers = set(h.lower() for h in re.findall(r'#include\s+<([^>]+)>', code))
    # Determine which headers need to be added
    headers_to_add = set()
    for keyword, header in required_headers.items():
        if re.search(r'\b' + re.escape(keyword) + r'\b', code):
            if header.strip("<>") not in existing_headers:
                headers_to_add.add(header)

    # Prepend missing headers
    if headers_to_add:
        headers_str = "\n".join(f"#include {h}" for h in sorted(headers_to_add))
        code = headers_str + "\n\n" + code

        # ----------------------------
        # 4️⃣ Prepare output folder
        # ----------------------------
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    nested_dir = f"generated/crypt"
    os.makedirs(nested_dir, exist_ok=True)

    cpp_path = os.path.join(nested_dir, f"generated_script_{timestamp}.cpp")
    exe_path = os.path.join(nested_dir, f"a_{timestamp}.out")

    # ----------------------------
    # 5️⃣ Save C++ code and generate header
    # ----------------------------

    with open(cpp_path, "w", encoding="utf-8") as f:
        f.write("// Generated by Azure GPT-4o\n\n")
        f.write(code)
    print(f"💾 Saved C++ code to: {cpp_path}")
    Generate_Header.generate_header(cpp_path)

    # ----------------------------
    # 6️⃣ Compile and run
    # ----------------------------
    print("🧱 Compiling with g++...")
    compile_result = subprocess.run(["x86_64-w64-mingw32-g++", "-std=c++17", cpp_path, "-o", exe_path],
                                    capture_output=True, text=True)

    if compile_result.returncode != 0:
        print("❌ Compilation failed:\n", compile_result.stderr)
        if os.path.exists(exe_path):
            os.remove(exe_path)
            print(f"🗑️ Deleted failed compiled binary: {exe_path}")
    
        header_path = os.path.splitext(cpp_path)[0] + ".h"  # assuming Generate_Header created a .h with same basename
        if os.path.exists(header_path):
            os.remove(header_path)
            print(f"🗑️ Deleted failed header file: {header_path}")
    else: #can run but this just makes sure it compiles
        # print("🚀 Running compiled C++ binary...\n")
        # result = subprocess.run([exe_path], capture_output=True, text=True)
        # print("📤 STDOUT:\n", result.stdout)
        # if result.stderr:
        #     print("⚠️ STDERR:\n", result.stderr)
        os.remove(exe_path)
    print("\n✅ Completed run at:", timestamp)
