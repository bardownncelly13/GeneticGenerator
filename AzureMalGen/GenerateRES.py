import os

import os
import random

def create_resource_file(binary_path, output_folder, extragoodware=0):
    filename = os.path.basename(binary_path)
    name, _ = os.path.splitext(filename)

    rc_filename = os.path.join(output_folder, f"{name}.rc")
    escaped_path = binary_path.replace("\\", "\\\\")

    rc_lines = []

    if extragoodware > 0:
        goodware_folder = os.path.abspath("../GeneticPart/goodware/")
        goodware_files = [
            os.path.join(goodware_folder, f)
            for f in os.listdir(goodware_folder)
            if os.path.isfile(os.path.join(goodware_folder, f))
        ]

        if len(goodware_files) == 0:
            print("⚠ No goodware files found!")
        else:
            selected = random.sample(goodware_files, min(extragoodware, len(goodware_files)))

            resource_id = 102  # Start AFTER 101
            for gw_path in selected:
                gw_path_esc = gw_path.replace("\\", "\\\\")
                rc_lines.append(f"#define IDR_EXE{resource_id} {resource_id}\n")
                rc_lines.append(f'IDR_EXE{resource_id} RCDATA "{gw_path_esc}"\n')
                resource_id += 1

    rc_lines.append("#define IDR_EXE1 101\n")
    rc_lines.append(f'IDR_EXE1 RCDATA "{escaped_path}"\n')
    with open(rc_filename, "w", encoding="utf-8") as f:
        f.writelines(rc_lines)

    print(f"✅ Created resource file: {rc_filename}")



def generate_all_resources(input_folder, output_folder=None, extragoodware=0):
    """Generate .rc files for all binaries inside input_folder."""
    if output_folder is None:
        output_folder = input_folder 

    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    for file in os.listdir(input_folder):
        path = os.path.join(input_folder, file)
        if os.path.isfile(path):
            create_resource_file(path, output_folder,extragoodware)


if __name__ == "__main__":
    folder = "encrypted_binaries"
    generate_all_resources(folder)
