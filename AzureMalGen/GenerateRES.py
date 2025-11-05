import os

def create_resource_file(binary_path, output_folder):
    """Generate a .rc file for a given binary, embedding it as IDR_EXE1 101."""
    filename = os.path.basename(binary_path)
    name, _ = os.path.splitext(filename)

    rc_filename = os.path.join(output_folder, f"{name}.rc")

    # Escape backslashes for Windows paths
    escaped_path = binary_path.replace("\\", "\\\\")
    
    rc_content = f'#define IDR_EXE1 101\nIDR_EXE1 RCDATA "{escaped_path}"\n'

    with open(rc_filename, "w", encoding="utf-8") as f:
        f.write(rc_content)

    print(f"✅ Created resource file: {rc_filename}")


def generate_all_resources(input_folder, output_folder=None):
    """Generate .rc files for all binaries inside input_folder."""
    if output_folder is None:
        output_folder = input_folder  # default to same folder

    if not os.path.exists(output_folder):
        os.makedirs(output_folder)

    for file in os.listdir(input_folder):
        path = os.path.join(input_folder, file)
        if os.path.isfile(path):
            create_resource_file(path, output_folder)


if __name__ == "__main__":
    folder = "encrypted_binaries"
    generate_all_resources(folder)
