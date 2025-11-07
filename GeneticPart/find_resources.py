
import pefile
import sys
from pathlib import Path

def get_id_or_name(entry):
    try:
        if entry.name is not None:
            return str(entry.name)
    except Exception:
        pass
    return str(entry.id)

def walk_resources(pe):
    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        print("❌ No resource directory found.")
        return
    rsrc_section = None
    for s in pe.sections:
        name = s.Name.decode(errors="ignore").rstrip("\x00")
        if name.lower() == ".rsrc":
            rsrc_section = s
            break

    if rsrc_section:
        rsrc_start = rsrc_section.PointerToRawData
        print(f"[.rsrc] section: offset=0x{rsrc_start:08X} size={rsrc_section.SizeOfRawData} bytes  "
              f"[ {rsrc_start} , {rsrc_start + rsrc_section.SizeOfRawData} )\n")
    else:
        rsrc_start = None
        print("No .rsrc section found (proceeding without relative offsets)\n")

    entries = []

    for res_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        type_id = get_id_or_name(res_type)
        if not hasattr(res_type, "directory"):
            continue
        for res_name in res_type.directory.entries:
            name_id = get_id_or_name(res_name)
            if not hasattr(res_name, "directory"):
                continue
            for res_lang in res_name.directory.entries:
                data_struct = res_lang.data.struct
                data_rva = data_struct.OffsetToData
                data_size = data_struct.Size
                file_offset = pe.get_offset_from_rva(data_rva)
                rel = file_offset - rsrc_start if rsrc_start is not None else None
                path = f"/{type_id}/{name_id}/{res_lang.id}"
                entries.append((path, file_offset, data_size, rel))

    if not entries:
        print("⚠️  No individual resource entries discovered.")
        return

    entries.sort(key=lambda e: e[1])
    print("Resource tree (TYPE / NAME / LANG) with file offsets and sizes:\n")
    for path, offset, size, rel in entries:
        if rel is None:
            print(f"{path:25} offset=0x{offset:08X}  size={size:8d} bytes  [ {offset:8d} , {offset+size:8d} )")
        else:
            print(f"{path:25} offset=0x{offset:08X}  size={size:8d} bytes  [ {offset:8d} , {offset+size:8d} )  rel_to_rsrc={rel:8d} (0x{rel:06X})")
    print()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 list_resources_deep.py <pe_file>")
        sys.exit(1)

    pe_path = Path(sys.argv[1])
    if not pe_path.exists():
        print(f"❌ File not found: {pe_path}")
        sys.exit(1)

    pe = pefile.PE(str(pe_path))
    print(f"PE File: {pe_path}\n")
    walk_resources(pe)
