
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

def collect_resource_ranges(pe):
    resources = []
    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        return resources

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
                start = file_offset
                end = file_offset + data_size
                resources.append((type_id, name_id, res_lang.id, start, end))
    return resources

def invert_ranges(file_size, zero_ranges):
    """Given total size and excluded ranges, return the complement as (start, end) tuples."""
    zero_ranges.sort(key=lambda r: r[0])
    one_ranges = []
    last_end = 0
    for start, end in zero_ranges:
        if start > last_end:
            one_ranges.append((last_end, start))
        last_end = max(last_end, end)
    if last_end < file_size:
        one_ranges.append((last_end, file_size))
    return one_ranges

def build_one_ranges(pe_path, zero_ids):
    """Internal: computes excluded (zero) and included (one) ranges."""
    pe = pefile.PE(str(pe_path))
    file_size = pe.__data__.__len__()
    resources = collect_resource_ranges(pe)
    zero_ranges = []
    for (rtype, name, lang, start, end) in resources:
        try:
            name_int = int(name)
        except ValueError:
            continue
        if name_int in zero_ids:
            zero_ranges.append((start, end))
    return invert_ranges(file_size, zero_ranges)

def getmask(pe_path: str, exclude_ids: list[int]) -> list[tuple[int, int]]:
    """
    Return a list of (start, end) tuples representing file regions
    NOT belonging to the given resource IDs.
    """
    pe_path = Path(pe_path)
    if not pe_path.exists():
        raise FileNotFoundError(f"PE file not found: {pe_path}")
    return build_one_ranges(pe_path, exclude_ids)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit(1)

    pe_path = Path(sys.argv[1])
    ids = [int(x) for x in sys.argv[2:]]
    one_ranges = getmask(pe_path, ids)

    print("\n Ranges representing bytes marked as 1:")
    print(one_ranges)
