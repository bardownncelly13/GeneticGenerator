from pathlib import Path
from typing import List, Tuple, Optional
import pefile

def diff_ranges(file1: Path, file2: Path, gap: int = 0) -> List[Tuple[int, int]]:
    with file1.open("rb") as f1, file2.open("rb") as f2:
        data1 = f1.read()
        data2 = f2.read()

    min_len = min(len(data1), len(data2))
    max_len = max(len(data1), len(data2))

    print(f"Smaller binary length: {min_len} bytes")

    raw_diffs = []
    in_diff = False
    start = 0
    for i in range(min_len):
        if data1[i] != data2[i]:
            if not in_diff:
                start = i
                in_diff = True
        else:
            if in_diff:
                raw_diffs.append((start, i))
                in_diff = False
    if in_diff:
        raw_diffs.append((start, min_len))

    if len(data1) != len(data2):
        raw_diffs.append((min_len, max_len))

    if gap > 0 and raw_diffs:
        merged = [raw_diffs[0]]
        for s, e in raw_diffs[1:]:
            last_s, last_e = merged[-1]
            if s <= last_e + gap:
                merged[-1] = (last_s, max(last_e, e))
            else:
                merged.append((s, e))
        return merged
    else:
        return raw_diffs


def get_resource_range(pe_path: Path, target_id: int) -> Optional[Tuple[int, int]]:
    pe = pefile.PE(pe_path.as_posix())
    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        print("No resources found.")
        return None

    for res_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        for res_id in getattr(res_type, "directory", []).entries:
            if res_id.id == target_id:
                for res_lang in getattr(res_id, "directory", []).entries:
                    data_rva = res_lang.data.struct.OffsetToData
                    size = res_lang.data.struct.Size
                    offset = pe.get_offset_from_rva(data_rva)
                    print(f"Resource {target_id} range: [{offset}, {offset + size}) (size={size} bytes)")
                    return (offset, offset + size)
    print(f"Resource {target_id} not found.")
    return None


def classify_diff(diff: Tuple[int, int], res_range: Optional[Tuple[int, int]], shorter_len: int) -> str:
    start, end = diff
    if start >= shorter_len:
        return "after the end of the shorter file"
    if not res_range:
        return "outside the range"
    res_start, res_end = res_range
    if end <= res_start or start >= res_end:
        return "outside the range"
    return "in resource 102 range"


f1 = Path("../AzureMalGen/generated/finalexes/1.exe")
f2 = Path("best.exe")

diffs = diff_ranges(f1, f2, gap=1000)
res_range = get_resource_range(f2, 102)

print("\nByte ranges that differ:")
for start, end in diffs:
    status = classify_diff((start, end), res_range, min(f1.stat().st_size, f2.stat().st_size))
    print(f"[{start}, {end}) -> {status}")
