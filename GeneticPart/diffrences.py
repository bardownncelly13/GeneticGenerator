from pathlib import Path
from typing import List, Tuple

def diff_ranges(file1: Path, file2: Path, gap: int = 0) -> List[Tuple[int, int]]:
    """
    Return a list of (start, end) tuples where file1 and file2 differ.
    - gap: merge differences that are within `gap` bytes of each other.
    Compares only up to the length of the shorter file, then marks remaining bytes in the longer file as different.
    """
    with file1.open("rb") as f1, file2.open("rb") as f2:
        data1 = f1.read()
        data2 = f2.read()

    min_len = min(len(data1), len(data2))
    max_len = max(len(data1), len(data2))

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

    # Add remaining bytes from the longer file as a final diff
    if len(data1) != len(data2):
        raw_diffs.append((min_len, max_len))

    # Merge ranges that are within `gap` bytes
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

# Example usage
f1 = Path("../AzureMalGen/generated/finalexes/adig.exe")
f2 = Path("best_individual.bin")
diffs = diff_ranges(f1, f2, gap=1000)
print("Byte ranges that differ:")
for start, end in diffs:
    print(f"[{start}, {end})")
