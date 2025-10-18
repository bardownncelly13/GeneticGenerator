from pathlib import Path
import lief

def GetBinaries(src_dir: str, extensions=["exe", "dll", "pe"]):
    """Load all binaries in memory using LIEF."""
    src = Path(src_dir)
    if not src.exists() or not src.is_dir():
        raise ValueError(f"{src_dir} is not a valid directory")

    ext_set = {e.lower().lstrip(".") for e in extensions}
    binaries = []

    for p in src.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix.lower().lstrip(".") not in ext_set:
            continue

        pe = lief.parse(str(p))
        raw = getattr(pe, "raw", None)
        if raw is None:
            raise RuntimeError(f"Could not get raw bytes for {p}")
        binaries.append(bytes(raw))

    return binaries


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Extract all binaries in memory using LIEF.")
    parser.add_argument("--src", "-s", required=True, help="Source directory containing binaries")
    parser.add_argument("--ext", "-e", nargs="*", default=["exe", "dll", "pe"], help="Extensions to include")
    args = parser.parse_args()

    bins = GetBinaries(args.src, args.ext)
    print(f"Loaded {len(bins)} binaries into memory.")
