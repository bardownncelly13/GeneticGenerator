import subprocess
from pathlib import Path
import shutil
import glob

WINDRES = "x86_64-w64-mingw32-windres"
GPP = "x86_64-w64-mingw32-g++"

LINK_FLAGS = [
    "-static", "-static-libgcc", "-static-libstdc++",
    "-lgdiplus", "-luser32", "-lgdi32", "-lole32", "-luuid", "-lcrypt32",
    "-mwindows", "-municode"
]


def _ensure_tools():
    """Verify MinGW tools exist in PATH."""
    for t in (WINDRES, GPP):
        if shutil.which(t) is None:
            print(f" Tool not found: {t}")
            return False
    return True


def build_one(cpp_path: Path, rc_path: Path, out_dir: Path) -> bool:
    """Compile a single .cpp + .rc pair into an .exe."""
    name = cpp_path.stem
    obj_path = out_dir / f"{name}.o"
    exe_path = out_dir / f"{name}.exe"

    print(f"[windres] {rc_path.name} → {obj_path.name}")
    res_cmd = [WINDRES, str(rc_path), "-O", "coff", "-o", str(obj_path)]
    try:
        subprocess.run(res_cmd, check=True)
    except subprocess.CalledProcessError:
        print(f" Failed to compile resource for {name}")
        return False

    print(f"[g++] {cpp_path.name} + {obj_path.name} → {exe_path.name}")
    gpp_cmd = [GPP, str(cpp_path), str(obj_path)] + LINK_FLAGS + ["-o", str(exe_path)]
    try:
        subprocess.run(gpp_cmd, check=True)
        print(f"Built {exe_path}")
        return True
    except subprocess.CalledProcessError:
        print(f" Build failed for {name}")
        return False


def build_all(cpp_dir: str, rc_dir: str, out_dir: str):
    """
    Build all .cpp files in cpp_dir that have matching .rc files in rc_dir.
    Output .exe files go into out_dir.
    """
    cpp_dir = Path(cpp_dir)
    rc_dir = Path(rc_dir)
    out_dir = Path(out_dir)
    out_dir.mkdir(exist_ok=True)

    if not _ensure_tools():
        return

    cpp_files = sorted(cpp_dir.glob("*.cpp"))
    if not cpp_files:
        print(" No .cpp files found.")
        return

    fails = 0
    for cpp in cpp_files:
        rc_path = rc_dir / f"{cpp.stem}.rc"
        if not rc_path.exists():
            print(f" Missing resource for {cpp.stem}: {rc_path}")
            fails += 1
            continue

        ok = build_one(cpp, rc_path, out_dir)
        if not ok:
            fails += 1
    for obj in out_dir.glob("*.o"):
        try:
            obj.unlink()
            print(f" Deleted {obj.name}")
        except Exception as e:
            print(f" Could not delete {obj.name}: {e}")
    if fails:
        print(f"\n Completed with {fails} failure(s).")
    else:
        print("\n All builds succeeded!")


if __name__ == "__main__":
    import sys
    if len(sys.argv) == 4:
        build_all(sys.argv[1], sys.argv[2], sys.argv[3])
    else:
        print("Usage: python mingw_builder.py <cpp_dir> <rc_dir> <out_dir>")
