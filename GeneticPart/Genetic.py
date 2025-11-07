import os
import random
import struct
from pathlib import Path
from typing import List, Tuple, Optional
import hashlib
import math
from collections import Counter
import math
from collections import Counter
import mark_reasorces_mask
try:
    import lief
except Exception:
    lief = None
    # We'll fallback to raw file reads if lief isn't available

# ---------- Parameters ----------
TARGET_SIZE = int(4.9 * 1024 * 1024)     # 4.9 MB individuals
MAX_APPEND_CHUNK = 1000 * 1024            # 1MB
MIN_APPEND_CHUNK = 1024                 # 1 KB min chunk
MUTATION_BYTE_COUNT = 16                # mutate up to this many bytes per mutate call
TOURNAMENT_K = 3

# ---------- Utilities ----------
def make_mask(length, locked_ranges): # this will lock the ranges that dont want to be edited
    mask = [True] * length
    for start, end in locked_ranges:
        for i in range(start, min(end, length)):
            mask[i] = False
    return mask

def get_genes(path: Path) -> bytes:                                    #get origonal Path file that we start with and append to
    """Return raw bytes for a PE. Use lief if available for consistent 'raw' view."""
    if lief is not None:
        try:
            pe = lief.parse(str(path))
            raw = getattr(pe, "raw", None)
            if raw is not None:
                return bytes(raw)
        except Exception:
        
            pass

    with path.open("rb") as f:
        return f.read()

def list_exes(folder: Path) -> List[Path]:                              #this is used to get all the goodware files 
    """Return list of .exe paths under folder (non-recursive)."""
    if not folder.exists():
        return []
    exes = []
    with os.scandir(folder) as it:
        for entry in it:
            if not entry.is_file():
                continue
            if entry.name.lower().endswith(".exe"):
                exes.append(Path(entry.path))
    return exes

def _read_random_chunk(path: Path, max_bytes: int = MAX_APPEND_CHUNK) -> bytes: #gets a random chunk of goodware to use for mutations
    size = path.stat().st_size
    if size == 0:
        return b""
    chunk_size = random.randint(MIN_APPEND_CHUNK, min(max_bytes, size))
    # choose a random offset so we don't always read header
    if size <= chunk_size:
        with path.open("rb") as f:
            return f.read()
    start = random.randint(0, size - chunk_size)
    with path.open("rb") as f:
        f.seek(start)
        return f.read(chunk_size)

# ---------- GA building blocks ----------
def fitness(chromosome: bytes, original: bytes = None) -> float:
    if not chromosome:
        return 0.0

    total = len(chromosome)
    counts = Counter(chromosome)

    # Shannon entropy in bits
    entropy = -sum((count / total) * math.log2(count / total) for count in counts.values())

    # Normalize: max entropy for 8-bit = 8 bits
    normalized_entropy = entropy / 8.0

    # Invert: low entropy is high fitness
    return 1.0 - normalized_entropy

def tournament_selection(pop: List[bytes], fit_scores: List[float], k: int = TOURNAMENT_K) -> bytes: #picks the best fitted
    """Select one individual using tournament selection (k competitors)."""
    assert len(pop) == len(fit_scores)
    competitors = random.sample(list(zip(pop, fit_scores)), k)
    return max(competitors, key=lambda x: x[1])[0]

def crossover(p1: bytes, p2: bytes, mask: List[bool]) -> Tuple[bytes, bytes]: # vary for the next generation

    """Perform one-point crossover, respecting mask (False = locked/immutable)."""
    L = min(len(p1), len(p2))
    p1, p2 = p1[:L], p2[:L]

    if L < 2:
        return p1, p2

    point = random.randint(1, L - 1)

    c1 = bytearray(p1)
    c2 = bytearray(p2)

    for i in range(point, L):
        if mask[i]:
            c1[i], c2[i] = p2[i], p1[i]

    return bytes(c1), bytes(c2)

def mutate(chrom: bytes, mask: List[bool], goodware_files: List[Path]) -> bytes: #adding random goodware in unmutated areas
    c = bytearray(chrom)
    length = len(c)
    if goodware_files and random.random() < 0.3:
        gw = random.choice(goodware_files)
        chunk = _read_random_chunk(gw, max_bytes=MAX_APPEND_CHUNK)
        if chunk:
            mutable_indices = [i for i in range(length) if mask[i]]
            if mutable_indices:
                start = random.choice(mutable_indices)
                end = min(length, start + len(chunk))
                for i in range(start, end):
                    if mask[i]:
                        c[i] = chunk[i - start]
    return bytes(c)

# ---------- Population generation ----------
def generate_population(count: int, base_binary: bytes, goodware_path: Path) -> List[bytes]: #makes a population by taking a base exe and appending random goodware to it
    """
    Create `count` individuals.
    Each individual = base_binary truncated/padded, then appended with random chunks from goodware files
    until TARGET_SIZE is reached. Final truncate to TARGET_SIZE.
    """
    goodware_files = list_exes(goodware_path)
    if not goodware_files:
        raise ValueError(f"No .exe files found in {goodware_path}")

    population = []
    for i in range(count):
        # Start with base
        data = bytearray(base_binary)
        # If larger than target, truncate
        if len(data) > TARGET_SIZE:
            data = data[:TARGET_SIZE]
        # Append random chunks until we reach or slightly exceed target
        while len(data) < TARGET_SIZE:
            gw = random.choice(goodware_files)
            chunk = _read_random_chunk(gw)
            if not chunk:
                # read fallback: small sample of zeros if source empty
                chunk = bytes([random.randint(0,255) for _ in range(1024)])
            data += chunk
            # safety: avoid infinite loops
            if len(data) > TARGET_SIZE + MAX_APPEND_CHUNK:
                break
        # truncate to exact target size
        population.append(bytes(data[:TARGET_SIZE]))
    return population

# ---------- Main GA ----------
def genetic_algo(popsize: int,
                 generations: int,
                 exe_path: Path,
                 goodware_path: Path,
                 save_best_to: Optional[Path] = None):
    """
    Run GA. Returns the best individual's bytes.
    - popsize: number of individuals (should be even)
    - generations: number of generations
    - exe_path: Path to base exe (seed)
    - goodware_path: directory containing goodware exes to use as chunks
    - save_best_to: if provided, write best individual's bytes to this path (non-executable raw file)
    """
    base = get_genes(exe_path)
    goodware_files = list_exes(goodware_path)

    if not goodware_files:
        raise ValueError(f"No .exe files found in {goodware_path}")

    population = generate_population(popsize, base, goodware_path)

    # Lock the first 512 bytes (headers)
    IMMUTABLE_RANGES = mark_reasorces_mask.getmask(exe_path,[102])
    mask = make_mask(TARGET_SIZE, IMMUTABLE_RANGES)

    for gen in range(generations):
        fitnesses = [fitness(ind) for ind in population]

        new_pop: List[bytes] = []
        for _ in range(popsize // 2):
            p1 = tournament_selection(population, fitnesses)
            p2 = tournament_selection(population, fitnesses)
            c1, c2 = crossover(p1, p2, mask)
            # use precomputed goodware_files and mask
            c1 = mutate(c1, mask, goodware_files)
            c2 = mutate(c2, mask, goodware_files)
            new_pop.extend([c1, c2])

        population = new_pop
        best = max(population, key=fitness)
        best_score = fitness(best)
        print(f"Gen {gen:3d}: Best fitness = {best_score:.6f}")

    best_overall = max(population, key=fitness)
    if save_best_to:
        # write raw bytes; DO NOT mark as executable or attempt to run
        with save_best_to.open("wb") as f:
            f.write(best_overall)
        print(f"[i] Best individual written raw to {save_best_to} (do not execute)")

    return best_overall


# ---------- Example usage ----------
if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser()
    p.add_argument("--base", required=True, help="Base EXE to seed population")
    p.add_argument("--goodware", required=True, help="Directory containing benign EXEs to sample chunks from")
    p.add_argument("--pop", type=int, default=10, help="Population size (even)")
    p.add_argument("--gens", type=int, default=20, help="Generations")
    p.add_argument("--out", default=None, help="Optional output file to save best individual (raw bytes)")
    args = p.parse_args()

    base_path = Path(args.base)
    goodware_dir = Path(args.goodware)
    out_path = Path(args.out) if args.out else None

    best = genetic_algo(popsize=args.pop,
                        generations=args.gens,
                        exe_path=base_path,
                        goodware_path=goodware_dir,
                        save_best_to=out_path)

    print("Done. Best fitness:", fitness(best))
