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


TARGET_SIZE = int(4.9 * 1024 * 1024)    
MAX_APPEND_CHUNK = 1000 * 1024           
MIN_APPEND_CHUNK = 1024               
MUTATION_BYTE_COUNT = 16                
TOURNAMENT_K = 3

def make_mask(length, locked_ranges):
    mask = [True] * length
    for start, end in locked_ranges:
        for i in range(start, min(end, length)):
            mask[i] = False
    return mask

def get_genes(path: Path) -> bytes:                                    
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

def list_exes(folder: Path) -> List[Path]:                             
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

def _read_random_chunk(path: Path, max_bytes: int = MAX_APPEND_CHUNK) -> bytes: 
    size = path.stat().st_size
    if size == 0:
        return b""
    chunk_size = random.randint(MIN_APPEND_CHUNK, min(max_bytes, size))
    if size <= chunk_size:
        with path.open("rb") as f:
            return f.read()
    start = random.randint(0, size - chunk_size)
    with path.open("rb") as f:
        f.seek(start)
        return f.read(chunk_size)
def fitness(chromosome: bytes, original: bytes = None) -> float:
    if not chromosome:
        return 0.0

    total = len(chromosome)
    counts = Counter(chromosome)

    entropy = -sum((count / total) * math.log2(count / total) for count in counts.values())

    normalized_entropy = entropy / 8.0
    return 1.0 - normalized_entropy

def tournament_selection(pop: List[bytes], fit_scores: List[float], k: int = TOURNAMENT_K) -> bytes: 
    """Select one individual using tournament selection (k competitors)."""
    assert len(pop) == len(fit_scores)
    competitors = random.sample(list(zip(pop, fit_scores)), k)
    return max(competitors, key=lambda x: x[1])[0]

def crossover(p1: bytes, p2: bytes, mask: List[bool]) -> Tuple[bytes, bytes]: 

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

def mutate(chrom: bytes, mask: List[bool], goodware_files: List[Path]) -> bytes: 
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


def generate_population(count: int, base_binary: bytes, goodware_path: Path) -> List[bytes]:

    goodware_files = list_exes(goodware_path)
    if not goodware_files:
        raise ValueError(f"No .exe files found in {goodware_path}")

    population = []
    for i in range(count):
        data = bytearray(base_binary)
  
        if len(data) > TARGET_SIZE:
            data = data[:TARGET_SIZE]

        while len(data) < TARGET_SIZE:
            gw = random.choice(goodware_files)
            chunk = _read_random_chunk(gw)
            if not chunk:
                chunk = bytes([random.randint(0,255) for _ in range(1024)])
            data += chunk
            if len(data) > TARGET_SIZE + MAX_APPEND_CHUNK:
                break
        population.append(bytes(data[:TARGET_SIZE]))
    return population

def genetic_algo(popsize: int,
                 generations: int,
                 exe_path: Path,
                 goodware_path: Path,
                 save_best_to: Optional[Path] = None):

    base = get_genes(exe_path)
    goodware_files = list_exes(goodware_path)

    if not goodware_files:
        raise ValueError(f"No .exe files found in {goodware_path}")

    population = generate_population(popsize, base, goodware_path)
    #####
    ###!!!! important 
    #####
    IMMUTABLE_RANGES = mark_reasorces_mask.getmask(exe_path,[102])  # select reasorces that can be edited
    mask = make_mask(TARGET_SIZE, IMMUTABLE_RANGES)

    for gen in range(generations):
        fitnesses = [fitness(ind) for ind in population]

        new_pop: List[bytes] = []
        for _ in range(popsize // 2):
            p1 = tournament_selection(population, fitnesses)
            p2 = tournament_selection(population, fitnesses)
            c1, c2 = crossover(p1, p2, mask)
            c1 = mutate(c1, mask, goodware_files)
            c2 = mutate(c2, mask, goodware_files)
            new_pop.extend([c1, c2])

        population = new_pop
        best = max(population, key=fitness)
        best_score = fitness(best)
        print(f"Gen {gen:3d}: Best fitness = {best_score:.6f}")

    best_overall = max(population, key=fitness)
    if save_best_to:
        with save_best_to.open("wb") as f:
            f.write(best_overall)
        print(f"[i] Best individual written raw to {save_best_to} (do not execute)")

    return best_overall

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
