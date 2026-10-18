#!/usr/bin/env python3
"""Check shared GPU arithmetic as C++; no claim of GPU execution."""
from pathlib import Path
import random
import subprocess
import tempfile
root = Path(__file__).resolve().parents[1]
p = 21888242871839275222246405745257275088548364400416034343698204186575808495617
R = pow(2, 256, p)
rng = random.Random(2026)
edge = [0, 1, 2, p-1, p-2, 2**128, 2**253]
pairs = [(a,b) for a in edge for b in edge]
pairs += [(rng.randrange(p), rng.randrange(p)) for _ in range(2000)]
def limbs(v): return [(v >> (16*i)) & 65535 for i in range(16)]
text = '\n'.join(' '.join(map(str, limbs(a*R%p)+limbs(b*R%p))) for a,b in pairs)+'\n'
with tempfile.TemporaryDirectory() as tmp:
    exe = str(Path(tmp)/'test-field')
    subprocess.run(['c++','-std=c++17','-O2',str(root/'gpu/field_host_test.cpp'),'-o',exe],check=True)
    out = subprocess.run([exe],input=text,text=True,capture_output=True,check=True).stdout.splitlines()
    assert len(out)==len(pairs)
    for (a,b),line in zip(pairs,out):
        values=list(map(int,line.split()))
        assert len(values)==32 and all(0<=v<65536 for v in values)
        assert sum(v<<(16*i) for i,v in enumerate(values[:16]))==a*b*R%p
        assert sum(v<<(16*i) for i,v in enumerate(values[16:]))==(a+b)*R%p
print(f'Shared arithmetic host test: PASS ({len(pairs)} pairs; not a GPU test)')
