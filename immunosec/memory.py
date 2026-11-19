"""Cellules mémoire : réponse secondaire rapide face aux variants.

Quand un essaim réapparaît sous une forme mutée, l'affinité avec une cellule mémoire
permet de sauter la phase canari. Le nouveau transcrit cible la région CONSERVÉE
entre l'ancienne et la nouvelle souche (intersection des épitopes) : un vaccin
« large », plus résistant aux mutations suivantes.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional


def _as_set(v) -> set:
    if isinstance(v, dict):
        return {json.dumps(v, sort_keys=True)}
    return set(v) if isinstance(v, (list, tuple)) else {v}


def affinity(a: dict, b: dict) -> float:
    if a.get("kind") != b.get("kind"):
        return 0.0
    keys = set(a) | set(b)
    same = sum(1 for k in set(a) & set(b) if _as_set(a[k]) & _as_set(b[k]))
    return same / len(keys) if keys else 0.0


def _negatives(ep: dict) -> dict:
    return {k: v for k, v in ep.items() if isinstance(v, dict)}


def conserved(old: dict, new: dict) -> dict:
    """Région conservée entre deux souches + exclusions apprises (tolérance acquise)."""
    out = {k: new[k] for k in set(old) & set(new)
           if not isinstance(old[k], dict) and _as_set(old[k]) & _as_set(new[k])}
    out.update(_negatives(old))
    return dict(sorted(out.items()))


def polyvalent(old: dict, new: dict) -> dict:
    """Vaccin polyvalent : couvre l'ancienne ET la nouvelle souche (union des valeurs
    sur les clés communes), en conservant les exclusions apprises."""
    out = {}
    for k in set(old) & set(new):
        if isinstance(old[k], dict):
            continue
        vals = sorted(_as_set(old[k]) | _as_set(new[k]))
        out[k] = vals[0] if len(vals) == 1 else vals
    out.update(_negatives(old))
    return dict(sorted(out.items()))


@dataclass
class MemoryCell:
    lineage: str
    epitope: dict
    version: int
    created_at: float
    last_seen: float
    encounters: int = 1


class ImmuneMemory:
    def __init__(self, path: Optional[str] = None):
        self.path = Path(path) if path else None
        self.cells: dict[str, MemoryCell] = {}
        if self.path and self.path.exists():
            for d in json.loads(self.path.read_text()):
                self.cells[d["lineage"]] = MemoryCell(**d)

    def recall(self, epitope: dict, min_affinity: float = 0.5) -> Optional[tuple[MemoryCell, float]]:
        best = max(((c, affinity(c.epitope, epitope)) for c in self.cells.values()),
                   key=lambda x: x[1], default=None)
        return best if best and best[1] >= min_affinity else None

    def store(self, lineage: str, epitope: dict, version: int, now: float) -> None:
        c = self.cells.get(lineage)
        if c:
            c.epitope, c.version, c.last_seen, c.encounters = epitope, version, now, c.encounters + 1
        else:
            self.cells[lineage] = MemoryCell(lineage, epitope, version, now, now)
        self.save()

    def save(self) -> None:
        if self.path:
            self.path.write_text(json.dumps([asdict(c) for c in self.cells.values()],
                                            indent=2, ensure_ascii=False))
