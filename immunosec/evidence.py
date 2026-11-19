"""Journal de preuves : « Bloquer d'abord, préserver la preuve ensuite ».

Journal en chaîne de hachage (append-only) : chaque entrée contient le hash de la
précédente, toute altération casse la chaîne. Des points de contrôle sont co-signés
par des témoins indépendants (ancrage pluriel, cf. registre de type Truebit dans le
livre blanc AITI), pour que l'attribution reste prouvable même si l'opérateur
est compromis.
"""
from __future__ import annotations

import hashlib
import json

from .mrna import sign


def _h(obj) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, ensure_ascii=False,
                                     separators=(",", ":")).encode()).hexdigest()


class EvidenceLog:
    def __init__(self):
        self.entries: list[dict] = []
        self.head = "0" * 64

    def append(self, ts: float, kind: str, data: dict) -> str:
        entry = {"i": len(self.entries), "ts": round(ts, 3), "kind": kind, "data": data, "prev": self.head}
        entry["hash"] = _h(entry)
        self.head = entry["hash"]
        self.entries.append(entry)
        return entry["hash"]

    def checkpoint(self, ts: float, witnesses: dict[str, bytes]) -> str:
        sigs = {w: sign(self.head.encode(), k) for w, k in witnesses.items()}
        return self.append(ts, "checkpoint", {"head": self.head, "witnesses": sigs})

    def verify(self) -> tuple[bool, int]:
        prev = "0" * 64
        for e in self.entries:
            body = {k: v for k, v in e.items() if k != "hash"}
            if e["prev"] != prev or _h(body) != e["hash"]:
                return False, e["i"]
            prev = e["hash"]
        return True, len(self.entries)

    def dump(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            for e in self.entries:
                f.write(json.dumps(e, ensure_ascii=False) + "\n")
