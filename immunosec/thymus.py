"""Thymus et vérificateurs indépendants : sélection négative avant diffusion.

Dans le thymus, les lymphocytes qui reconnaissent le soi sont éliminés. Ici, un
transcrit est rejoué contre le corpus du soi : s'il touche trop de trafic légitime,
il est rejeté (risque auto-immun) ou rétrogradé en « challenge ».

Vérification plurielle (livre blanc AITI, annexe Truebit) : plusieurs vérificateurs
indépendants rejouent la sélection, chacun sur SA propre vue du soi, et ne signent
que si elle passe. Les nœuds exigent un quorum de signatures : aucun acteur unique
(ni un orchestrateur compromis) ne peut pousser seul un transcrit.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .mrna import Transcript, sign


@dataclass
class Selection:
    passed: bool
    fp_rate: float
    action: str
    reason: str


class Thymus:
    def __init__(self, sample: list, max_fp: float = 0.001):
        self.sample = sample
        self.max_fp = max_fp

    def select(self, t: Transcript) -> Selection:
        hits = sum(1 for e in self.sample if t.matches(e))
        fp = hits / max(1, len(self.sample))
        if hits == 0:
            return Selection(True, 0.0, t.action, "aucun contact avec le soi")
        if fp <= self.max_fp:
            return Selection(True, fp, "challenge", f"contact marginal avec le soi ({fp:.3%}) → rétrogradé")
        return Selection(False, fp, t.action, f"auto-immunité : {fp:.2%} du soi touché")


class Verifier:
    def __init__(self, vid: str, key: bytes, sample: list, max_fp: float = 0.001):
        self.vid = vid
        self.key = key
        self.thymus = Thymus(sample, max_fp)

    def endorse(self, t: Transcript) -> Optional[str]:
        if t.action == "revoke":
            return sign(t.canonical(), self.key)
        sel = self.thymus.select(t)
        if not sel.passed:
            return None
        return sign(t.canonical(), self.key)
