"""Le « soi » : le profil du trafic légitime.

Il sert à deux choses, comme dans un organisme :
  * mesurer la rareté (un motif absent du soi est suspect) ;
  * tester la tolérance (un vaccin qui attaque le soi = maladie auto-immune).

Il n'apprend QUE sur du trafic validé (phase d'entraînement ou trafic certifié) :
apprendre en continu sur le trafic brut laisserait un essaim lent devenir « soi ».
"""
from __future__ import annotations

import random
from collections import Counter, defaultdict

from .events import Event


class SelfProfile:
    def __init__(self, sample_size: int = 5000, seed: int = 0):
        self.counts: dict[str, Counter] = defaultdict(Counter)
        self.total = 0
        self.sample: list[Event] = []          # corpus du soi (échantillonnage réservoir)
        self.sample_size = sample_size
        self.known_sources: set[str] = set()
        self._rng = random.Random(seed)

    def learn(self, ev: Event) -> None:
        self.total += 1
        for f, v in ev.features.items():
            self.counts[f][v] += 1
        self.known_sources.add(ev.src)
        if len(self.sample) < self.sample_size:
            self.sample.append(ev)
        else:
            j = self._rng.randrange(self.total)
            if j < self.sample_size:
                self.sample[j] = ev

    def freq(self, feature: str, value: str) -> float:
        return self.counts[feature][value] / self.total if self.total else 0.0

    def subsample(self, n: int, seed: int) -> list[Event]:
        rng = random.Random(seed)
        return rng.sample(self.sample, min(n, len(self.sample)))
