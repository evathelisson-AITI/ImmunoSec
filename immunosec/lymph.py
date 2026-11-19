"""Ganglion lymphatique : corrélation globale et présentation de l'antigène.

Reçoit les événements suspects de TOUS les nœuds. Un essaim se trahit par ce qu'il
ne peut pas faire varier à bas coût : son outillage (empreinte TLS, ordre des
en-têtes, schéma de noms de fichiers d'un canal caché...). C'est l'équivalent de la
protéine Spike : la partie conservée que le vaccin va cibler.

Critère : une valeur rare dans le soi, partagée par >= min_sources sources
distinctes sur >= min_nodes nœuds dans la fenêtre. On en extrait l'épitope :
la conjonction des caractéristiques portées par >= min_support du cluster.
"""
from __future__ import annotations

from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from typing import Callable

from .events import Event
from .self_profile import SelfProfile
from .sensors import NON_DISCRIMINANT


@dataclass
class Antigen:
    epitope: dict
    support: dict
    sources: int
    nodes: int
    events: int
    first_seen: float
    detected_at: float
    seed: tuple
    owner: str | None = None   # établissement détecteur (mode local) ; None = vue globale


class LymphNode:
    def __init__(self, profile: SelfProfile, window: float = 60.0, min_sources: int = 25,
                 min_nodes: int = 3, max_self_freq: float = 0.01, min_support: float = 0.8,
                 per_node_quota: int = 4000, owner: str | None = None, primed_min_sources: int = 8):
        self.profile = profile
        self.window = window
        self.min_sources = min_sources
        self.min_nodes = min_nodes
        self.max_self_freq = max_self_freq
        self.min_support = min_support
        self.buffer: deque[Event] = deque()
        # Contre-pression : un nœud inondé ne peut pas saturer le ganglion
        # (attaque par saturation du processus de réparation lui-même).
        self.per_node_quota = per_node_quota
        self.owner = owner
        # Mémoire immunitaire : une souche proche d'une souche connue est reconnue à
        # plus faible « dose » (moins de sources), comme les lymphocytes mémoire.
        self.primed_min_sources = primed_min_sources
        self.per_node: Counter = Counter()
        self.dropped = 0

    def present(self, ev: Event) -> None:
        if self.per_node[ev.node] >= self.per_node_quota:
            self.dropped += 1
            return
        self.per_node[ev.node] += 1
        self.buffer.append(ev)

    def scan(self, now: float, is_covered: Callable[[Event], bool],
             primed: Callable[[dict], bool] | None = None) -> list[Antigen]:
        while self.buffer and self.buffer[0].ts < now - self.window:
            old = self.buffer.popleft()
            self.per_node[old.node] -= 1
        events = [e for e in self.buffer if not is_covered(e)]

        index: dict[tuple, list[Event]] = defaultdict(list)
        for e in events:
            for f, v in e.features.items():
                index[(f, v)].append(e)

        candidates = []
        for key, evs in index.items():
            # Les caractéristiques volontairement diversifiées par l'attaquant (ASN)
            # ne servent pas de graine : elles agrègent des populations sans rapport.
            if key[0] in NON_DISCRIMINANT or self.profile.freq(*key) > self.max_self_freq:
                continue
            srcs = {e.src for e in evs}
            nodes = {e.node for e in evs}
            floor = self.primed_min_sources if primed else self.min_sources
            if len(srcs) >= floor and len(nodes) >= min(self.min_nodes, len(nodes) if primed else self.min_nodes):
                candidates.append((key, evs, len(srcs)))
        candidates.sort(key=lambda c: c[2], reverse=True)

        antigens, claimed = [], set()
        for key, evs, _ in candidates:
            cluster = [e for e in evs if id(e) not in claimed]
            srcs = {e.src for e in cluster}
            if len(srcs) < (self.primed_min_sources if primed else self.min_sources):
                continue
            epitope, support = self._extract(cluster)
            n_nodes = len({e.node for e in cluster})
            if len(srcs) < self.min_sources or n_nodes < self.min_nodes:
                if not (primed and primed(epitope)):
                    continue   # sous le seuil normal et aucune mémoire : pas encore d'antigène
            strong = [f for f in epitope if f not in NON_DISCRIMINANT]
            if len(strong) < 2 or not any(self.profile.freq(f, v) <= self.max_self_freq
                                          for f, v in epitope.items() if f not in NON_DISCRIMINANT):
                continue   # cluster dilué : on ne le « réclame » pas, la graine suivante peut mieux faire
            claimed.update(id(e) for e in cluster)
            antigens.append(Antigen(epitope, support, len(srcs), len({e.node for e in cluster}),
                                    len(cluster), min(e.ts for e in cluster), now, key, self.owner))
        return antigens

    def _extract(self, cluster: list[Event]) -> tuple[dict, dict]:
        epitope, support = {}, {}
        keys = set().union(*(e.features.keys() for e in cluster))
        for f in sorted(keys):
            v, c = Counter(e.get(f) for e in cluster).most_common(1)[0]
            s = c / len(cluster)
            if s >= self.min_support and v != "∅":
                epitope[f], support[f] = v, round(s, 3)
        return epitope, support
