"""Défense dynamique : exploiter la DYNAMIQUE de l'essaim plutôt que ses signatures.

La force d'un essaim est aussi sa faiblesse : il mutualise sa reconnaissance. Ce qu'un
membre découvre, tous l'exploitent. Une découverte empoisonnée contamine donc tout
l'essaim d'un coup.

1. Déception à cible mouvante (Deception)
   Des leurres plausibles (« /.env », « /api/v1/backup »…) sont exposés et TOURNENT à
   chaque époque. Aucun utilisateur légitime ne les connaît : y toucher est un signal
   de dommage quasi sans faux positif. Après rotation, la carte de l'essaim est
   périmée, et chaque accès à un leurre retiré trahit qu'on agit sur un renseignement
   partagé.
   Effet clé : une exploitation qui RÉUSSIT (statut 200) n'émet aucun signal de
   dommage. Sans déception, elle est invisible ; avec, ses auteurs ont déjà été marqués
   pendant la reconnaissance.

2. Routeur kill chain (KillChainRouter)
   Chaque événement suspect est rattaché à une phase de la kill chain, et chaque
   phase est traitée par le « modèle » le moins cher qui suffit :
     T0 règle traduite (ribosome, leurre, bail)        ~µs, coût ≈ 0
     T1 capteur statistique local                       ~ms
     T2 corrélateur multi-nœuds (ganglion)              ~s
     T3 agent analyste IA (LLM), sous bail en LECTURE   ~min, coûteux
   T3 n'est sollicité que sur ambiguïté à fort enjeu (thymus en échec, effet
   indésirable, aucun transcrit sûr). Il n'a aucun droit d'écriture : il propose un
   transcrit qui repasse par le thymus et le quorum comme les autres.
"""
from __future__ import annotations

import random
from collections import Counter

DECOY_POOL = [f"/{p}" for p in (
    ".env", ".git/config", "backup.zip", "db.sql", "admin/login", "api/v1/backup", "api/v1/debug",
    "api/internal/users", "wp-admin/setup.php", "phpinfo.php", "server-status", "actuator/env",
    "api/v2/admin/export", "config.json", "api/keys", "graphql/console", "jenkins/script",
    "api/v1/tokens", "console", "storage/logs", "api/legacy/upload", "cgi-bin/status",
    "api/v1/migrate", "internal/metrics", "api/debug/pprof", "uploads/shell", "api/v1/sync",
    "old/admin", "test/api", "api/v0/export", "_profiler", "api/v1/import", "dump.tar.gz",
    "api/v1/impersonate", "api/sso/bypass", "telescope/requests", "api/v1/reset", "staging/api",
    "api/batch", "api/v1/admin/keys")]


class Deception:
    def __init__(self, seed: int = 0, active: int = 12, epoch: float = 120.0):
        self.rng = random.Random(f"deception-{seed}")
        self.n_active, self.epoch = active, epoch
        self.active: set[str] = set()
        self.retired: set[str] = set()
        self._epoch_id = -1
        self.hits = Counter()

    def rotate(self, now: float) -> bool:
        e = int(now // self.epoch)
        if e == self._epoch_id:
            return False
        self._epoch_id = e
        self.retired |= self.active
        self.active = set(self.rng.sample(DECOY_POOL, self.n_active))
        self.retired -= self.active
        return True

    def trap(self, ev) -> str | None:
        path = ev.get("path")
        if path in self.active:
            self.hits["actif"] += 1
            return "leurre actif"
        if path in self.retired:
            self.hits["périmé"] += 1
            return "leurre périmé (renseignement partagé par l'essaim)"
        return None


PHASES = ("reconnaissance", "accès initial", "exploitation", "commande & contrôle",
          "mouvement latéral", "exfiltration", "indéterminée")

TIERS = {"T0": {"name": "règle traduite / leurre / bail", "latency_s": 1e-5, "cost": 0.0001},
         "T1": {"name": "capteur statistique local", "latency_s": 1e-3, "cost": 0.001},
         "T2": {"name": "corrélateur multi-nœuds", "latency_s": 5.0, "cost": 0.01},
         "T3": {"name": "agent analyste IA (lecture seule, sous bail)", "latency_s": 90.0, "cost": 50.0}}


class KillChainRouter:
    """Comptabilise l'allocation phase → modèle et le coût total, comparé à une
    architecture naïve qui soumettrait chaque événement suspect à un LLM."""

    def __init__(self):
        self.by_phase: Counter = Counter()
        self.by_tier: Counter = Counter()
        self.matrix: Counter = Counter()
        self.escalations: list[dict] = []

    @staticmethod
    def phase(ev, trap: str | None = None, gateway_reason: str | None = None) -> str:
        if trap:
            return "reconnaissance"
        if ev.kind == "agent":
            if gateway_reason and "ODD" in gateway_reason or ev.get("action") == "net.resolve":
                return "commande & contrôle" if "dns" in ev.get("dest") else "exfiltration"
            if ev.get("action") == "cache.write":
                return "mouvement latéral"
            return "indéterminée"
        if ev.status == 404:
            return "reconnaissance"
        if ev.get("path") == "/api/login" and ev.status in (401, 403):
            return "accès initial"
        if ev.get("payload_bucket") == "1k+":
            return "exploitation"
        return "indéterminée"

    def route(self, phase: str, tier: str) -> None:
        self.by_phase[phase] += 1
        self.by_tier[tier] += 1
        self.matrix[(phase, tier)] += 1

    def escalate(self, now: float, reason: str) -> None:
        self.by_tier["T3"] += 1
        self.escalations.append({"ts": round(now, 1), "reason": reason})

    def cost(self) -> dict:
        actual = sum(TIERS[t]["cost"] * n for t, n in self.by_tier.items())
        suspicious = sum(n for t, n in self.by_tier.items() if t != "T3")
        naive = suspicious * TIERS["T3"]["cost"]
        return {"cost_units": round(actual, 2), "naive_llm_cost_units": round(naive, 2),
                "savings_factor": round(naive / actual, 1) if actual else None,
                "t3_escalations": self.by_tier["T3"]}
