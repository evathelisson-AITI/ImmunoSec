"""Ribosome : traduction locale du transcrit en règle appliquée sur un nœud.

Le nœud ne reçoit jamais de code, seulement une description déclarative qu'il
traduit lui-même (comme la cellule fabrique la protéine Spike sans jamais recevoir
le virus). Contrôles à la réception : quorum de signatures, expiration, version
monotone (anti-rejeu / anti-retour arrière).
"""
from __future__ import annotations

from typing import Optional

from .mrna import ACTIONS, Capsule, IntegrityError, Transcript, decapsulate


class Ribosome:
    def __init__(self, node: str, trust: dict[str, bytes], quorum: int,
                 grace: float = 600.0, hb_timeout: float = 15.0):
        self.node = node
        self.trust = trust
        self.quorum = quorum
        self.active: dict[str, Transcript] = {}
        self.revoked_versions: dict[str, int] = {}
        self.rejected = 0
        # Mode dégradé : si le plan de contrôle se tait, les protections en place ne
        # se dégradent pas (sinon une attaque sur l'orchestrateur désarmerait le
        # réseau). Délai de grâce borné pour ne pas figer indéfiniment une règle.
        self.grace = grace
        self.hb_timeout = hb_timeout
        self.last_hb = 0.0

    def heartbeat(self, now: float) -> None:
        self.last_hb = now

    def degraded(self, now: float) -> bool:
        return now - self.last_hb > self.hb_timeout

    def _expiry(self, t: Transcript, now: float) -> float:
        return t.expires_at + (self.grace if self.degraded(now) else 0.0)

    def receive(self, capsule: Capsule, now: float) -> tuple[bool, str]:
        try:
            t = decapsulate(capsule, self.trust, self.quorum)
        except IntegrityError as e:
            self.rejected += 1
            return False, str(e)
        cur = self.active.get(t.lineage)
        floor = max(cur.version if cur else 0, self.revoked_versions.get(t.lineage, 0))
        if t.version <= floor:
            self.rejected += 1
            return False, "version obsolète (anti-rejeu)"
        if t.action == "revoke":
            self.active.pop(t.lineage, None)
            self.revoked_versions[t.lineage] = t.version
            return True, "révoqué"
        if self._expiry(t, now) <= now:
            return False, "expiré"
        self.active[t.lineage] = t
        return True, "traduit"

    def translate(self, ev, now: float) -> Optional[Transcript]:
        best = None
        for lin, t in list(self.active.items()):
            if self._expiry(t, now) <= now:  # dégradation naturelle de l'ARNm
                del self.active[lin]
                continue
            if t.matches(ev) and (best is None or ACTIONS[t.action] > ACTIONS[best.action]):
                best = t
        return best
