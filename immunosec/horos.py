"""Barrière structurelle pour les essaims d'agents IA (peau + muqueuses).

Inspiré du livre blanc AITI « Innovative Guardrails for Agentic AI » (oct. 2026) :
  * « Contraindre plutôt que classifier » : la classification comportementale est
    indécidable (théorème de Rice), la sûreté repose donc d'abord sur une
    contrainte externe que l'agent ne contrôle pas ;
  * Baux HOROS : chaque action exige un bail temporaire liant le principal (UAI non
    transférable), sa lignée de délégation signée, son domaine d'effet (ODD), une
    courte durée et un ancrage juridictionnel ;
  * Règle de coalition descendante : l'autorité d'un enfant = intersection avec
    celle du parent, elle ne peut que rétrécir ;
  * Contrôle à l'ÉMISSION (passerelle de sortie), pas à l'arrivée ;
  * Kill switch d'opérateur révoquant tous ses baux, à tester régulièrement.

La couche adaptative (ARNm) se place AU-DESSUS : elle traite ce que la barrière
laisse passer (agents légitimement baillés mais compromis, canaux cachés internes).
"""
from __future__ import annotations

import json
from dataclasses import dataclass

from .mrna import sign


class LeaseError(Exception):
    pass


def operator_of(principal: str) -> str:
    parts = principal.split(":")
    return parts[1] if len(parts) > 2 else principal


@dataclass(frozen=True)
class Lease:
    principal: str
    lineage: tuple
    domain: frozenset
    issued: float
    expires: float
    anchor: str
    sig: str = ""

    def body(self) -> bytes:
        return json.dumps({"p": self.principal, "l": list(self.lineage), "d": sorted(self.domain),
                           "i": self.issued, "e": self.expires, "a": self.anchor},
                          sort_keys=True).encode()


class LeaseAuthority:
    def __init__(self, key: bytes, anchor: str = "EU/AI-Act"):
        self.key = key
        self.anchor = anchor
        self.revoked: set[str] = set()
        self.killed_operators: set[str] = set()
        self.coalition_violations = 0
        self.max_duration: dict[str, float] = {}   # confinement dynamique (S2) par opérateur

    def issue(self, principal: str, domain, now: float, duration: float = 120.0,
              parent: Lease | None = None, root: str = "human") -> Lease:
        if principal in self.revoked:
            raise LeaseError("principal révoqué")
        if operator_of(principal) in self.killed_operators:
            raise LeaseError("opérateur suspendu (kill switch)")
        domain = frozenset(domain)
        duration = min(duration, self.max_duration.get(operator_of(principal), duration))
        if parent is not None:
            ok, why = self.verify(parent, now)
            if not ok:
                raise LeaseError(f"bail parent invalide : {why}")
            if not domain <= parent.domain:
                self.coalition_violations += 1
                raise LeaseError("coalition descendante violée : domaine enfant ⊄ domaine parent")
            lineage = parent.lineage + (parent.principal,)
            expires = min(now + duration, parent.expires)
        else:
            lineage, expires = (root,), now + duration
        draft = Lease(principal, lineage, domain, now, expires, self.anchor)
        return Lease(principal, lineage, domain, now, expires, self.anchor, sign(draft.body(), self.key))

    def verify(self, lease: Lease, now: float) -> tuple[bool, str]:
        if sign(lease.body(), self.key) != lease.sig:
            return False, "signature de bail invalide"
        if now >= lease.expires:
            return False, "bail expiré"
        if lease.principal in self.revoked:
            return False, "bail révoqué"
        if operator_of(lease.principal) in self.killed_operators:
            return False, "opérateur suspendu (kill switch)"
        return True, "ok"

    def revoke(self, principal: str) -> None:
        self.revoked.add(principal)

    def shorten(self, operator: str, duration: float) -> None:
        """« Mettre en pause les agents similaires » : raccourcir les baux de la cohorte
        pour forcer des ré-attestations fréquentes pendant l'incident."""
        self.max_duration[operator] = duration

    def kill(self, operator: str) -> None:
        self.killed_operators.add(operator)


class EgressGateway:
    """Passerelle de sortie : bloque à l'émission, hors du contrôle de l'agent."""

    def __init__(self, authority: LeaseAuthority):
        self.authority = authority

    def check(self, ev, now: float) -> tuple[bool, str]:
        if ev.kind != "agent":
            return True, "n/a"
        if ev.lease is None:
            return False, "bail absent"
        ok, why = self.authority.verify(ev.lease, now)
        if not ok:
            return False, why
        if ev.lease.principal != ev.uai:
            return False, "bail non transférable"
        dest = ev.get("dest")
        if dest not in ev.lease.domain:
            return False, f"hors domaine d'effet (ODD) : {dest}"
        return True, "ok"
