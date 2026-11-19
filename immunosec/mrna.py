"""Le transcrit ARNm et sa nanoparticule lipidique.

ARNm biologique                    | Transcrit ImmunoSec
-----------------------------------|----------------------------------------------
Code l'antigène, pas le virus      | Code l'épitope + la riposte, jamais du code exécutable
Traduit par les ribosomes de       | Traduit localement par chaque nœud (Ribosome) en
chaque cellule                     | règle de filtrage
Se dégrade en quelques jours       | TTL : la règle expire seule si elle n'est pas rappelée
Nanoparticule lipidique            | Capsule signée : rejetée si le quorum de signatures
                                   | de vérificateurs indépendants n'est pas atteint
Rappel (booster)                   | Nouvelle version, même lignée, TTL renouvelé

Signatures : HMAC-SHA256 (stdlib) pour le prototype. En production : Ed25519 ou
signatures à seuil, clés en HSM/TEE, une clé par vérificateur indépendant.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import asdict, dataclass

# Échelle de riposte, alignée sur le confinement gradué (S0→S3)
# « hold » = mise en attente avant finalité (paiements) : réversible, confirmée par le client
ACTIONS = {"observe": 0, "challenge": 1, "rate_limit": 2, "hold": 3, "block": 4, "quarantine": 5, "revoke": 6}


@dataclass
class Transcript:
    lineage: str           # famille du vaccin (ex. SW-001) — stable entre variants
    version: int           # monotone : anti-rejeu, le plus récent remplace l'ancien
    epitope: dict          # caractéristique -> valeur (ou liste de valeurs)
    action: str
    issued_at: float
    ttl: float
    confidence: float
    origin: str = "primaire"   # primaire | secondaire | rappel | révocation

    @property
    def id(self) -> str:
        return f"{self.lineage}.v{self.version}"

    @property
    def expires_at(self) -> float:
        return self.issued_at + self.ttl

    def matches(self, ev) -> bool:
        for f, v in self.epitope.items():
            x = ev.get(f)
            if isinstance(v, dict):              # condition négative issue de la maturation
                if x in v.get("not", ()):
                    return False
            elif isinstance(v, (list, tuple)):
                if x not in v:
                    return False
            elif x != v:
                return False
        return True

    def canonical(self) -> bytes:
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False).encode()


class IntegrityError(Exception):
    pass


def sign(payload: bytes, key: bytes) -> str:
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


@dataclass
class Capsule:
    payload: bytes
    signatures: dict   # verifier_id -> signature


def decapsulate(capsule: Capsule, trust: dict[str, bytes], quorum: int) -> Transcript:
    valid = sum(1 for vid, sig in capsule.signatures.items()
                if vid in trust and hmac.compare_digest(sig, sign(capsule.payload, trust[vid])))
    if valid < quorum:
        raise IntegrityError(f"quorum non atteint ({valid}/{quorum} signatures valides)")
    return Transcript(**json.loads(capsule.payload))
