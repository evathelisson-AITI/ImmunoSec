"""Événement normalisé : la « cellule » observée par le système immunitaire.

Un événement peut être une requête HTTP (essaim de bots) ou une action d'agent IA
(essaim d'agents). Les caractéristiques sont un dictionnaire générique : le même
pipeline de détection fonctionne pour les deux.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:  # pragma: no cover
    from .horos import Lease


@dataclass(slots=True)
class Event:
    ts: float                      # horodatage (secondes)
    node: str                      # nœud / passerelle qui observe l'événement
    src: str                       # IP, ou identifiant d'instance d'agent
    features: dict                 # caractéristiques catégorielles (kind, method, ja3, action, dest...)
    status: int = 200              # code de réponse (401/403 = signal de danger)
    truth: str = "self"            # vérité terrain : utilisée UNIQUEMENT par la simulation
    uai: Optional[str] = None      # Unique Agent Identifier (agents uniquement)
    lease: Optional["Lease"] = None  # bail HOROS présenté par l'agent

    def get(self, feature: str) -> str:
        return self.features.get(feature, "∅")

    @property
    def kind(self) -> str:
        return self.features.get("kind", "http")
