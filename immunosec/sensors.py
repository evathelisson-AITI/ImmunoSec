"""Immunité innée locale : capteurs de danger sur chaque nœud.

Modèle du danger (Matzinger) : on ne réagit pas à « l'étranger » mais aux signaux
de dommage. Un essaim est conçu pour que chaque membre reste sous les seuils
individuels (low & slow) : les capteurs ne bloquent donc rien, ils PRÉSENTENT les
événements suspects au ganglion (LymphNode), qui voit l'ensemble.
"""
from __future__ import annotations

from .events import Event
from .self_profile import SelfProfile

NON_DISCRIMINANT = {"asn", "kind"}


class InnateSensor:
    def __init__(self, node: str, profile: SelfProfile, taint: dict[str, float],
                 threshold: float = 0.6, rarity: float = 0.005, taint_window: float = 60.0):
        self.node = node
        self.profile = profile
        self.taint = taint              # partagé : principal -> dernier refus à la passerelle
        self.threshold = threshold
        self.rarity = rarity
        self.taint_window = taint_window

    def danger(self, ev: Event) -> float:
        s = 0.0
        if ev.status in (401, 403, 409, 429):
            s += 0.5                    # dommage : authentification refusée, accès interdit
        elif ev.status >= 500:
            s += 0.2
        if ev.src not in self.profile.known_sources:
            s += 0.3                    # source jamais vue
        t = self.taint.get(ev.src)
        if t is not None and ev.ts - t <= self.taint_window:
            s += 0.4                    # principal récemment bloqué par la barrière structurelle
        rare = sum(1 for f, v in ev.features.items()
                   if f not in NON_DISCRIMINANT and self.profile.freq(f, v) < self.rarity)
        s += min(0.3, 0.15 * rare)      # motifs absents du soi
        return min(1.0, s)

    def damage(self, ev: Event) -> bool:
        """Signal de DOMMAGE (et non de simple nouveauté) : échec d'authentification,
        refus, erreur serveur, ou principal récemment bloqué par la barrière."""
        t = self.taint.get(ev.src)
        # 409 = alerte de vérification du bénéficiaire (nom ≠ titulaire du compte)
        return ev.status in (401, 403, 409, 429) or ev.status >= 500 or (
            t is not None and ev.ts - t <= self.taint_window)

    def is_dangerous(self, ev: Event) -> bool:
        # Nouveauté + rareté seules ne suffisent pas : un lancement d'application
        # légitime est nouveau et rare. Sans dommage, pas de présentation.
        return self.damage(ev) and self.danger(ev) >= self.threshold
