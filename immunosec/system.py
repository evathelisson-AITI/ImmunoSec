"""Orchestrateur : le cycle complet, de l'infection à la mémoire.

    trafic ─► Passerelle de sortie (barrière structurelle, baux HOROS) ─► bloque / laisse passer
          └─► Ribosome du nœud (transcrits actifs) ─► applique la riposte
          └─► Capteur inné (danger) ─► présentation au ganglion
    ganglion ─► antigène ─► mémoire ? ─► transcrit ─► thymus ─► quorum de vérificateurs
          ─► canari (+ confinement intérimaire partout ailleurs) ─► déploiement complet
          ─► pharmacovigilance (retrait ou maturation) ─► rappel ou dégradation ─► mémoire

Robustesse PENDANT la réparation (la fenêtre où l'on est le plus vulnérable) :
  * confinement intérimaire : limitation de débit sur tous les nœuds hors canari ;
  * mode dégradé : les règles ne se dégradent pas si le plan de contrôle tombe ;
  * quorum k-sur-n : tolère la perte de n-k vérificateurs, refuse un signataire isolé ;
  * contre-pression du ganglion : un nœud inondé ne sature pas l'analyse ;
  * disjoncteur anti-tempête de cytokines : nombre borné de nouvelles lignées/min ;
  * pharmacovigilance : défis témoins (holdout) mesurant les dommages collatéraux
    réels après déploiement, avec retrait ou maturation d'affinité automatique ;
  * versions monotones + révocations signées : retour arrière sûr, sans rejeu.
"""
from __future__ import annotations

import random
from collections import Counter, defaultdict, deque
from dataclasses import replace
from typing import Callable, Optional

from .events import Event
from .evidence import EvidenceLog
from .horos import EgressGateway, LeaseAuthority
from .lymph import Antigen, LymphNode
from .memory import ImmuneMemory, conserved, polyvalent
from .horos import operator_of
from .dynamic import Deception, KillChainRouter
from .mrna import Capsule, Transcript, sign
from .ribosome import Ribosome
from .self_profile import SelfProfile
from .sensors import NON_DISCRIMINANT, InnateSensor
from .thymus import Thymus, Verifier

MITIGATING = {"challenge", "rate_limit", "hold", "block", "quarantine", "deceive"}


def fmt_epitope(ep: dict) -> str:
    parts = []
    for k, v in ep.items():
        if k == "kind":
            continue
        if isinstance(v, dict):
            parts.append(f"{k}∉{{{len(v['not'])} valeurs}}")
        elif isinstance(v, list):
            parts.append(f"{k}∈{v}")
        else:
            parts.append(f"{k}={v}")
    return ", ".join(parts)


class ImmuneSystem:
    def __init__(self, nodes, profile: SelfProfile, authority: LeaseAuthority,
                 verifiers: list[Verifier], *, quorum: int = 2,
                 challenge_oracle: Optional[Callable[[Event], bool]] = None,
                 memory: Optional[ImmuneMemory] = None, evidence: Optional[EvidenceLog] = None,
                 witnesses: Optional[dict] = None,
                 canary_fraction: float = 0.25, canary_period: float = 20.0,
                 scan_interval: float = 5.0, ttl: float = 300.0, renew_window: float = 60.0,
                 holdout: float = 0.10, max_collateral: float = 0.05,
                 max_new_lineages_per_min: int = 4, heartbeat_grace: float = 600.0,
                 lymph_quota: int = 4000, approvers: Optional[dict] = None, kill_quorum: int = 2,
                 deception: Optional[Deception] = None, lymph_scope: str = "global",
                 seed: int = 7, verbose: bool = True):
        self.nodes = list(nodes)
        self.profile = profile
        self.authority = authority
        self.verifiers = verifiers
        self.quorum = quorum
        # Défi témoin : CAPTCHA / preuve de possession pour un humain, ré-attestation
        # TEE + confirmation par le principal humain pour un agent.
        self.oracle = challenge_oracle or (lambda ev: False)
        self.gateway = EgressGateway(authority)
        self.taint: dict[str, float] = {}
        self.sensors = {n: InnateSensor(n, profile, self.taint) for n in self.nodes}
        trust = {v.vid: v.key for v in verifiers}
        self.ribosomes = {n: Ribosome(n, trust, quorum, heartbeat_grace) for n in self.nodes}
        self.lymph = LymphNode(profile, per_node_quota=lymph_quota)
        # « local » = ablation : chaque établissement corrèle seul, sans partage du motif
        self.lymph_scope = lymph_scope
        self.local_lymphs = ({n: LymphNode(profile, per_node_quota=lymph_quota, min_nodes=1, owner=n)
                              for n in self.nodes} if lymph_scope == "local" else {})
        self.thymus = Thymus(profile.sample)
        self.memory = memory or ImmuneMemory()
        self.evidence = evidence or EvidenceLog()
        self.witnesses = witnesses or {}

        self.canary_fraction, self.canary_period = canary_fraction, canary_period
        self.scan_interval, self.ttl, self.renew_window = scan_interval, ttl, renew_window
        self.holdout, self.max_collateral = holdout, max_collateral
        self.max_new = max_new_lineages_per_min

        self.rollouts: dict[str, dict] = {}
        # lignée -> deque[(ts, nœud, résultat du défi témoin: True/False/None, événement)]
        self.hits: dict[str, deque] = defaultdict(deque)
        self.buckets: dict[tuple, float] = {}
        self.timeline: list[dict] = []
        self.counters: Counter = Counter()
        self.control_plane_up = True
        self.offline_verifiers: set[str] = set()
        self.deception = deception
        self.router = KillChainRouter()
        self.approvers: dict[str, bytes] = approvers or {}
        self.kill_quorum = kill_quorum
        self._issued: deque = deque()
        self.sent_capsules: list[Capsule] = []
        self._rng = random.Random(seed)
        self._n = 0
        self._next_scan = 0.0
        self._next_ckpt = 60.0
        self.verbose = verbose

    # ------------------------------------------------------------------ journal
    def _log(self, now: float, kind: str, msg: str, **data) -> None:
        self.timeline.append({"ts": round(now, 1), "kind": kind, "msg": msg, **data})
        if kind in ("thymus_reject", "no_safe_transcript", "pv_alert"):
            # Ambiguïté à fort enjeu → agent analyste (T3), lecture seule : il propose,
            # le thymus et le quorum disposent.
            self.router.escalate(now, kind)
        self.evidence.append(now, kind, {"msg": msg, **data})
        if self.verbose:
            print(f"  [t={now:7.1f}s] {msg}")

    # ------------------------------------------------------------ plan de données
    def handle(self, ev: Event) -> tuple[str, Optional[str]]:
        now = ev.ts
        if self.deception is not None and ev.kind == "http":
            if self.deception.rotate(now):
                self.counters["decoy_rotations"] += 1
            trap = self.deception.trap(ev)
            if trap:                                  # cible mouvante : quasi zéro faux positif
                self.taint[ev.src] = now
                self.router.route("reconnaissance", "T0")
                if self.counters["decoy_logged"] < 3:
                    self.counters["decoy_logged"] += 1
                    self._log(now, "decoy", f"Leurre touché ({trap}) : {ev.src} marqué — "
                              "toute action ultérieure de cette source est un signal de dommage")
                return "deceive", "déception"
        ok, why = self.gateway.check(ev, now)
        if not ok:                                    # « Bloquer d'abord, preuve ensuite »
            self.router.route(KillChainRouter.phase(ev, gateway_reason=why), "T0")
            self.taint[ev.src] = now
            self.counters["egress_denied"] += 1
            self.evidence.append(now, "egress_denied", {"uai": ev.uai, "reason": why, "node": ev.node})
            return "block", "innée"

        t = self.ribosomes[ev.node].translate(ev, now)
        if t is not None:
            self.router.route(KillChainRouter.phase(ev), "T0")
            return self._apply(t, ev, now)

        sensor = self.sensors[ev.node]
        if sensor.is_dangerous(ev):
            self.router.route(KillChainRouter.phase(ev), "T2")
            if self.control_plane_up:
                (self.local_lymphs.get(ev.node) or self.lymph).present(ev)
        elif sensor.damage(ev):
            self.router.route(KillChainRouter.phase(ev), "T1")
        return "allow", None

    def _apply(self, t: Transcript, ev: Event, now: float) -> tuple[str, Optional[str]]:
        if t.action == "hold":
            # Paiement mis en attente AVANT finalité : le client confirme par un canal
            # indépendant (rappel, appli). Confirmé → libéré ; sinon → rejeté.
            ok = bool(self.oracle(ev))
            self.hits[t.lineage].append((now, ev.node, ok, ev))
            if ok:
                self.counters["held_released"] += 1
                return "allow", "libéré après confirmation"
            return "hold", "adaptative"
        verdict = None
        stage = self.rollouts.get(t.lineage, {}).get("stage")
        rate = 0.25 if stage == "canary" else self.holdout   # essai clinique renforcé
        if t.action != "observe" and self._rng.random() < rate:
            verdict = bool(self.oracle(ev))          # défi témoin (pharmacovigilance)
        self.hits[t.lineage].append((now, ev.node, verdict, ev))
        if verdict is True:
            return "allow", "défi réussi"
        if t.action == "observe":
            return "allow", None
        if t.action == "rate_limit":
            key = (t.lineage, ev.node)
            if now - self.buckets.get(key, -1e9) >= 5.0:   # 1 requête / 5 s / nœud
                self.buckets[key] = now
                return "allow", "quota"
            return "rate_limit", "adaptative"
        if t.action == "quarantine" and ev.uai and ev.uai not in self.authority.revoked:
            self.authority.revoke(ev.uai)
            self.counters["leases_revoked"] += 1
            self.evidence.append(now, "lease_revoked", {"uai": ev.uai, "by": t.id})
            op = operator_of(ev.uai)
            self.counters[f"quarantined:{op}"] += 1
            if self.counters[f"quarantined:{op}"] == 10 and op not in self.authority.max_duration:
                self.authority.shorten(op, 30.0)
                self._log(now, "cohort_pause", f"Cohorte « {op} » : baux raccourcis à 30 s "
                          "(ré-attestation forcée des agents similaires)", operator=op)
        return t.action, "adaptative"

    # ----------------------------------------------------------- plan de contrôle
    def tick(self, now: float) -> None:
        if not self.control_plane_up:
            return
        for r in self.ribosomes.values():
            r.heartbeat(now)
        if self.witnesses and now >= self._next_ckpt:
            self.evidence.checkpoint(now, self.witnesses)
            self._next_ckpt = now + 60.0
        if now < self._next_scan:
            return
        self._next_scan = now + self.scan_interval
        self._advance(now)
        self._pharmacovigilance(now)
        self._maintain(now)

        def covered(e: Event) -> bool:
            return any(e.node in r["canary"] and r["t"].matches(e) for r in self.rollouts.values())

        def primed(ep: dict) -> bool:
            return not self.local_lymphs and self.memory.recall(ep) is not None

        found = []
        for lymph in (self.local_lymphs.values() if self.local_lymphs else [self.lymph]):
            found.extend(lymph.scan(now, covered, primed))
        for ag in self._fuse(found, now):
            self._respond(ag, now)

    def _fuse(self, antigens: list[Antigen], now: float) -> list[Antigen]:
        """Essaims simultanés de même forme (mêmes clés, outillage décliné) → un seul
        antigène polyvalent : une lignée au lieu de k, contre la tempête de transcrits."""
        groups: dict = defaultdict(list)
        for ag in antigens:
            if self.memory.recall(ag.epitope):
                groups[id(ag)].append(ag)
            else:
                groups[tuple(sorted(ag.epitope))].append(ag)
        out = []
        for g in groups.values():
            if len(g) == 1:
                out.append(g[0])
                continue
            ep = g[0].epitope
            for other in g[1:]:
                ep = polyvalent(ep, other.epitope)
            self.counters["fused"] += len(g) - 1
            out.append(Antigen(ep, {}, sum(a.sources for a in g), max(a.nodes for a in g),
                               sum(a.events for a in g), min(a.first_seen for a in g), now, ("fusion",)))
        return out

    def _sign(self, t: Transcript) -> Optional[Capsule]:
        payload = t.canonical()
        sigs = {}
        for v in self.verifiers:
            if v.vid in self.offline_verifiers:
                continue
            s = v.endorse(t)
            if s:
                sigs[v.vid] = s
        return Capsule(payload, sigs) if len(sigs) >= self.quorum else None

    def _broadcast(self, t: Transcript, nodes, now: float) -> bool:
        cap = self._sign(t)
        if cap is None:
            self.counters["quorum_failures"] += 1
            self._log(now, "quorum_fail", f"Quorum de vérificateurs non atteint pour {t.id} : "
                      "diffusion suspendue, la barrière innée reste active", transcript=t.id)
            return False
        self.sent_capsules.append(cap)
        for n in nodes:
            self.ribosomes[n].receive(cap, now)
        return True

    def _revoke(self, lineage: str, now: float, reason: str, kind: str = "revoked") -> None:
        r = self.rollouts.pop(lineage, None)
        if not r:
            return
        rv = Transcript(lineage, r["t"].version + 1, {}, "revoke", now, 0.0, 1.0, "révocation")
        self._broadcast(rv, self.nodes, now)
        self._log(now, kind, f"{lineage} révoqué ({reason})", lineage=lineage)

    def _new_lineage_allowed(self, now: float) -> bool:
        while self._issued and self._issued[0] < now - 60.0:
            self._issued.popleft()
        return len(self._issued) < self.max_new

    def _respond(self, ag: Antigen, now: float) -> None:
        self.counters["antigens"] += 1
        if ag.owner is not None:
            return self._respond_local(ag, now)
        recall = self.memory.recall(ag.epitope)
        if not recall and not self._new_lineage_allowed(now):
            self.counters["storm_deferred"] += 1
            return  # disjoncteur : l'antigène sera re-présenté au prochain balayage
        latency = now - ag.first_seen
        self._log(now, "detection", f"Essaim détecté : {ag.sources} sources / {ag.nodes} nœuds "
                  f"(premier signal il y a {latency:.0f}s) — épitope {{{fmt_epitope(ag.epitope)}}}",
                  sources=ag.sources, epitope=ag.epitope)
        plans = []
        if recall:
            cell, aff = recall
            plans = [("secondaire", cell.lineage, conserved(cell.epitope, ag.epitope), aff),
                     ("secondaire", cell.lineage, polyvalent(cell.epitope, ag.epitope), aff)]
        else:
            self._n += 1
            plans = [("primaire", f"SW-{self._n:03d}", ag.epitope, None)]

        for origin, lin, ep, aff in plans:
            if len([k for k in ep if k not in NON_DISCRIMINANT]) < 2:
                continue
            conf = 0.97 if origin == "secondaire" else min(0.99, 0.5 + 0.5 * min(1.0, ag.sources / 100))
            action = "block" if conf >= 0.9 else "challenge"
            if ep.get("kind") == "agent" and action == "block":
                action = "quarantine"
            if ep.get("kind") == "payment":
                action = "hold"   # jamais de rejet sec avant finalité : mise en attente
            cur = self.rollouts.get(lin)
            base = max(cur["t"].version if cur else 0, recall[0].version if recall else 0)
            t = Transcript(lin, base + 1, dict(ep), action, now, self.ttl, round(conf, 3), origin)
            sel = self.thymus.select(t)
            if not sel.passed:
                self._log(now, "thymus_reject", f"Thymus : {t.id} rejeté — {sel.reason}")
                continue
            t.action = sel.action if ep.get("kind") != "payment" else "hold"
            if origin == "secondaire":
                if not self._broadcast(t, self.nodes, now):
                    return
                self.rollouts[lin] = {"t": t, "stage": "full", "started": now, "canary": set(self.nodes)}
                self.memory.store(lin, t.epitope, t.version, now)
                self._log(now, "secondary", f"Réponse SECONDAIRE (mémoire, affinité {aff:.2f}) : "
                          f"{t.id} [{t.action}] ciblant la région conservée {{{fmt_epitope(t.epitope)}}} "
                          "→ tous les nœuds, sans canari", lineage=lin)
            else:
                k = max(1, round(len(self.nodes) * self.canary_fraction))
                canary = sorted(self._rng.sample(self.nodes, k))
                if not self._broadcast(t, canary, now):
                    return
                self._issued.append(now)
                self.rollouts[lin] = {"t": t, "stage": "canary", "started": now, "canary": set(canary)}
                self._log(now, "canary", f"Transcrit {t.id} [{t.action}, confiance {t.confidence}] "
                          f"signé {self.quorum}-sur-{len(self.verifiers)} → canari sur {len(canary)} nœuds",
                          lineage=lin)
                others = [n for n in self.nodes if n not in canary]
                it = Transcript(lin + "-i", 1, dict(ep), "hold" if ep.get("kind") == "payment" else "rate_limit",
                                now, self.canary_period * 3,
                                t.confidence, "intérimaire")
                if self._broadcast(it, others, now):
                    self.rollouts[it.lineage] = {"t": it, "stage": "interim", "started": now,
                                                 "canary": set(others)}
                    self._log(now, "interim", f"Confinement intérimaire {it.id} [rate_limit] sur "
                              f"{len(others)} nœuds pendant la phase canari", lineage=it.lineage)
            return
        self._log(now, "no_safe_transcript", "Aucun transcrit sûr : surveillance renforcée, "
                  "escalade vers l'analyste")

    def _respond_local(self, ag: Antigen, now: float) -> None:
        """Ablation « sans partage » : l'établissement détecteur se protège seul,
        sans mémoire commune ni diffusion aux autres."""
        self._n += 1
        lin = f"SW-{self._n:03d}@{ag.owner}"
        action = "hold" if ag.epitope.get("kind") == "payment" else "block"
        t = Transcript(lin, 1, dict(ag.epitope), action, now, self.ttl, 0.9, "locale")
        if not self.thymus.select(t).passed or not self._broadcast(t, [ag.owner], now):
            return
        self.rollouts[lin] = {"t": t, "stage": "full", "started": now, "canary": {ag.owner}}
        self._log(now, "local", f"{ag.owner} détecte seul ({ag.sources} sources) et se protège seul : {t.id}",
                  lineage=lin)

    @staticmethod
    def _collateral(samples: list) -> tuple[float, int]:
        judged = [s[2] for s in samples if s[2] is not None]
        if not judged:
            return 0.0, 0
        return sum(judged) / len(judged), len(judged)

    def _advance(self, now: float) -> None:
        for lin, r in list(self.rollouts.items()):
            if r["stage"] != "canary":
                continue
            elapsed = now - r["started"]
            if elapsed < self.canary_period:
                continue
            hs = [h for h in self.hits[lin] if h[0] >= r["started"]]
            coll, n = self._collateral(hs)
            if n == 0:
                if elapsed > 6 * self.canary_period:
                    self._revoke(lin, now, "aucun contact pendant le canari")
                continue
            if coll > self.max_collateral:
                self._revoke(lin, now, f"canari : {coll:.0%} de défis réussis = dommages collatéraux")
                self._revoke(lin + "-i", now, "canari échoué", "interim_end")
                continue
            if n >= 5 or elapsed >= 3 * self.canary_period:
                # Le canari a accumulé des preuves : on réévalue la confiance et on
                # durcit la riposte si l'essaim est confirmé à grande échelle.
                sources = len({h[3].src for h in hs})
                judged = [h[2] for h in hs if h[2] is not None]
                laplace = 1 - (sum(judged) + 1) / (len(judged) + 2)   # défis échoués = preuve
                conf = max(r["t"].confidence, laplace, min(0.99, 0.5 + 0.5 * min(1.0, sources / 100)))
                action = r["t"].action
                if conf >= 0.9 and action == "challenge" and r["t"].epitope.get("kind") != "payment":
                    action = "quarantine" if r["t"].epitope.get("kind") == "agent" else "block"
                t2 = replace(r["t"], version=r["t"].version + 1, action=action,
                             confidence=round(conf, 3), issued_at=now)
                if self.thymus.select(t2).passed and self._broadcast(t2, self.nodes, now):
                    r["t"], r["stage"], r["canary"] = t2, "full", set(self.nodes)
                    self.memory.store(lin, t2.epitope, t2.version, now)
                    self._revoke(lin + "-i", now, "remplacé par le déploiement complet", "interim_end")
                    self._log(now, "full", f"Canari validé ({len(hs)} contacts, {n} défis témoins, "
                              f"collatéral {coll:.0%}) → {t2.id} [{t2.action}, confiance {t2.confidence}] "
                              f"sur les {len(self.nodes)} nœuds ; cellule mémoire créée", lineage=lin)

    def _pharmacovigilance(self, now: float) -> None:
        for lin, r in list(self.rollouts.items()):
            if r["stage"] != "full":
                continue
            hs = [h for h in self.hits[lin] if h[0] >= now - 60.0]
            coll, n = self._collateral(hs)
            if n < 20 or coll <= self.max_collateral:
                continue
            self.counters["pharmacovigilance_alerts"] += 1
            self._log(now, "pv_alert", f"Pharmacovigilance : {lin} touche du trafic légitime "
                      f"({coll:.0%} des défis réussis sur {n})", lineage=lin)
            matured = self._mature(r["t"], hs, now)
            if matured is None:
                self._revoke(lin, now, "effet indésirable, aucune maturation sûre")

    def _mature(self, t: Transcript, hs: list, now: float) -> Optional[Transcript]:
        """Maturation d'affinité : trouver une caractéristique qui sépare les témoins
        légitimes (défi réussi) des attaquants (défi échoué), et l'ajouter en exclusion."""
        passed = [h[3] for h in hs if h[2] is True]
        failed = [h[3] for h in hs if h[2] is False]
        if not passed or not failed:
            return None
        best = None
        feats = {f for f in set().union(*(e.features.keys() for e in passed))
                 if f != "kind" and (f not in t.epitope or isinstance(t.epitope[f], dict))}
        for f in sorted(feats):
            # Tolérance périphérique : valeurs vues chez les témoins légitimes + valeurs
            # courantes du soi + exclusions déjà apprises.
            vp = {e.get(f) for e in passed}
            vp |= {v for v, c in self.profile.counts[f].items() if c / max(1, self.profile.total) >= 0.005}
            if isinstance(t.epitope.get(f), dict):
                vp |= set(t.epitope[f]["not"])
            overlap = sum(1 for e in failed if e.get(f) in vp) / len(failed)
            if len(vp) <= 64 and overlap <= 0.05 and (best is None or overlap < best[1]):
                best = (f, overlap, sorted(vp))
        if best is None:
            return None
        f, overlap, vp = best
        ep = dict(t.epitope)
        ep[f] = {"not": vp}
        t2 = replace(t, version=t.version + 1, epitope=ep, issued_at=now, origin="maturation")
        if not self.thymus.select(t2).passed or any(t2.matches(e) for e in passed):
            return None
        if not self._broadcast(t2, self.nodes, now):
            return None
        self.rollouts[t.lineage]["t"] = t2
        self.hits[t.lineage].clear()
        self.memory.store(t.lineage, ep, t2.version, now)
        self._log(now, "matured", f"Maturation d'affinité : {t2.id} exclut {f} ∈ {vp} "
                  f"(sépare légitimes et attaquants, chevauchement {overlap:.0%})", lineage=t.lineage)
        return t2

    def _maintain(self, now: float) -> None:
        for lin, r in list(self.rollouts.items()):
            t = r["t"]
            dq = self.hits[lin]
            while dq and dq[0][0] < now - self.ttl:
                dq.popleft()
            rem = t.expires_at - now
            recent = bool(dq) and dq[-1][0] >= now - self.renew_window
            if r["stage"] == "full" and rem < self.renew_window and recent:
                t2 = replace(t, version=t.version + 1, issued_at=now, origin="rappel")
                if self._broadcast(t2, self.nodes, now):
                    r["t"] = t2
                    self.memory.store(lin, t2.epitope, t2.version, now)
                    self._log(now, "booster", f"Rappel : {t2.id} (essaim encore actif) — TTL renouvelé",
                              lineage=lin)
            elif rem <= 0:
                self.rollouts.pop(lin, None)
                if r["stage"] != "interim":
                    self._log(now, "decayed", f"{t.id} dégradé naturellement (TTL expiré, plus "
                              "aucun contact) — la cellule mémoire demeure", lineage=lin)

    # --------------------------------------------------------- commandes d'urgence
    def kill_operator(self, operator: str, now: float, approvals: dict[str, str]) -> bool:
        """Pas d'accès root : même l'arrêt d'urgence exige k approbations humaines
        indépendantes (signatures distinctes). Un seul compte compromis ne peut ni
        déclencher ni empêcher l'arrêt d'un opérateur entier."""
        msg = f"kill:{operator}".encode()
        valid = {a for a, s in approvals.items()
                 if a in self.approvers and s == sign(msg, self.approvers[a])}
        if len(valid) < self.kill_quorum:
            self.counters["kill_denied"] += 1
            self._log(now, "kill_denied", f"Kill switch refusé pour « {operator} » : "
                      f"{len(valid)}/{self.kill_quorum} approbations valides", operator=operator)
            return False
        self.authority.kill(operator)
        self._log(now, "kill_switch", f"KILL SWITCH ({len(valid)}/{len(self.approvers)} approbations) : "
                  f"tous les baux de l'opérateur « {operator} » révoqués à la passerelle",
                  operator=operator, approvers=sorted(valid))
        return True
