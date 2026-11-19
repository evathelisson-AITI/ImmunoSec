"""Banc d'essai : exécute un scénario (attaques + fautes injectées) et mesure.

Un scénario est un dictionnaire JSON pur → hachable, rejouable, vérifiable par des
nœuds indépendants (voir campaign.py et la campagne Truebit).
"""
from __future__ import annotations

import hashlib
import json
import operator
import random
from collections import Counter, defaultdict
from pathlib import Path

from .adversary import build
from .events import Event
from .mrna import Capsule, Transcript, sign
from .system import MITIGATING, ImmuneSystem
from .thymus import Verifier
from .world import NODES, World, challenge_oracle

OPS = {">=": operator.ge, "<=": operator.le, "==": operator.eq, ">": operator.gt, "<": operator.lt}


def code_hash() -> str:
    h = hashlib.sha256()
    for p in sorted(Path(__file__).parent.glob("*.py")):
        h.update(p.name.encode())
        h.update(p.read_bytes())
    return h.hexdigest()


def canonical_hash(obj) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True, ensure_ascii=False,
                                     separators=(",", ":")).encode()).hexdigest()


def _ttc(series: dict, start: int, window: int = 5, thr: float = 0.9):
    ts = sorted(t for t in series if t >= start)
    for i, t in enumerate(ts):
        chunk = [series[x] for x in range(t, t + window) if x in series]
        if len(chunk) == window and all(c["mit"] / c["total"] >= thr for c in chunk if c["total"]):
            return t - start
    return None


def run(cfg: dict, verbose: bool = False) -> dict:
    seed = cfg.get("seed", 42)
    flash = tuple(cfg["flash"]) if cfg.get("flash") else None
    world = World(seed, flash=flash, payments=bool(cfg.get("payments")))
    rng = random.Random(seed + 1)
    verifiers = [Verifier(f"verif-{c}", f"vkey-{c}-{seed}".encode(),
                          world.profile.subsample(3000, seed + i), 0.001) for i, c in enumerate("ABC")]
    approvers = {f"humain-{n}": f"akey-{n}-{seed}".encode() for n in ("rssi", "dpo", "astreinte")}
    sysargs = dict(cfg.get("system", {}))
    if cfg.get("deception"):
        from .dynamic import Deception
        world.deception = Deception(seed)
        sysargs["deception"] = world.deception
    system = ImmuneSystem(NODES, world.profile, world.authority, verifiers, quorum=2,
                          challenge_oracle=challenge_oracle, approvers=approvers, kill_quorum=2,
                          witnesses={"témoin-EU": b"w-eu", "témoin-CH": b"w-ch"},
                          seed=seed, verbose=verbose, **sysargs)
    attacks = [build(a) for a in cfg.get("attacks", [])]
    faults = cfg.get("faults", [])
    per_label: dict[str, Counter] = defaultdict(Counter)
    per_sec: dict[str, dict] = defaultdict(lambda: defaultdict(Counter))
    first_seen: dict[str, int] = {}
    special = Counter()
    kill_at = None

    for t in range(cfg["duration"]):
        for f in faults:
            typ = f["type"]
            if typ == "control_plane_outage":
                up = not (f["start"] <= t < f["end"])
                if up != system.control_plane_up:
                    system.control_plane_up = up
                    if verbose:
                        print(f"  [t={t:7.1f}s] ⚠ Plan de contrôle {'RÉTABLI' if up else 'EN PANNE'} "
                              "(les nœuds passent en mode dégradé)" if not up else
                              f"  [t={t:7.1f}s] ✓ Plan de contrôle rétabli")
            elif typ == "verifier_outage":
                if t == f["start"]:
                    system.offline_verifiers |= set(f["ids"])
                if t == f["end"]:
                    system.offline_verifiers -= set(f["ids"])
            elif t == f.get("at"):
                if typ == "forged_capsule":
                    # Clé d'attaquant + clés volées : tentative de « désarmer » le vaccin
                    evil = Transcript("SW-001", 999, {}, "revoke", t, 0, 1.0, "forgé")
                    sigs = {"verif-X": sign(evil.canonical(), b"attacker")}
                    for vid in f.get("stolen", []):
                        v = next(v for v in verifiers if v.vid == vid)
                        sigs[vid] = sign(evil.canonical(), v.key)
                    cap = Capsule(evil.canonical(), sigs)
                    for r in system.ribosomes.values():
                        ok, _ = r.receive(cap, t)
                        special["forged_accepted"] += ok
                        special["forged_rejected"] += not ok
                elif typ == "replay":
                    for cap in system.sent_capsules[: f.get("n", 5)]:
                        for r in system.ribosomes.values():
                            ok, _ = r.receive(cap, t)
                            special["replay_accepted"] += ok
                elif typ == "orchestrator_compromise":
                    # L'orchestrateur compromis n'a AUCUNE clé : il ne peut que demander
                    # des signatures. Il tente un transcrit qui bloquerait tout le HTTP.
                    evil = Transcript("EVIL-001", 1, {"kind": "http"}, "block", t, 3600, 1.0, "malveillant")
                    special["evil_pushed"] += system._broadcast(evil, NODES, t)
                elif typ == "kill_switch":
                    approvals = {a: sign(f"kill:{f['operator']}".encode(), approvers[a])
                                 for a in f.get("approvers", [])}
                    approvals.update({a: "signature-forgée" for a in f.get("forged", [])})
                    if system.kill_operator(f["operator"], t, approvals):
                        kill_at = t
                    else:
                        special["kill_denied"] += 1

        evs: list[Event] = world.legit(t)
        for a in attacks:
            evs.extend(a.events(world, t, rng))
        evs.sort(key=lambda e: e.ts)
        for ev in evs:
            action, layer = system.handle(ev)
            lab = ev.truth
            first_seen.setdefault(lab, t)
            c = per_label[lab]
            c["total"] += 1
            mit = action in MITIGATING
            c["mitigated" if mit else "allowed"] += 1
            if mit:
                c[f"by_{layer}"] += 1
            # Succès de l'attaquant : connexion réussie, ou paiement frauduleux exécuté
            if (ev.status == 200 or ev.kind == "payment") and not lab.startswith("self"):
                c["success_baseline"] += 1
                if not mit:
                    c["success"] += 1
            if kill_at is not None and not mit:
                c["allowed_after_kill"] += 1
            s = per_sec[lab][t]
            s["total"] += 1
            s["mit"] += mit
        system.tick(t + 1)

    metrics: dict = {}
    for lab, c in sorted(per_label.items()):
        m = {"total": c["total"], "mitigated_rate": round(c["mitigated"] / c["total"], 4),
             "impacted_rate": round(c["mitigated"] / c["total"], 4),
             "by_innate": c["by_innée"], "by_adaptive": c["by_adaptative"]}
        if not lab.startswith("self"):
            base = c["success_baseline"]
            m["success"] = c["success"]
            m["success_rate"] = round(c["success"] / base, 4) if base else 0.0
            m["ttc"] = _ttc(per_sec[lab], first_seen[lab])
        m["allowed_after_kill"] = c["allowed_after_kill"]
        metrics[lab] = m

    kinds = Counter(e["kind"] for e in system.timeline)
    lineage_starts = sorted(e["ts"] for e in system.timeline if e["kind"] == "canary")
    max_per_min = max((sum(1 for x in lineage_starts if s <= x < s + 60) for s in lineage_starts), default=0)
    ok_chain, n_entries = system.evidence.verify()
    metrics["system"] = {
        "detections": kinds["detection"], "canaries": kinds["canary"], "full": kinds["full"],
        "secondary": kinds["secondary"], "boosters": kinds["booster"], "decayed": kinds["decayed"],
        "matured": kinds["matured"], "revoked": kinds["revoked"], "pv_alerts": kinds["pv_alert"],
        "thymus_rejects": kinds["thymus_reject"], "quorum_failures": system.counters["quorum_failures"],
        "held_released": system.counters["held_released"],
        "storm_deferred": system.counters["storm_deferred"], "fused": system.counters["fused"],
        "cohort_pauses": kinds["cohort_pause"], "max_new_per_min": max_per_min,
        "lymph_dropped": system.lymph.dropped, "egress_denied": system.counters["egress_denied"],
        "leases_revoked": system.counters["leases_revoked"],
        "coalition_violations_refused": world.authority.coalition_violations,
        "forged_accepted": special["forged_accepted"], "forged_rejected": special["forged_rejected"],
        "replay_accepted": special["replay_accepted"], "evil_pushed": special["evil_pushed"],
        "kill_denied": special["kill_denied"], "kill_executed": int(kill_at is not None),
        "evidence_chain_valid": int(ok_chain), "evidence_entries": n_entries,
        "decoy_hits": sum(system.deception.hits.values()) if system.deception else 0,
        **system.router.cost(),
    }
    metrics["killchain"] = {f"{p} → {t}": n for (p, t), n in sorted(system.router.matrix.items())}

    checks = []
    for expr in cfg.get("expect", []):
        lhs, op, rhs = expr.split()
        lab, key = lhs.split(".", 1)
        val = metrics.get(lab, {}).get(key)
        target = float(rhs)
        passed = val is not None and OPS[op](val, target)
        checks.append({"expr": expr, "value": val, "passed": bool(passed)})

    result = {"name": cfg["name"], "metrics": metrics, "checks": checks,
              "passed": all(c["passed"] for c in checks), "evidence_head": system.evidence.head,
              "timeline": system.timeline}
    result["output_hash"] = canonical_hash({"metrics": metrics, "evidence_head": system.evidence.head})
    result["_system"] = system
    return result
