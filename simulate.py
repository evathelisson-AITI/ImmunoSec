#!/usr/bin/env python3
"""Démonstration narrée : une journée d'attaques sur 12 passerelles.

  t=120–420  essaim de bourrage d'identifiants (600 IP, low & slow)
  t=300–360  pic de trafic légitime (ne doit déclencher aucune réaction)
  t=500–700  variant muté du même essaim (réponse secondaire par la mémoire)
  t=600–700  panne du plan de contrôle (mode dégradé)
  t=800–1000 essaim d'agents IA compromis (canal caché, exfiltration, clones)
  t=1010     capsule forgée avec une clé volée
  t=1100     kill switch d'exercice (2 approbations humaines sur 3)

Usage : python -I simulate.py [--out sortie/]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from immunosec.adapters import to_modsecurity, to_rego  # noqa: E402
from immunosec.scenarios import run  # noqa: E402

DEMO = {
    "name": "demo", "seed": 42, "duration": 1300, "flash": [300, 360],
    "attacks": [
        {"type": "botnet", "label": "bot1", "start": 120, "end": 420},
        {"type": "botnet", "label": "bot2", "start": 500, "end": 700, "ja3": "ja3-bot-c3e0",
         "ua_family": "firefox", "ip_prefix": "203.1"},
        {"type": "rogue_agents", "start": 800, "end": 1000},
        {"type": "drill_fleet", "start": 1050, "end": 1300},
    ],
    "faults": [
        {"type": "control_plane_outage", "start": 600, "end": 700},
        {"type": "forged_capsule", "at": 1010, "stolen": ["verif-A"]},
        {"type": "kill_switch", "operator": "drill", "at": 1100, "approvers": ["humain-rssi", "humain-dpo"]},
    ],
}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="sortie")
    a = ap.parse_args()
    out = Path(a.out)
    out.mkdir(exist_ok=True)

    print("ImmunoSec — démonstration\n")
    r = run(DEMO, verbose=True)
    system = r.pop("_system")
    m = r["metrics"]

    print("\nBilan")
    labels = {"bot1": "Essaim 1 (bots)", "bot2": "Variant muté", "rogue": "Agents IA compromis",
              "drill": "Flotte d'exercice", "self": "Trafic légitime", "self_flash": "Pic légitime"}
    for lab, name in labels.items():
        if lab not in m:
            continue
        x = m[lab]
        if lab == "drill":
            print(f"  {name:22s} {x['total']:6d} év. — autorisés APRÈS le kill switch : {x['allowed_after_kill']}")
        elif lab.startswith("self"):
            print(f"  {name:22s} {x['total']:6d} év. — impactés : {x['impacted_rate']:.2%}")
        else:
            print(f"  {name:22s} {x['total']:6d} év. — neutralisés : {x['mitigated_rate']:.1%} "
                  f"(inné {x['by_innate']}, adaptatif {x['by_adaptive']}) — confinement en "
                  f"{x['ttc']} s — succès de l'attaquant : {x['success_rate']:.1%}")
    s = m["system"]
    print(f"  Capsules forgées acceptées : {s['forged_accepted']} / rejetées : {s['forged_rejected']}")
    print(f"  Baux révoqués : {s['leases_revoked']} — violations de coalition refusées : "
          f"{s['coalition_violations_refused']} — refus à la passerelle : {s['egress_denied']}")
    print(f"  Journal de preuves : {s['evidence_entries']} entrées, chaîne "
          f"{'VALIDE' if s['evidence_chain_valid'] else 'CORROMPUE'} — tête {r['evidence_head'][:16]}…")

    system.evidence.dump(str(out / "evidence.jsonl"))
    system.memory.path = out / "memory.json"
    system.memory.save()
    (out / "timeline.json").write_text(json.dumps(r["timeline"], indent=2, ensure_ascii=False))
    (out / "metrics.json").write_text(json.dumps(m, indent=2, ensure_ascii=False))
    rules = []
    for cap in system.sent_capsules:
        from immunosec.mrna import Transcript
        t = Transcript(**json.loads(cap.payload))
        if t.action == "revoke" or t.origin == "intérimaire":
            continue
        rules.append(to_rego(t) if t.epitope.get("kind") == "agent" else to_modsecurity(t))
    (out / "regles_exportees.txt").write_text("\n\n".join(rules[-6:]), encoding="utf-8")
    print(f"\nFichiers écrits dans {out}/ : evidence.jsonl, memory.json, timeline.json, "
          "metrics.json, regles_exportees.txt")


if __name__ == "__main__":
    main()
