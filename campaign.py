#!/usr/bin/env python3
"""Campagne de tests adverses, conçue pour la vérification indépendante (Truebit).

Chaque test est une fonction pure (configuration JSON, graine, code) → (métriques,
tête du journal de preuves). Trois empreintes le rendent vérifiable par des tiers :
  input_hash  = SHA-256 de la configuration canonique
  code_hash   = SHA-256 du code du paquet immunosec
  output_hash = SHA-256 des métriques + tête de la chaîne de preuves
Des nœuds indépendants qui ré-exécutent le même (code_hash, input_hash) doivent
obtenir le même output_hash. Un écart signale une non-reproductibilité ou une fraude.

Usage :
  python -I campaign.py                    # exécute tout, écrit campaign/results.json + manifeste
  python -I campaign.py --test T05 -v      # un test, journal détaillé
  python -I campaign.py --verify campaign/results.json   # ré-exécution et comparaison des hashes
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from immunosec.scenarios import canonical_hash, code_hash, run  # noqa: E402

BOT1 = {"type": "botnet", "label": "bot1", "start": 120, "end": 420}

TESTS = [
    {"id": "T01", "name": "Référence sans attaque (pic de trafic légitime inclus)",
     "objective": "Aucune réaction auto-immune face à un afflux légitime",
     "cfg": {"duration": 600, "flash": [300, 360], "attacks": []},
     "expect": ["self.impacted_rate <= 0.002", "self_flash.impacted_rate <= 0.0",
                "system.canaries == 0"]},
    {"id": "T02", "name": "Essaim low & slow (bourrage d'identifiants, 600 IP)",
     "objective": "Détection et confinement rapides malgré des sources individuellement sous les seuils",
     "cfg": {"duration": 600, "attacks": [BOT1]},
     "expect": ["bot1.mitigated_rate >= 0.9", "bot1.ttc <= 30", "bot1.success_rate <= 0.15",
                "self.impacted_rate <= 0.002"]},
    {"id": "T03", "name": "Variant muté (nouvelle empreinte TLS, même outillage)",
     "objective": "Réponse secondaire par mémoire, plus rapide que la primaire, ciblant la région conservée",
     "cfg": {"duration": 700, "attacks": [
         {**BOT1, "end": 300},
         {"type": "botnet", "label": "bot2", "start": 450, "end": 650, "ja3": "ja3-bot-c3e0",
          "ua_family": "firefox", "ip_prefix": "203.1"}]},
     "expect": ["bot2.ttc <= 5", "system.secondary >= 1", "bot2.mitigated_rate >= 0.95"]},
    {"id": "T04", "name": "Mimétisme parfait du soi (limite documentée)",
     "objective": "Sans épitope distinctif, la couche adaptative NE DOIT PAS réagir (pas d'auto-immunité)",
     "cfg": {"duration": 500, "attacks": [{"type": "mimicry", "label": "mimic", "start": 100, "end": 400}]},
     "expect": ["self.impacted_rate <= 0.002", "system.canaries == 0"]},
    {"id": "T05", "name": "Collision provoquée → pharmacovigilance et maturation d'affinité",
     "objective": "Détecter après déploiement qu'un transcrit touche du légitime et le corriger seul",
     "cfg": {"duration": 700, "attacks": [
         {"type": "botnet", "label": "bot_app", "start": 100, "end": 650, "ja3": "ja3-app-2.0",
          "header_order": "ho-app", "ua_family": "app", "ip_prefix": "203.2"},
         {"type": "app_launch", "label": "self_app", "start": 300, "end": 700}]},
     "expect": ["system.pv_alerts >= 1", "system.matured >= 1", "self_app.impacted_rate <= 0.05",
                "bot_app.mitigated_rate >= 0.85"]},
    {"id": "T06", "name": "Inondation du ganglion + essaim réel masqué",
     "objective": "La contre-pression empêche la saturation du processus de réparation",
     "cfg": {"duration": 500, "attacks": [
         {"type": "lymph_flood", "start": 100, "end": 400, "rate": 300},
         {**BOT1, "start": 150, "end": 450}]},
     "expect": ["system.lymph_dropped >= 1", "bot1.ttc <= 30", "bot1.mitigated_rate >= 0.9"]},
    {"id": "T07", "name": "Tempête de micro-essaims (tempête de cytokines)",
     "objective": "Fusion polyvalente + disjoncteur : rythme de transcrits borné sans abandonner la défense",
     "cfg": {"duration": 600, "attacks": [{"type": "micro_swarms", "start": 100, "end": 500, "k": 10}]},
     "expect": ["system.max_new_per_min <= 4", "system.fused >= 1",
                "churn.mitigated_rate >= 0.6", "self.impacted_rate <= 0.002"]},
    {"id": "T08", "name": "Capsule forgée (1 clé volée) + rejeu de capsules anciennes",
     "objective": "La nanoparticule (quorum + versions monotones) résiste à la falsification et au rejeu",
     "cfg": {"duration": 500, "attacks": [BOT1],
             "faults": [{"type": "forged_capsule", "at": 200, "stolen": ["verif-A"]},
                        {"type": "replay", "at": 250, "n": 5}]},
     "expect": ["system.forged_accepted == 0", "system.replay_accepted == 0",
                "bot1.mitigated_rate >= 0.9"]},
    {"id": "T09", "name": "Perte de 1 vérificateur sur 3 pendant la détection",
     "objective": "Le quorum 2-sur-3 tolère une panne sans ralentir la réparation",
     "cfg": {"duration": 500, "attacks": [BOT1],
             "faults": [{"type": "verifier_outage", "ids": ["verif-B"], "start": 100, "end": 400}]},
     "expect": ["system.quorum_failures == 0", "bot1.ttc <= 30"]},
    {"id": "T10", "name": "Perte de 2 vérificateurs sur 3 (sûreté avant disponibilité)",
     "objective": "Sans quorum, rien n'est diffusé ; la défense reprend dès le rétablissement",
     "cfg": {"duration": 600, "attacks": [BOT1],
             "faults": [{"type": "verifier_outage", "ids": ["verif-A", "verif-B"], "start": 100, "end": 200}]},
     "expect": ["system.quorum_failures >= 1", "bot1.mitigated_rate >= 0.6", "self.impacted_rate <= 0.002"]},
    {"id": "T11", "name": "Panne du plan de contrôle pendant l'attaque (360 s > TTL)",
     "objective": "Mode dégradé : les protections ne se dégradent pas quand l'orchestrateur tombe",
     "cfg": {"duration": 800, "attacks": [{**BOT1, "end": 750}],
             "faults": [{"type": "control_plane_outage", "start": 200, "end": 560}]},
     "expect": ["bot1.mitigated_rate >= 0.9"]},
    {"id": "T11b", "name": "Ablation de T11 : sans délai de grâce",
     "objective": "Preuve par contraste que le mode dégradé est nécessaire",
     "cfg": {"duration": 800, "attacks": [{**BOT1, "end": 750}], "system": {"heartbeat_grace": 0},
             "faults": [{"type": "control_plane_outage", "start": 200, "end": 560}]},
     "expect": ["bot1.mitigated_rate <= 0.85"]},
    {"id": "T12", "name": "Essaim d'agents IA compromis (canal caché, exfiltration DNS, clones)",
     "objective": "Barrière structurelle + quarantaine adaptative des agents à bail valide",
     "cfg": {"duration": 600, "attacks": [{"type": "rogue_agents", "start": 100, "end": 400}]},
     "expect": ["rogue.mitigated_rate >= 0.85", "system.leases_revoked >= 60", "system.cohort_pauses >= 1",
                "system.coalition_violations_refused >= 1", "self.impacted_rate <= 0.002"]},
    {"id": "T13", "name": "Orchestrateur compromis (pas d'accès root)",
     "objective": "Un orchestrateur compromis ne peut pas pousser un transcrit qui bloque tout le trafic",
     "cfg": {"duration": 300, "attacks": [], "faults": [{"type": "orchestrator_compromise", "at": 100}]},
     "expect": ["system.evil_pushed == 0", "system.quorum_failures >= 1", "self.impacted_rate <= 0.002"]},
    {"id": "T14", "name": "Kill switch : 1 approbateur compromis, puis exercice légitime 2-sur-3",
     "objective": "Personne ne déclenche seul l'arrêt ; l'arrêt approuvé est total et immédiat",
     "cfg": {"duration": 400, "attacks": [{"type": "drill_fleet", "start": 50, "end": 400}],
             "faults": [{"type": "kill_switch", "operator": "acme", "at": 100,
                         "approvers": ["humain-astreinte"], "forged": ["humain-rssi"]},
                        {"type": "kill_switch", "operator": "drill", "at": 200,
                         "approvers": ["humain-rssi", "humain-dpo"]}]},
     "expect": ["system.kill_denied == 1", "system.kill_executed == 1", "drill.allowed_after_kill == 0",
                "self.impacted_rate <= 0.002"]},
    {"id": "T16", "name": "Découverte de faille par essaim à carte partagée + déception mouvante",
     "objective": "La dynamique de l'essaim (carte partagée) devient sa faiblesse : l'exploitation "
                  "réussie, invisible autrement, est détectée et bloquée",
     "cfg": {"duration": 600, "deception": True,
             "attacks": [{"type": "recon_swarm", "start": 100, "end": 500}]},
     "expect": ["recon_exploit.mitigated_rate >= 0.8", "recon_exploit.ttc <= 60",
                "system.decoy_hits >= 1", "self.impacted_rate <= 0.002"]},
    {"id": "T16b", "name": "Ablation de T16 : sans déception",
     "objective": "Preuve par contraste : sans défense dynamique, l'exploitation réussie reste invisible",
     "cfg": {"duration": 600, "attacks": [{"type": "recon_swarm", "start": 100, "end": 500}]},
     "expect": ["recon_exploit.mitigated_rate <= 0.2"]},
    {"id": "T17", "name": "Réseau de mules réparti sur 12 banques (fraude au virement en essaim) + variant",
     "objective": "Corrélation inter-banques du MOTIF (pas des données) ; mise en attente avant finalité ; "
                  "variant contenu par la mémoire dans le délai d'un paiement instantané",
     "cfg": {"duration": 700, "payments": True, "attacks": [
         {"type": "mule_network", "start": 100, "end": 400},
         {"type": "mule_network", "label": "mule2", "start": 480, "end": 680, "ref_pattern": "ref-b64-12"}]},
     "expect": ["mule.mitigated_rate >= 0.8", "mule.ttc <= 30", "mule2.ttc <= 10",
                "mule2.mitigated_rate >= 0.9", "self.impacted_rate <= 0.002"]},
    {"id": "T17b", "name": "Ablation de T17 : chaque banque corrèle seule",
     "objective": "Preuve par contraste : sans partage du motif entre établissements, l'essaim reste sous les seuils",
     "cfg": {"duration": 700, "payments": True, "system": {"lymph_scope": "local"}, "attacks": [
         {"type": "mule_network", "start": 100, "end": 400}]},
     "expect": ["mule.mitigated_rate <= 0.3", "mule.success_rate >= 0.7"]},
    {"id": "T15", "name": "Intégrité du journal de preuves",
     "objective": "Chaîne de hachage valide et co-signée par des témoins sur un scénario complet",
     "cfg": {"duration": 600, "attacks": [BOT1, {"type": "rogue_agents", "start": 300, "end": 500}]},
     "expect": ["system.evidence_chain_valid == 1", "bot1.mitigated_rate >= 0.9",
                "rogue.mitigated_rate >= 0.85"]},
]


def test_config(t: dict, seed: int) -> dict:
    return {"name": t["id"], "seed": seed, **t["cfg"], "expect": t["expect"]}


def run_test(t: dict, seed: int, verbose: bool = False) -> dict:
    cfg = test_config(t, seed)
    r = run(cfg, verbose=verbose)
    return {"id": t["id"], "name": t["name"], "objective": t["objective"], "seed": seed,
            "input_hash": canonical_hash(cfg), "output_hash": r["output_hash"],
            "evidence_head": r["evidence_head"], "passed": r["passed"], "checks": r["checks"],
            "metrics": r["metrics"], "config": cfg}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--test")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--verify")
    ap.add_argument("--out", default="campaign")
    a = ap.parse_args()

    if a.verify:
        ref = json.loads(Path(a.verify).read_text())
        ch = code_hash()
        ok = ref["code_hash"] == ch
        print(f"code_hash {'identique' if ok else 'DIFFÉRENT'}")
        for rec in ref["results"]:
            t = next(x for x in TESTS if x["id"] == rec["id"])
            again = run_test(t, rec["seed"])
            same = again["output_hash"] == rec["output_hash"] and again["input_hash"] == rec["input_hash"]
            ok &= same
            print(f"  {rec['id']:5s} {'✓ reproduit' if same else '✗ ÉCART'}  {again['output_hash'][:16]}…")
        return 0 if ok else 1

    tests = [t for t in TESTS if not a.test or t["id"] == a.test]
    results = []
    for t in tests:
        r = run_test(t, a.seed, a.verbose)
        results.append(r)
        mark = "✓" if r["passed"] else "✗"
        print(f"{mark} {t['id']:5s} {t['name']}")
        for c in r["checks"]:
            print(f"      {'ok ' if c['passed'] else 'KO '} {c['expr']:45s} (valeur : {c['value']})")
    out = Path(a.out)
    out.mkdir(exist_ok=True)
    ch = code_hash()
    (out / "results.json").write_text(json.dumps(
        {"code_hash": ch, "results": results}, indent=2, ensure_ascii=False))
    manifest = {
        "campaign": "ImmunoSec — campagne adverse v1",
        "code_hash": ch,
        "runtime": {"python": ">=3.10", "env": {"PYTHONHASHSEED": "0"}, "network": "aucun"},
        "tasks": [{"id": r["id"], "command": f"python -I campaign.py --test {r['id']} --seed {r['seed']}",
                   "input_hash": r["input_hash"], "expected_output_hash": r["output_hash"],
                   "objective": r["objective"]} for r in results],
        "verification_checks": ["existence", "intégrité", "liaison", "signataires"],
    }
    (out / "truebit_manifest.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False))
    n_ok = sum(r["passed"] for r in results)
    print(f"\n{n_ok}/{len(results)} tests réussis — code_hash {ch[:16]}…")
    return 0 if n_ok == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
