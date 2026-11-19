"""Traduction des transcrits vers des moteurs d'application existants.

Le ribosome intégré sert de référence ; en production, chaque nœud traduit le
transcrit dans SON moteur : WAF (ModSecurity/Coraza), politique OPA/Rego pour une
passerelle d'agents, etc. Le transcrit reste déclaratif : aucun code n'est diffusé.

Prérequis : l'empreinte JA3/JA4, l'ordre des en-têtes, la famille UA et l'ASN doivent
être calculés en bordure (HAProxy, Envoy, CDN) et transmis en en-têtes de confiance.
"""
from __future__ import annotations

import json

from .mrna import Transcript

MODSEC_VARS = {"method": "REQUEST_METHOD", "path": "REQUEST_FILENAME",
               "ja3": "REQUEST_HEADERS:X-JA3", "header_order": "REQUEST_HEADERS:X-Header-Order",
               "ua_family": "REQUEST_HEADERS:X-UA-Family", "payload_bucket": "REQUEST_HEADERS:X-Payload-Bucket",
               "asn": "REQUEST_HEADERS:X-ASN"}


def _modsec_op(v) -> str:
    if isinstance(v, dict):
        return "!@within " + " ".join(v["not"])
    if isinstance(v, list):
        return "@within " + " ".join(v)
    return "@streq " + str(v)


def to_modsecurity(t: Transcript, rule_id: int = 990001) -> str:
    conds = [(k, v) for k, v in t.epitope.items() if k in MODSEC_VARS]
    if not conds:
        return f"# {t.id} : aucun champ HTTP traduisible"
    disrupt = {"block": "deny,status:403", "challenge": "redirect:/challenge",
               "rate_limit": "deny,status:429"}.get(t.action, "pass")
    lines = [f"# ImmunoSec {t.id} — origine {t.origin}, expire à t={t.expires_at:.0f} (TTL {t.ttl:.0f}s)"]
    for i, (k, v) in enumerate(conds):
        head = i == 0
        last = i == len(conds) - 1
        actions = []
        if head:
            actions += [f"id:{rule_id}", "phase:1", disrupt, "log", f"msg:'immunosec {t.id}'"]
        if not last:
            actions.append("chain")
        act = f' "{",".join(actions)}"' if actions else ""
        lines.append(f'{"" if head else "  "}SecRule {MODSEC_VARS[k]} "{_modsec_op(v)}"{act}')
    return "\n".join(lines)


def to_rego(t: Transcript) -> str:
    """Politique OPA (Rego v1) pour une passerelle d'agents / MCP."""
    conds = []
    for k, v in t.epitope.items():
        if isinstance(v, dict):
            conds.append(f"    not input.{k} in {json.dumps(sorted(v['not']))}")
        elif isinstance(v, list):
            conds.append(f"    input.{k} in {json.dumps(v)}")
        else:
            conds.append(f"    input.{k} == {json.dumps(v)}")
    exp_ns = int(t.expires_at * 1e9)
    body = "\n".join(conds)
    return (f"package immunosec.{t.lineage.lower().replace('-', '_')}\n\nimport rego.v1\n\n"
            f"# {t.id} — action {t.action}, expire (horloge du banc) {t.expires_at:.0f}s\n"
            f"deny contains msg if {{\n{body}\n    input.now_ns < {exp_ns}\n"
            f"    msg := \"{t.id}: {t.action}\"\n}}\n")
