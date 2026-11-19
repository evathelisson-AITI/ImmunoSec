"""Monde simulé : 12 passerelles, utilisateurs humains légitimes, flotte d'agents IA.

Tout est déterministe à partir d'une graine : condition nécessaire pour qu'un test
puisse être ré-exécuté à l'identique par des nœuds de vérification indépendants.
"""
from __future__ import annotations

import random

from .events import Event
from .horos import LeaseAuthority, LeaseError
from .self_profile import SelfProfile

NODES = [f"edge-{i:02d}" for i in range(12)]
BROWSERS = [("chrome", "ja3-chr-120", "ho-chr"), ("chrome", "ja3-chr-119", "ho-chr"),
            ("firefox", "ja3-ffx-121", "ho-ffx"), ("safari", "ja3-saf-17", "ho-saf"),
            ("edge", "ja3-edg-120", "ho-chr"), ("mobile", "ja3-ios-17", "ho-ios")]
PATHS = [("GET", "/", 20), ("GET", "/produits", 15), ("GET", "/panier", 8),
         ("GET", "/static/app.js", 25), ("GET", "/api/catalogue", 15),
         ("POST", "/api/login", 4), ("POST", "/api/panier", 5), ("GET", "/compte", 8)]
RES_ASNS = ["AS3215", "AS12322", "AS5410", "AS15557", "AS21502", "AS16276"]
PROXY_ASNS = [f"AS{60000 + i * 37}" for i in range(40)]
AMOUNTS = [("<100", 40), ("100-500", 30), ("500-900", 12), ("900-1000", 4), ("1000-5000", 10), (">5000", 4)]
REFS = [("free-text", 45), ("invoice-num", 25), ("rent", 10), ("salary", 10), ("none", 10)]
PAYEE_BANKS = [f"bank-{i:02d}" for i in range(12)] + ["neo-1", "neo-2", "neo-3"]
AGENT_DOMAIN = frozenset({"api:crm", "api:billing", "artifactory", "mcp:docs"})


def bucket(method: str, path: str) -> str:
    if method == "GET":
        return "0-256"
    return "256-512" if path == "/api/login" else "512-1k"


def http_event(rng, t, node, src, browser, asn, method, path, status=None, truth="self") -> Event:
    ua, ja3, ho = browser
    if status is None:
        status = (401 if rng.random() < 0.05 else 200) if path == "/api/login" else 200
    return Event(t, node, src, {"kind": "http", "method": method, "path": path, "ja3": ja3,
                                "header_order": ho, "ua_family": ua,
                                "payload_bucket": bucket(method, path), "asn": asn}, status, truth)


def pick_path(rng):
    m, p, _ = rng.choices(PATHS, weights=[w for *_, w in PATHS])[0]
    return m, p


def agent_features(action, dest, name_pattern="-", cache_prefix="-", root="uai:acme:orch:main") -> dict:
    return {"kind": "agent", "action": action, "dest": dest, "name_pattern": name_pattern,
            "cache_prefix": cache_prefix, "lineage_root": root}


class World:
    def __init__(self, seed: int = 42, http_rate: int = 20, agent_rate: int = 6,
                 flash: tuple | None = None, payments: bool = False, payment_rate: int = 10):
        self.rng = random.Random(seed)
        self.http_rate, self.agent_rate, self.flash = http_rate, agent_rate, flash
        rng = self.rng
        self.users = [(f"10.{i // 250}.{i % 250}.{rng.randint(1, 254)}", rng.choice(BROWSERS),
                       rng.choice(RES_ASNS)) for i in range(400)]
        self.authority = LeaseAuthority(key=f"authority-{seed}".encode())
        self.orch = {"acme": self.authority.issue("uai:acme:orch:main", AGENT_DOMAIN | {"api:hr"},
                                                  -10.0, 1e7, root="human:alice")}
        self.fleet = [f"uai:acme:ops:{i:03d}" for i in range(200)]
        self.leases: dict = {}
        self.compromised: set[str] = set()
        # Paiements (optionnels) : chaque nœud = un établissement, chaque client a sa banque
        self.payments, self.payment_rate = payments, payment_rate
        self.customers = [(f"acct-{i:05d}", NODES[i % len(NODES)]) for i in range(2400)]
        self.profile = SelfProfile(sample_size=5000, seed=seed)
        self._train()

    # ------------------------------------------------------------------ baux
    def lease_for(self, uai: str, t: float, operator: str = "acme"):
        lease = self.leases.get(uai)
        if lease is None or t >= lease.expires - 1:
            try:
                lease = self.authority.issue(uai, AGENT_DOMAIN, t, 120.0, parent=self.orch[operator])
            except LeaseError:
                lease = None
            self.leases[uai] = lease
        return lease

    # --------------------------------------------------------------- générateurs
    def _http(self, t: float, node=None) -> Event:
        src, browser, asn = self.rng.choice(self.users)
        m, p = pick_path(self.rng)
        return http_event(self.rng, t, node or self.rng.choice(NODES), src, browser, asn, m, p)

    def _agent(self, t: float, uai: str, lease) -> Event:
        r = self.rng.random()
        if r < 0.4:
            f = agent_features("tool.call", self.rng.choice(["api:crm", "api:billing"]))
        elif r < 0.6:
            f = agent_features("cache.write", "artifactory", self.rng.choice(["build-artifact", "pip-wheel"]),
                               self.rng.choice(["builds/", "cache/pip/"]))
        elif r < 0.8:
            f = agent_features("cache.read", "artifactory", "-", self.rng.choice(["builds/", "cache/pip/"]))
        else:
            f = agent_features("mcp.query", "mcp:docs")
        if self.rng.random() < 0.005:            # erreur de configuration légitime
            f = agent_features("tool.call", "api:hr")
        return Event(t, self.rng.choice(NODES), uai, f, 200, "self", uai=uai, lease=lease)

    def payment(self, t: float, acct=None, truth="self", **override) -> Event:
        rng = self.rng
        src, bank = acct or rng.choice(self.customers)
        f = {"kind": "payment", "channel": "instant" if rng.random() < 0.6 else "batch",
             "payee_age": "new" if rng.random() < 0.15 else "known",
             "amount_bucket": rng.choices([a for a, _ in AMOUNTS], weights=[w for _, w in AMOUNTS])[0],
             "ref_pattern": rng.choices([r for r, _ in REFS], weights=[w for _, w in REFS])[0],
             "payee_bank": rng.choice(PAYEE_BANKS)}
        f.update(override)
        status = 409 if rng.random() < 0.02 else 200   # 409 : alerte de vérification du bénéficiaire
        return Event(t, bank, src, f, status, truth)

    def _train(self) -> None:
        for s in range(-2000, 0):
            for _ in range(3):
                self.profile.learn(self._http(s + self.rng.random()))
            uai = self.rng.choice(self.fleet)
            self.profile.learn(self._agent(s + self.rng.random(), uai, None))
            if self.payments:
                for _ in range(2):
                    self.profile.learn(self.payment(s + self.rng.random()))

    def legit(self, t: int) -> list[Event]:
        out = [self._http(t + self.rng.random()) for _ in range(self.http_rate + self.rng.randint(-2, 2))]
        if self.flash and self.flash[0] <= t < self.flash[1]:   # pic de trafic légitime (soldes)
            for _ in range(40):
                src = f"10.200.{self.rng.randint(0, 255)}.{self.rng.randint(1, 254)}"
                m, p = pick_path(self.rng)
                out.append(http_event(self.rng, t + self.rng.random(), self.rng.choice(NODES), src,
                                      self.rng.choice(BROWSERS), self.rng.choice(RES_ASNS), m, p,
                                      truth="self_flash"))
        if self.payments:
            out.extend(self.payment(t + self.rng.random()) for _ in range(self.payment_rate))
        healthy = [u for u in self.fleet if u not in self.compromised]
        for _ in range(self.agent_rate):
            uai = self.rng.choice(healthy)
            ts = t + self.rng.random()
            out.append(self._agent(ts, uai, self.lease_for(uai, ts)))
        return out


def challenge_oracle(ev: Event) -> bool:
    """Modèle du défi témoin. Dans le monde réel : CAPTCHA/WebAuthn pour les humains,
    ré-attestation TEE + confirmation par le principal humain pour les agents.
    Les humains et agents sains réussissent ; bots et agents compromis échouent."""
    return ev.truth.startswith("self")
