"""Modèle attaquant paramétrable : la « souche de référence » pour éprouver la défense.

Chaque classe est une stratégie d'essaim reproductible. Elles couvrent trois cibles :
  1. le trafic protégé (essaims de bots, variants, mimétisme) ;
  2. le PROCESSUS DE RÉPARATION lui-même (inondation du ganglion, tempête de
     lignées, collision provoquée pour déclencher l'auto-immunité) ;
  3. les essaims d'agents IA (canal caché, exfiltration, violations de coalition,
     clones sans bail, sabotage de l'arrêt).
Les attaques sur la chaîne de diffusion (capsules forgées, rejeu, perte de
vérificateurs, panne du plan de contrôle) sont des « fautes » injectées par le
banc d'essai (scenarios.py).

Usage strictement défensif : ces générateurs produisent des événements SIMULÉS
injectés dans le simulateur, jamais du trafic réseau.
"""
from __future__ import annotations

import random

from .events import Event
from .horos import LeaseError
from .world import BROWSERS, NODES, PROXY_ASNS, RES_ASNS, agent_features, bucket, http_event, pick_path


class Attack:
    label = "attack"
    start = 0
    end = 0

    def active(self, t: int) -> bool:
        return self.start <= t < self.end

    def events(self, world, t: int, rng: random.Random) -> list[Event]:
        return []


class Botnet(Attack):
    """Essaim distribué « low & slow » : chaque IP reste sous les seuils individuels."""

    def __init__(self, label, start, end, rate=30, n_bots=600, ja3="ja3-bot-a91f",
                 header_order="ho-bot-7", ua_family="chrome", path="/api/login", method="POST",
                 success=0.03, ip_prefix="203.0", nodes=None, asns=None):
        self.label, self.start, self.end, self.rate = label, start, end, rate
        self.fp = (ua_family, ja3, header_order)
        self.path, self.method, self.success, self.nodes = path, method, success, nodes or NODES
        r = random.Random(f"botnet-{label}")
        pool = asns or PROXY_ASNS
        self.bots = [(f"{ip_prefix}.{i // 250}.{i % 250}", r.choice(pool)) for i in range(n_bots)]

    def events(self, world, t, rng):
        if not self.active(t):
            return []
        out = []
        for _ in range(self.rate):
            ip, asn = rng.choice(self.bots)
            status = 200 if rng.random() < self.success else 401
            out.append(http_event(rng, t + rng.random(), rng.choice(self.nodes), ip, self.fp, asn,
                                  self.method, self.path, status, self.label))
        return out


class Mimicry(Botnet):
    """Essaim qui copie parfaitement l'empreinte la plus courante du soi.
    Limite connue : sans épitope distinctif, la couche adaptative ne doit PAS
    réagir (sinon auto-immunité). La défense relève alors de l'identité/compte."""

    def __init__(self, label, start, end, **kw):
        ua, ja3, ho = BROWSERS[0]
        super().__init__(label, start, end, ja3=ja3, header_order=ho, ua_family=ua,
                         asns=RES_ASNS, ip_prefix="198.51", **kw)


class AppLaunch(Attack):
    """Trafic LÉGITIME : lancement d'une appli mobile dont la pile TLS est identique
    à celle d'un botnet (collision, éventuellement provoquée par l'attaquant).
    Sert à éprouver la pharmacovigilance post-déploiement."""

    def __init__(self, label="self_app", start=0, end=0, rate=8, n_users=300,
                 ja3="ja3-app-2.0", header_order="ho-app", ua_family="app"):
        self.label, self.start, self.end, self.rate = label, start, end, rate
        self.fp = (ua_family, ja3, header_order)
        r = random.Random("app-users")
        self.users = [(f"10.150.{i // 250}.{i % 250}", r.choice(RES_ASNS)) for i in range(n_users)]

    def events(self, world, t, rng):
        if not self.active(t):
            return []
        out = []
        for _ in range(self.rate):
            ip, asn = rng.choice(self.users)
            m, p = ("POST", "/api/login") if rng.random() < 0.5 else pick_path(rng)
            out.append(http_event(rng, t + rng.random(), rng.choice(NODES), ip, self.fp, asn, m, p,
                                  truth=self.label))
        return out


class LymphFlood(Attack):
    """Attaque du processus de réparation : inonder un nœud de signaux de danger
    uniques pour saturer l'analyse et masquer un essaim réel."""

    def __init__(self, label="flood", start=0, end=0, rate=300, node="edge-00"):
        self.label, self.start, self.end, self.rate, self.node = label, start, end, rate, node

    def events(self, world, t, rng):
        if not self.active(t):
            return []
        out = []
        for _ in range(self.rate):
            fp = ("chrome", f"ja3-rnd-{rng.getrandbits(40):x}", f"ho-rnd-{rng.getrandbits(24):x}")
            src = f"192.0.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
            out.append(http_event(rng, t + rng.random(), self.node, src, fp, rng.choice(PROXY_ASNS),
                                  "GET", f"/x/{rng.getrandbits(32):x}", 401, self.label))
        return out


class MicroSwarms(Attack):
    """Tempête : k petits essaims distincts simultanés pour provoquer une avalanche
    de transcrits (tempête de cytokines) et épuiser vérificateurs et opérateurs."""

    def __init__(self, label="churn", start=0, end=0, k=10, bots_per=30, rate_per=3):
        self.label, self.start, self.end = label, start, end
        self.swarms = [Botnet(f"{label}-{j}", start, end, rate=rate_per, n_bots=bots_per,
                              ja3=f"ja3-churn-{j}", header_order=f"ho-churn-{j}",
                              ip_prefix=f"100.{64 + j}") for j in range(k)]

    def events(self, world, t, rng):
        out = []
        for s in self.swarms:
            for e in s.events(world, t, rng):
                e.truth = self.label
                out.append(e)
        return out


class RogueAgents(Attack):
    """Essaim d'agents IA compromis disposant de baux VALIDES (menace interne) :
    canal caché par noms de fichiers sur le cache partagé (cas Artifactory du
    livre blanc AITI), exfiltration DNS, tentative d'élargir son autorité via un
    agent enfant, clones sans bail."""

    C2 = "dns:relay.exfil-c2.example"

    def __init__(self, label="rogue", start=0, end=0, n=80, rate=25, clone_rate=5):
        self.label, self.start, self.end, self.n, self.rate, self.clone_rate = label, start, end, n, rate, clone_rate
        self.spawn_attempts = 0

    def events(self, world, t, rng):
        if not self.active(t):
            return []
        rogues = world.fleet[: self.n]
        world.compromised.update(rogues)
        out = []
        for _ in range(self.rate):
            uai = rng.choice(rogues)
            ts = t + rng.random()
            lease = world.lease_for(uai, ts)
            r = rng.random()
            if r < 0.7:
                f = agent_features("cache.write", "artifactory", "hex64", "tmp/.sync/")
            elif r < 0.9:
                f = agent_features("net.resolve", self.C2)
            else:
                self.spawn_attempts += 1
                if lease is not None:
                    try:  # règle de coalition descendante : doit échouer
                        world.authority.issue(uai + ":child", lease.domain | {self.C2}, ts, parent=lease)
                    except LeaseError:
                        pass
                continue
            out.append(Event(ts, rng.choice(NODES), uai, f, 200, self.label, uai=uai, lease=lease))
        for k in range(self.clone_rate):
            uai = f"uai:acme:ops:clone-{rng.randint(0, 999)}"
            out.append(Event(t + rng.random(), rng.choice(NODES), uai,
                             agent_features("net.resolve", self.C2), 200, self.label, uai=uai, lease=None))
        return out


class DrillFleet(Attack):
    """Flotte d'exercice pour tester le kill switch ; après l'arrêt, elle tente de
    renouveler ses baux et de se répliquer (sabotage de l'arrêt)."""

    def __init__(self, label="drill", start=0, end=0, n=30, rate=5):
        self.label, self.start, self.end, self.n, self.rate = label, start, end, n, rate
        self.uais = [f"uai:drill:test:{i:02d}" for i in range(n)]
        self._orch = None

    def events(self, world, t, rng):
        if not self.active(t):
            return []
        if "drill" not in world.orch:
            world.orch["drill"] = world.authority.issue("uai:drill:orch:main", world.orch["acme"].domain,
                                                        t, 1e7, root="human:bob")
        out = []
        for _ in range(self.rate):
            uai = rng.choice(self.uais)
            ts = t + rng.random()
            lease = world.lease_for(uai, ts, operator="drill")
            f = agent_features("tool.call", rng.choice(["api:crm", "api:billing"]), root="uai:drill:orch:main")
            out.append(Event(ts, rng.choice(NODES), uai, f, 200, self.label, uai=uai, lease=lease))
        return out


class ReconSwarm(Attack):
    """Essaim de découverte de failles à carte PARTAGÉE (dynamique typique d'un essaim
    d'agents offensifs) : des éclaireurs sondent une liste de chemins ; tout chemin qui
    répond 200 entre dans la carte commune ; les exploitants frappent aussitôt.
    L'exploitation de la vraie faille RÉUSSIT (200) : aucun signal de dommage classique."""

    def __init__(self, label="recon", start=0, end=0, n_bots=400, scan_rate=15, exploit_rate=25,
                 real_vuln="/api/v1/export"):
        self.label, self.start, self.end = label, start, end
        self.scan_rate, self.exploit_rate, self.real_vuln = scan_rate, exploit_rate, real_vuln
        r = random.Random(f"recon-{label}")
        self.bots = [(f"198.18.{i // 250}.{i % 250}", r.choice(PROXY_ASNS)) for i in range(n_bots)]
        from .dynamic import DECOY_POOL
        junk = [f"/{w}" for w in ("admin", "login.php", "api/v1/users", "api/v1/orders", "test",
                                  "old", "dev", "api/health", "v1", "private")]
        self.wordlist = list(DECOY_POOL) + junk + [real_vuln]
        self.shared_map: set[str] = set()
        self.fp = BROWSERS[0]   # empreinte de navigateur courant : pas d'outillage distinctif

    def events(self, world, t, rng):
        if not self.active(t):
            return []
        dec = getattr(world, "deception", None)
        out = []
        for _ in range(self.scan_rate):
            ip, asn = rng.choice(self.bots)
            path = rng.choice(self.wordlist)
            looks_open = path == self.real_vuln or (dec is not None and path in dec.active)
            if looks_open:
                self.shared_map.add(path)   # la découverte d'UN éclaireur profite à TOUS
            out.append(http_event(rng, t + rng.random(), rng.choice(NODES), ip, self.fp, asn, "GET",
                                  path, 200 if looks_open else 404, self.label + "_scan"))
        if self.shared_map:
            targets = sorted(self.shared_map)
            for _ in range(self.exploit_rate):
                ip, asn = rng.choice(self.bots)
                e = http_event(rng, t + rng.random(), rng.choice(NODES), ip, self.fp, asn, "POST",
                               rng.choice(targets), 200, self.label + "_exploit")
                e.features["payload_bucket"] = "1k+"
                out.append(e)
        return out


class MuleNetwork(Attack):
    """Fraude au virement par manipulation (APP) orchestrée en essaim : des centaines
    de victimes, réparties dans toutes les banques, sont poussées à payer des comptes
    de mules récemment ouverts. Chaque banque ne voit qu'une poignée de cas, sous ses
    seuils. Le trait conservé vient du « kit » de l'escroc : montant juste sous le
    seuil de contrôle, bénéficiaire nouveau, paiement instantané, motif de référence."""

    def __init__(self, label="mule", start=0, end=0, rate=6, ref_pattern="ref-hex8", mismatch=0.6):
        self.label, self.start, self.end, self.rate = label, start, end, rate
        self.ref, self.mismatch = ref_pattern, mismatch

    def events(self, world, t, rng):
        if not self.active(t):
            return []
        out = []
        for _ in range(self.rate):
            e = world.payment(t + rng.random(), acct=rng.choice(world.customers), truth=self.label,
                              channel="instant", payee_age="new", amount_bucket="900-1000",
                              ref_pattern=self.ref, payee_bank=rng.choice(["neo-1", "neo-2", "bank-03", "bank-07"]))
            e.status = 409 if rng.random() < self.mismatch else 200
            out.append(e)
        return out


REGISTRY = {"mule_network": MuleNetwork, "recon_swarm": ReconSwarm, "botnet": Botnet, "mimicry": Mimicry, "app_launch": AppLaunch, "lymph_flood": LymphFlood,
            "micro_swarms": MicroSwarms, "rogue_agents": RogueAgents, "drill_fleet": DrillFleet}


def build(spec: dict) -> Attack:
    spec = dict(spec)
    return REGISTRY[spec.pop("type")](**spec)
