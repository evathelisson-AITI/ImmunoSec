# ImmunoSec

**Une infrastructure immunitaire de type ARNm contre les attaques en essaim (bots et agents IA).**
Prototype de recherche open source (Apache-2.0), en Python 3.10+, sans dépendance externe.

> Un vaccin à ARNm ne transporte pas le virus. Il transporte une **instruction** courte, fragile et
> signée, que chaque cellule traduit elle-même pour apprendre à reconnaître la partie **conservée**
> de l'agresseur. ImmunoSec applique ce principe à la défense : chaque nœud reçoit un **transcrit**
> déclaratif, signé par un quorum, à durée de vie limitée. Il le traduit localement en règle de
> filtrage, et la règle se dégrade d'elle-même quand la menace disparaît.

## Pourquoi

Un essaim distribue l'attaque sur des centaines de sources qui restent chacune sous les seuils.
Les défenses par source ne le voient pas, et la réponse humaine arrive trop tard : en 2026, le
temps de propagation le plus court observé est de 27 s (CrowdStrike GTR 2026). Les essaims
d'**agents IA** compliquent encore les choses. Leurs membres ont souvent des identifiants
valides, communiquent par canaux cachés et peuvent saboter leur propre arrêt (AITI, *Innovative
Guardrails for Agentic AI*, 2026).

## Architecture

```
                   ┌──────────── PLAN DE DONNÉES (chaque nœud) ────────────┐
 trafic / actions →│ 1. Passerelle de sortie   bail HOROS valide ? ODD ?   │→ bloque (inné)
                   │ 2. Ribosome               transcrits actifs → riposte  │→ bloque/défie/quarantaine
                   │ 3. Capteur de danger      dommage + rareté → présente  │
                   └──────────────────────────────┬─────────────────────────┘
                                                  ▼
 ┌──────────────────────── PLAN DE CONTRÔLE (aucun privilège root) ────────────────────────┐
 │ Ganglion → antigène → Mémoire? → Transcrit → Thymus → Quorum 2/3 vérificateurs          │
 │   → Canari (+ confinement intérimaire ailleurs) → Déploiement → Pharmacovigilance       │
 │   → Maturation / Retrait → Rappel ou Dégradation (TTL) → Cellule mémoire                │
 │ Journal de preuves chaîné, co-signé par des témoins indépendants                        │
 └─────────────────────────────────────────────────────────────────────────────────────────┘
```

| Biologie | ImmunoSec | Module |
|---|---|---|
| Peau, muqueuses | Passerelle de sortie, baux HOROS, règle de coalition descendante | `horos.py` |
| Immunité innée, signaux de danger | Capteurs locaux (dommage **et** rareté) | `sensors.py` |
| Ganglion, présentation d'antigène | Corrélation multi-nœuds, extraction de l'épitope conservé | `lymph.py` |
| ARNm | Transcrit déclaratif, versionné, TTL | `mrna.py` |
| Nanoparticule lipidique | Capsule signée par un quorum k-sur-n | `mrna.py` |
| Thymus (sélection négative) | Test du transcrit contre le corpus du « soi » | `thymus.py` |
| Ribosome | Traduction locale en règle, anti-rejeu, mode dégradé | `ribosome.py` |
| Essai clinique | Canari + défis témoins | `system.py` |
| Pharmacovigilance | Mesure des dommages collatéraux après déploiement | `system.py` |
| Maturation d'affinité | Exclusion apprise qui sépare légitimes et attaquants | `system.py` |
| Cellules mémoire, vaccin polyvalent | Réponse secondaire sur la région conservée | `memory.py` |
| Dégradation de l'ARNm | Expiration automatique, rappel si l'essaim persiste | `system.py` |

## Robustesse pendant la réparation

On est le plus vulnérable dans la fenêtre entre la détection et le correctif. Chaque mécanisme
ci-dessous est éprouvé par un test de la campagne.

| Menace sur le processus de réparation | Contre-mesure | Test |
|---|---|---|
| Fenêtre d'exposition pendant le canari | Confinement intérimaire (limitation de débit) sur les autres nœuds | T02 |
| Panne de l'orchestrateur | Mode dégradé : les règles ne se dégradent pas, grâce bornée | T11, T11b (ablation) |
| Perte de vérificateurs | Quorum 2-sur-3 ; sans quorum, rien n'est diffusé (sûreté d'abord) | T09, T10 |
| Inondation du ganglion | Contre-pression par nœud ; les champs diversifiés ne servent pas de graines | T06 |
| Tempête de transcrits | Fusion polyvalente + disjoncteur (≤ 4 nouvelles lignées/min) | T07 |
| Auto-immunité provoquée | Thymus, puis pharmacovigilance, puis maturation automatique | T05 |
| Capsule forgée, clé volée, rejeu | Quorum de signatures et versions monotones | T08 |
| Orchestrateur compromis | Aucune clé dans l'orchestrateur ; les vérificateurs refusent un transcrit auto-immun | T13 |
| Abus du kill switch | Approbation humaine 2-sur-3 | T14 |
| Agents compromis à bail valide | Quarantaine, révocation de bail, pause de la cohorte | T12 |
| Effacement des traces | Journal chaîné et co-signé (« bloquer d'abord, préserver la preuve ensuite ») | T15 |

## Règlement bancaire

Pour les paiements, le transcrit ne rejette jamais un virement sec : il le **met en attente avant
finalité** (`hold`) jusqu'à confirmation du client par un canal indépendant. Les banques partagent le
**motif** de l'essaim (montant juste sous le seuil, bénéficiaire nouveau, schéma de référence), jamais
les transactions. Une souche proche d'une souche connue est reconnue avec moins de sources (mémoire
« amorcée »), ce qui tient le délai d'un paiement instantané.

## Reconnaissance par les États

La licence d'État devient la racine de la chaîne de confiance : autorité nationale → opérateur licencié
→ baux de ses agents. Chaque pays choisit de réguler lui-même, de s'appuyer sur l'organisation
internationale qui accrédite les autorités nationales, ou de rester en dehors (ses agents sont alors
traités comme non licenciés par les passerelles). Les licences sont des certificats signés, reconnus
mutuellement, révoqués et propagés comme des transcrits. Détails dans le white paper.

## Pas d'accès root

Aucun composant ne peut agir seul, et c'est vérifié par les tests :
- l'**orchestrateur** ne détient aucune clé de signature : il ne peut que demander des signatures ;
- chaque **vérificateur** rejoue la sélection thymique sur sa propre vue du soi et refuse de signer un
  transcrit qui toucherait le trafic légitime ;
- les **nœuds** n'exécutent jamais de code reçu : ils traduisent une description déclarative ;
- l'**autorité des baux** applique la coalition descendante : un enfant n'a jamais plus de droits que son parent ;
- le **kill switch** exige k approbations humaines distinctes ;
- les **agents défensifs** sont eux-mêmes soumis aux baux, au journal et au quorum.

## Démarrer

```bash
python -I simulate.py              # démonstration narrée (1 300 s simulées, ~5 s réelles)
python -I campaign.py              # campagne adverse T01–T17 → campaign/results.json + manifeste
python -I campaign.py --test T05 -v
python -I campaign.py --verify campaign/results.json   # ré-exécution indépendante, comparaison des hashes
```
Utilisez `PYTHONHASHSEED=0` pour une reproductibilité bit à bit. La CI GitHub
(`.github/workflows/campaign.yml`) rejoue la campagne et vérifie les hashes publiés à chaque push.

## Résultats (graine 42)

| Test | Résultat clé |
|---|---|
| T02 essaim low & slow | 99,3 % neutralisé, confinement en 12 s, 0 compte compromis |
| T03 variant muté | confinement en **1 s** par la mémoire |
| T05 collision provoquée | maturation automatique, trafic légitime impacté 3,1 % (contre 73 % sans maturation) |
| T11 / T11b panne du plan de contrôle | 99,7 % avec mode dégradé, contre 80,6 % sans |
| T12 agents compromis | 96 % neutralisés, 80 baux révoqués, cohorte mise en pause |
| T13 orchestrateur compromis | 0 transcrit malveillant diffusé |
| T16 / T16b essaim à carte partagée | 99,1 % bloqué avec leurres mouvants, 0 % sans |
| T17 / T17b réseau de mules sur 12 banques | 98 % des virements frauduleux mis en attente (variant : 6 s, sous la limite SCT Inst de 10 s), contre 17 % si chaque banque corrèle seule |
| Trafic légitime (tous tests) | ≤ 0,12 % impacté (des agents mal configurés hors de leur ODD) |

## Limites connues

- **Mimétisme parfait (T04)** : un essaim identique au soi n'a pas d'épitope. La couche adaptative
  ne réagit volontairement pas. La défense relève alors de l'identité (WebAuthn, limites par compte).
- Le **défi témoin** est modélisé par un oracle. En production, ce sont des CAPTCHA/WebAuthn pour les
  humains et une ré-attestation TEE avec confirmation humaine pour les agents.
- Les signatures HMAC du prototype sont à remplacer par Ed25519 ou des signatures à seuil, avec des
  clés en HSM/TEE détenues par des organisations distinctes.
- Monde simulé : à valider sur du trafic réel rejoué avant tout déploiement.

## Correspondance avec les référentiels

OWASP Top 10 for Agentic Applications 2026 (ASI01–ASI10, principe de « moindre agence ») ;
NIST IR 8596 *Cyber AI Profile* (Secure / Defend / Thwart) ; pratiques NIST, CISA et NSA
de réponse aux incidents d'agents IA (2026) ; MITRE ATLAS (techniques agentiques) ; AITI,
*Innovative Guardrails for Agentic AI* (2026) et annexe Truebit × MCP Registry.

## Licence

Apache-2.0 (voir `LICENSE`). Divulgation de vulnérabilités : voir `SECURITY.md`.
