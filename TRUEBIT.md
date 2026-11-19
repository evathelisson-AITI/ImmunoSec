# Campagne de tests vérifiables — protocole

Objectif : chaque affirmation de robustesse d'ImmunoSec doit pouvoir être **revérifiée par un tiers
qui ne fait pas confiance aux auteurs**. Le protocole reprend la méthode de l'expérience
Truebit × MCP Registry publiée en annexe du livre blanc AITI (oct. 2026) : instantané figé par
hash, graine publique, exécution vérifiée sur des nœuds indépendants qui doivent concorder,
transcrits signés et quatre contrôles (existence, intégrité, liaison, signataires).

## 1. Ce qui est figé

| Élément | Empreinte | Où |
|---|---|---|
| Code du banc et de la défense | `code_hash` (SHA-256 de `immunosec/*.py`) | `campaign/truebit_manifest.json` |
| Configuration de chaque test | `input_hash` (JSON canonique) | idem |
| Résultat attendu | `expected_output_hash` (métriques + tête du journal de preuves) | idem |
| Environnement | Python ≥ 3.10, `PYTHONHASHSEED=0`, aucun accès réseau | idem |

## 2. Série de tests proposée

| Phase | Tests | Ce qui est démontré |
|---|---|---|
| A — Ligne de base | T01, T04 | Absence d'auto-immunité, limite documentée |
| B — Essaims | T02, T03, T06, T07, T16, T16b | Détection, mémoire, résistance à l'inondation et à la tempête |
| C — Processus de réparation | T05, T08, T09, T10, T11, T11b | Pharmacovigilance, intégrité de la diffusion, pannes |
| D — Agents IA et paiements | T12, T14, T17, T17b | Quarantaine, kill switch multipartite, mise en attente avant finalité, corrélation inter-banques |
| E — Pas d'accès root, preuve | T13, T15 | Orchestrateur compromis, journal inaltérable |
| F — Robustesse statistique | T01–T15 × 30 graines publiques | Distribution des métriques, pas un seul tirage favorable |
| G — Red team ouverte | stratégies soumises par des tiers | Le défenseur ne choisit pas les attaques |

Pour la phase F, la graine de chaque série devrait provenir d'une source publique postérieure au
gel du code (par exemple une balise d'aléa publique). Le défenseur ne peut alors pas choisir de
graines favorables.

Pour la phase G, des tiers soumettent une stratégie (classe dérivée d'`adversary.Attack`). Elle est
figée par son hash avant exécution, et les résultats sont publiés quels qu'ils soient.

## 3. Exécution vérifiée

1. Publier `truebit_manifest.json` et l'archive du code. Le hash de l'archive doit correspondre à `code_hash`.
2. Soumettre chaque tâche (`python -I campaign.py --test Txx --seed N`) comme calcul vérifié, exécuté
   par **plusieurs nœuds indépendants**, dont au moins un hors de la juridiction de l'éditeur.
3. Chaque nœud produit un transcrit signé liant (code_hash, input_hash) → output_hash.
4. Contrôles :
   - **existence** : un transcrit existe pour chaque tâche du manifeste ;
   - **intégrité** : les hashes recalculés correspondent ;
   - **liaison** : l'output_hash est lié au code_hash et à l'input_hash déclarés ;
   - **signataires** : les signatures correspondent aux ancres de confiance publiées.
5. Tout écart entre nœuds signale une non-reproductibilité ou une fraude. La tâche est alors marquée
   « non vérifiée » et n'est pas comptée.

Contrôle local équivalent (sans réseau) : `python -I campaign.py --verify campaign/results.json`.

## 4. Ce que la vérification prouve, et ce qu'elle ne prouve pas

Elle prouve que les résultats publiés sont bien ceux que produit ce code sur ces scénarios, sans
retouche. Elle ne prouve **pas** que les scénarios sont représentatifs du monde réel. D'où les
phases F et G, et la nécessité de rejouer ensuite du trafic réel anonymisé.
