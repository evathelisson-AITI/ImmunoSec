# Contribuer

Les contributions sont bienvenues, en particulier de la part des deux communautés que ce projet
veut rapprocher : la cyberdéfense (SOC, CERT, red teams) et la sûreté de l'IA (évaluations,
alignement, gouvernance).

## Règles

1. **Toute affirmation de robustesse s'accompagne d'un test** dans `campaign.py`, avec ses attendus
   (`expect`). Un mécanisme sans test n'est pas fusionné.
2. **Tout mécanisme de défense s'accompagne d'une ablation** : un test qui montre ce qui casse sans lui
   (sur le modèle de T11 et T11b).
3. **Pas d'accès root** : aucune contribution ne doit permettre à un composant unique de diffuser un
   transcrit, d'arrêter un opérateur ou de réécrire le journal.
4. **Déterminisme** : graines explicites, pas de dépendance à l'ordre des ensembles, pas de réseau.
   `python -I campaign.py --verify` doit rester vert.
5. **Usage défensif uniquement** : les stratégies d'`adversary.py` génèrent des événements simulés.
   Les contributions qui produisent du trafic réel ou des charges exploitables sont refusées.
6. Licence : en contribuant, vous acceptez la diffusion sous Apache-2.0 (certificat d'origine DCO,
   `git commit -s`).

## Bons premiers sujets

- Remplacer HMAC par Ed25519 ou des signatures à seuil (FROST).
- Adaptateurs Envoy/Coraza et OPA pour une passerelle MCP réelle.
- Nouvelles stratégies adverses : essaim qui apprend les seuils, empoisonnement lent du soi.
- Correspondance des tests avec les techniques MITRE ATLAS et les catégories OWASP ASI.
