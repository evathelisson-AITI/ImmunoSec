# Politique de sécurité

ImmunoSec est un prototype de recherche. Ne le déployez pas en production sans revue
indépendante, sans remplacer les signatures HMAC de démonstration par des signatures asymétriques
ou à seuil, et sans stocker les clés en HSM/TEE.

## Signaler une vulnérabilité

Ne signalez pas de vulnérabilité dans un ticket public. Utilisez la fonction « Private
vulnerability reporting » du dépôt, ou écrivez aux mainteneurs. Indiquez :
- le composant (passerelle, ganglion, thymus, quorum, ribosome, journal) ;
- un scénario reproductible, idéalement sous forme de stratégie `adversary.Attack` et de configuration JSON ;
- l'impact (contournement, auto-immunité provoquée, déni de service du processus de réparation…).

Nous visons un accusé de réception sous 72 h et une divulgation coordonnée sous 90 jours.
Les stratégies d'attaque reçues rejoignent la campagne de tests (phase G de `TRUEBIT.md`),
avec l'accord de leur auteur et une mention de crédit.

## Périmètre

Dans le périmètre : contournement de la détection, forge ou rejeu de transcrits, attaques du
processus de réparation, escalade de privilèges des agents, altération du journal de preuves.
Hors périmètre : les attaques qui exigent la compromission simultanée d'un quorum de
vérificateurs. C'est l'hypothèse de confiance explicite du système.
