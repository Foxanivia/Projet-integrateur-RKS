<div align="center">

# Etat de l'art:

## RKS et Cryptographie embarquée

</div>

**Auteurs:** Loïc TESTA et Lucas MARACINE  
*Date:* _07/04/2024_  
**Dernière édition:** 03/06/2024


---

## Introduction 

<div style="text-align: justify;">
Dans le domaine de la cryptographie embarquée, les systèmes de contrôle d'accès et de démarrage sans clé (RKS) jouent un rôle crucial dans la sécurité des véhicules modernes.
Ces systèmes reposent sur des technologies avancées qui permettent aux utilisateurs de verrouiller, déverrouiller et démarrer leur véhicule sans avoir à utiliser une clé physique traditionnelle.
Cependant, cette commodité s'accompagne de défis en matière de sécurité, notamment en ce qui concerne la vulnérabilité aux attaques.
</div>


## Code fixe et Code tournant

Les systèmes de télécommande sans clé (RKE - Remote Keyless Entry) utilisent généralement deux types de codes pour l'authentification et l'autorisation : le code fixe et le code tournant.

- Code fixe : Le code fixe est un code unique et statique qui est envoyé à chaque fois que la télécommande est utilisée. Ce type de code est vulnérable aux attaques par enregistrement et relecture (replay attack), où un attaquant peut enregistrer le signal et le rejouer pour accéder au véhicule.
- Code tournant (Rolling Code) : Le code tournant utilise un algorithme pour générer un nouveau code pour chaque transmission. Les deux dispositifs (la télécommande et le récepteur dans le véhicule) doivent être synchronisés pour utiliser le même algorithme. Cette technique améliore la sécurité en empêchant les attaques par enregistrement et relecture.

### Code tournant 

Voici quelque exemple de code tournant courament utilisées: 

- KeeLoq

#### KeeLoq

- Taille du Bloc: 32bits 
- Taille de la clé: 64bits
- Nombre de tours: 528 

#### AES-Based 

#### Hmac-Based

## Protocole Hitag 

## Système RKE mono et bidirectionnel 

## Modulation des signaux 

## Attaques possibles 

### Replay 

### RollJam

### RollBack 

