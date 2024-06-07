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

Les systèmes de clé électronique utilisent couramment des codes tournants pour améliorer la sécurité. Un code tournant change à chaque utilisation, ce qui rend plus difficile pour un attaquant d'exploiter les signaux capturés. Voici quelques exemples de codes tournants couramment utilisés :

- KeeLoq
- AES-Based

#### KeeLoq

KeeLoq est un algorithme de cryptage utilisé dans les systèmes d'entrée sans clé. Il est largement déployé dans les systèmes de sécurité automobile.

- **Taille du Bloc:** 32 bits
- **Taille de la clé:** 64 bits
- **Nombre de tours:** 528

L'algorithme KeeLoq fonctionne en utilisant une technique de cryptage par décalage de bit et une clé de 64 bits pour générer un code tournant unique pour chaque transmission. Bien que largement utilisé, KeeLoq a été compromis à de nombreuses reprises par des attaques cryptographiques.

DPA:
CVE-2009-1780;
CVE-2010-1372;
> Les systèmes utilisant KeeLoq sont particulièrement vulnérables aux attaques DPA en raison de leur faible résistance aux analyses de puissance. KeeLoq effectue des opérations bit-à-bit qui montrent des variations de puissance distinctes selon les données manipulées. En enregistrant et en analysant les traces de puissance pendant l'exécution de KeeLoq, les attaquants peuvent déduire les bits de la clé.

Bruteforce:
CVE-2010-1373
> En raison d'une clé bien trop faible (64 bits seulement) les systèmes Keeloq sont particulièrement sensible aux attaques par force brute.

#### AES-Based

Les systèmes basés sur AES (Advanced Encryption Standard) utilisent une méthode de cryptage plus robuste et moderne comparée à KeeLoq. AES est un standard de cryptographie adopté par le gouvernement des États-Unis et largement utilisé à travers le monde pour sécuriser les données.

- **Taille du Bloc:** 128 bits (mais peut aussi être 192 ou 256 bits selon la version)
- **Taille de la clé:** 128, 192, ou 256 bits
- **Nombre de tours:** 10, 12, ou 14 tours (selon la taille de la clé)

Les systèmes basés sur AES utilisent une combinaison de substitutions et de permutations pour générer des codes tournants. En raison de la robustesse de l'algorithme AES, ces systèmes sont considérés comme plus sécurisés contre les attaques cryptographiques contemporaines.

L'adoption de codes tournants basés sur AES est en augmentation, car ils offrent une meilleure sécurité et résistance aux attaques par rapport aux anciens systèmes comme KeeLoq. En outre, les systèmes AES peuvent être intégrés avec d'autres techniques de sécurité, comme l'authentification mutuelle et la gestion des clés dynamique, pour renforcer encore la sécurité des systèmes de clé électronique.

Implémentation:
CVE-2017-16660;
CVE-2018-7935;
CVE-2019-18278;
CVE-2021-23840;
> Dans le cas des systèmes AES-Based la majorité des risques de sécurité actuel réside dans des defaults d'implémentation de la part des constructeurs dans leurs automobiles

## Système RKE mono et bidirectionnel 

Les systèmes RKE peuvent peuvent être séparé entre les systèmes monodirectionnels et les systèmes bidirectionnels.
Ses deux catégories peuvent présenter de nombreuses différences, en termes de cout technologique, énergétique ou en terme de sécurité. 

| Caractéristique            | Monodirectionnel                         | Bidirectionnel                           |
|----------------------------|------------------------------------------|------------------------------------------|
| **Communication**          | Unidirectionnelle (télécommande -> véhicule) | Bidirectionnelle (télécommande <-> véhicule) |
| **Sécurité**               | Vulnérable aux attaques par interception | Plus résistant aux attaques grâce à l'authentification mutuelle |
| **Complexité**             | Simple, facile à mettre en œuvre         | Plus complexe, nécessite une synchronisation des échanges |
| **Retour d'information**   | Aucun retour d'information               | Retour d'information visuel ou auditif pour l'utilisateur |
| **Coût**                   | Moins coûteux                            | Plus coûteux en raison de la technologie avancée |

### Systèmes RKE monodirectionnels

Les systèmes RKE monodirectionnels sont les plus simples et les plus couramment utilisés dans les véhicules.
Dans ce type de système, la communication se fait uniquement dans une direction, de l'emmeteur dans la télécommande vers le récepteur dans le véhicule.
L'emmeteur ne peut donc pas être challenger, il prouve son identité directement avec un code.

Même si les codes roulants permettent de limiter ce risque, les systèmes RKE sont souvent sensibles aux failles de rejeux. 

### Systèmes RKE bidirectionnels

Les systèmes RKE bidirectionnels offrent une communication à double sens entre l'émetteur et le récepteur du véhicule.
Ce type de système offre d'avantages de flexibilité en termes de fonctionnalité et permet d'améliorer la sécurité du système.
L'emmeteur après être entré en communication avec le recepteur vas se voir soumettre un challenge de ce dernier qu'il lui renverra. 


## Modulation des signaux 

La modulation des singaux est une part importante des RKE et RKS. 
C'est elle qui permet la transmission des données de la télécommande au véhicule en passant par un canal analogique.
On peut pour se faire transformer le signal numérique en signal analogique avant de le transmettre ou utiliser un système d'état binaire. 
Les principals méthodes utilisé dans le cadre des RKE et RKS sont: l'ask, fsk et psk.

### Modulation d'amplitude: ASK/AM

La modulation d'amplitude est l'une des techniques les plus simples, l'amplitude du signal porteur est modifiée en fonction de l'information à transmettre par exemple 5V pour un bit à 1 et 0V pour un bit à 0 .
Cette méthode est susceptible aux interférences et au bruit qui peuvent facilement modifier le code reçu. 

- **Avantages** :
  - Facile à implémenter.
  - Coûts de fabrication réduits.
- **Inconvénients** :
  - Sensible aux interférences et au bruit.
  - Moins sécurisé comparé à d'autres techniques de modulation.

### Modulation de fréquence: FSK/FM

La modulation de fréquence modifie la fréquence du signal porteur en fonction des données à transmettre (Par exemple en ajoutant ou réduit la fréquence de quelques dizaine de kHZ).
Elle résiste mieux aux interferance et bruit pendant la transmission. 

- **Avantages** :
  - Moins sensible aux interférences.
  - Meilleure qualité de signal.
- **Inconvénients** :
  - Plus complexe à implémenter.
  - Coûts de fabrication plus élevés que la modulation d'amplitude.

### Modulation de Phase: PSK/PM

La modulation de phase consiste à modifier la phase du signal porteur pour transmettre des informations.
Cette méthode est moins courante mais offre une bonne résistance aux interférences et peut être combinée avec la modulation de fréquence (FM) pour créer des systèmes plus robustes.

- **Avantages** :
  - Bonne résistance aux interférences.
  - Peut être combinée avec d'autres techniques pour améliorer la robustesse et la qualité du signal (ex:QPSK (utilisé dans les réseaux mobiles)).
- **Inconvénients** :
  - Complexité de l'implémentation plus élevée.
  - Nécessite des systèmes de synchronisation précis pour éviter les erreurs de démodulation.

## Attaques possibles 

### Replay 
L'attaque par rejeu, ou "replay attack", consiste à intercepter une transmission de données légitime entre une télécommande et un récepteur pour ensuite la rejouer ultérieurement. Dans le contexte des systèmes de clé électronique à distance (RKE - Remote Keyless Entry), un attaquant pourrait capturer le signal de la clé lorsqu'un utilisateur déverrouille son véhicule et le réutiliser pour déverrouiller le véhicule à nouveau sans autorisation.

#### Exemples de CVE :
- CVE-2019-20626: Honda HR-V 2017 permet une attaque par rejeu.

### RollJam
L'attaque RollJam exploite une faille dans le mécanisme de synchronisation des codes roulants utilisés par les systèmes de clé électronique à distance. L'attaquant utilise un dispositif qui bloque le signal de la clé lorsque l'utilisateur tente de verrouiller ou déverrouiller le véhicule, tout en enregistrant ce signal. Ensuite, il envoie un signal précédemment capturé au véhicule, déverrouillant ainsi le véhicule sans que l'utilisateur ne le sache.

#### Exemples de CVE :
- CVE-2021-46145: Honda CIVIC 2012 utilise des codes roulants non expirants et une resynchronisation des compteurs, facilitant les attaques RollJam.

### RollBack 
L'attaque RollBack exploite des faiblesses dans la gestion des codes roulants par les systèmes RKE. L'attaquant intercepte plusieurs signaux de la clé pour ensuite rejouer un signal précédent, profitant d'une mauvaise implémentation de la gestion des codes roulants qui permet d'accepter un ancien code comme valide.

#### Exemples de CVE :
- CVE-2022-27254: Honda CIVIC 2018 envoie le même signal pour chaque demande d'ouverture de porte.
- CVE-2022-38766: Renault Zoe 2021 utilise le même ensemble de codes roulants pour chaque demande d'ouverture de porte.
- CVE-2023-33281: Nissan Sylphy classic 2021 envoie le même signal pour chaque demande d'ouverture de porte.
- CVE-2022-37418: Nissan, Kia, Hyundai jusqu'en 2017 permettent à des attaquants distants de réaliser des opérations de déverrouillage et de forcer une resynchronisation après avoir capturé deux signaux valides consécutifs de la clé.
- CVE-2022-37305: certains véhicules Honda jusqu'en 2018 permettent à des attaquants distants de réaliser des opérations de déverrouillage et de forcer une resynchronisation après avoir capturé cinq signaux valides consécutifs de la clé RKE.
- CVE-2022-36945: certains véhicules Mazda jusqu'en 2020 permettent à des attaquants distants de réaliser des opérations de déverrouillage et de forcer une resynchronisation après avoir capturé trois signaux valides consécutifs de la clé.



