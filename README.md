# Encrypt - Application de chiffrement et déchiffrement de fichiers
Description du projet

Encrypt est une application de chiffrement et déchiffrement de fichiers dotée d'une interface graphique conviviale basée sur Tkinter. Elle permet aux utilisateurs de sécuriser leurs fichiers sensibles en utilisant des algorithmes de chiffrement robustes tels que Fernet et AES256.

Les fonctionnalités incluent :

    Chiffrement sécurisé de fichiers individuels.
    Déchiffrement sécurisé de fichiers en utilisant un mot de passe.
    Validation des mots de passe pour éviter les mots de passe faibles ou compromis.
    Gestion des erreurs et protection contre les attaques de type "brute force".
    Mode sombre/clair configurable par l'utilisateur.
    Historique des opérations.

Fonctionnalités principales
Chiffrement de fichiers

    Crypte un ou plusieurs fichiers (formats pris en charge : .docx, .xlsx, .jpg, .mp4, .pdf, etc.).
    Algorithmes disponibles : Fernet ou AES256.
    Stockage sécurisé des données chiffrées avec un salt unique pour chaque fichier.
    Possibilité de conserver les fichiers originaux.

Déchiffrement de fichiers

    Décrypte un fichier chiffré en utilisant le même algorithme et mot de passe utilisé lors du chiffrement.
    Gestion des erreurs en cas de fichier corrompu ou de mot de passe incorrect.

Validation des mots de passe

    Vérifie que les mots de passe :
    Ont une longueur minimale de 8 caractères.
    Incluent des chiffres, des lettres et des caractères spéciaux.
    Vérifie s'il s'agit d'un mot de passe compromis à l'aide de l'API Have I Been Pwned (HIBP).

Protection contre les attaques brute force

    Implémente un blocage exponentiel : à chaque tentative échouée, le temps de blocage double (démarrage à 10 secondes).

Interface graphique utilisateur moderne

    Simple et intuitive avec des boutons pour :
    Chiffrer des fichiers.
    Déchiffrer des fichiers.
    Basculer entre un mode sombre et un mode clair.
    Affichage d'un historique des opérations.

Installation
Prérequis

    Python 3.7+ doit être installé sur votre machine.
    Les bibliothèques Python suivantes sont nécessaires :

    cryptography : Pour les opérations de chiffrement et déchiffrement.
    requests : Pour interagir avec l'API de "Have I Been Pwned".

Installez ces dépendances avec :

pip install cryptography requests

Exécution

    Téléchargez le fichier Encrypt.py (le fichier du script).
    Exécutez le script :

python Encrypt.py

L'application s'ouvrira et affichera son interface graphique.
Utilisation
1. Mode sombre/clair

    Cliquez sur le bouton "Basculer Mode Sombre/Clair" pour basculer entre les deux thèmes disponibles.

2. Chiffrement de fichiers

    Cliquez sur "Chiffrer des fichiers".
    Une fenêtre d'explorateur s'ouvre pour sélectionner les fichiers à chiffrer.
    Entrez un mot de passe et choisissez un algorithme de chiffrement (Fernet ou AES256).
    Cliquez sur Valider.
    Les fichiers seront chiffrés et un historique des fichiers traités sera ajouté à la zone d'historique.

3. Déchiffrement de fichiers

    Cliquez sur "Déchiffrer un fichier".
    Une fenêtre d'explorateur s'ouvre pour sélectionner un fichier chiffré.
    Entrez le même mot de passe utilisé pour le chiffrement.
    Cliquez sur Valider.
    Le fichier sera déchiffré et un historique des fichiers traités sera ajouté à la zone d'historique.

4. Validation forte des mots de passe

    L'application exige que chaque mot de passe utilisé pour le chiffrement ou déchiffrement respecte les critères suivants :
    Au moins 8 caractères.
    Comprend des chiffres, des lettres et des caractères spéciaux.
    Si le mot de passe est compromis :
    L'application envoi une demande à l'API https://haveibeenpwned.com pour vérifier si le mot de passe a été exposé.
    Si le mot de passe est trouvé dans la base de données des mots de passe compromis, l'utilisateur est invité à en choisir un autre.

Sécurité intégrée

    Utilisation de cryptography :

    Fernet pour un chiffrement sécurisé et facile à utiliser.
    AES256 pour un chiffrement avancé.

    Validation des mots de passe avec HIBP :

    Tous les mots de passe sont vérifiés par la base de données d'API HIBP pour s'assurer qu'ils ne sont pas compromis.

    Sel (Salt) :

    Génération d'un salt unique aléatoire pour chaque fichier, inclus dans les données chiffrées.

    Gestion des erreurs :

    Messages d'erreur clairs pour les fichiers corrompus ou les mots de passe incorrects.
    Gestion sécurisée des fichiers pour éviter les pertes ou corruptions (ex. : suppression des fichiers temporaires sécurisée).

    Protection brute force :

    Blocage exponentiel intégré après chaque tentative échouée.

    Empêcher l'exécution sur des environnements non sécurisés :

    Vérifie l'environnement d'exécution de l'application en validant l'adresse MAC de la machine.
    Si la machine n'est pas autorisée, l'exécution est bloquée.

Aperçu de l'interface utilisateur

L'application utilise Tkinter pour fournir une interface simple et intuitive comprenant les éléments suivants :

    Un bouton pour chiffrer des fichiers.
    Un bouton pour déchiffrer des fichiers.
    Un historique des opérations effectuées.
    Un bouton pour basculer entre un thème sombre et un thème clair.

Améliorations possibles

Si vous souhaitez améliorer davantage cette application, voici quelques suggestions :

    Chiffrement/déchiffrement de dossiers complets :

    Ajoutez une fonctionnalité permettant de traiter tous les fichiers d'un dossier en une seule opération.

    Archivage automatique des fichiers chiffrés :

    Permet d'exporter automatiquement les fichiers chiffrés dans un dossier comprimé.

Contributions

Toute suggestion ou contribution est bienvenue pour rendre cette application plus robuste et conviviale. Si vous souhaitez collaborer, n'hésitez pas à créer une Pull Request ou à signaler un problème.

Licence

Ce projet est distribué sous la licence MIT - Vous êtes libre de l'utiliser, le modifier et de le distribuer, sous réserve d'une attribution claire au développeur initial.