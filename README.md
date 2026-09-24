# SoftHSM - Gestionnaire de Clés Cryptographiques

Projet de fin d'année L3 - TDSI 2026

## Description

Système de gestion de clés cryptographiques sécurisé implémentant 13 modules fonctionnels avec des mécanismes de sécurité avancés.

## Fonctionnalités principales

- ✅ **Module 1** : Génération de clés (AES, RSA, ECC, Ed25519)
- 🚧 **Module 2** : Stockage sécurisé avec chiffrement
- ⏳ **Module 3** : Importation de clés
- ⏳ **Module 4** : Exportation de clés
- ⏳ **Module 5** : Inventaire et consultation
- ⏳ **Module 6** : Utilisation cryptographique
- ⏳ **Module 7** : Rotation et renouvellement
- ⏳ **Module 8** : Révocation et compromission
- ⏳ **Module 9** : Archivage et sauvegarde
- ⏳ **Module 10** : Suppression sécurisée
- ⏳ **Module 11** : Authentification et RBAC
- ⏳ **Module 12** : Journalisation et audit
- ⏳ **Module 13** : Tableau de bord

## Mitigations de sécurité

| Limite | Mitigation | Technique |
|--------|-----------|-----------|
| Admin unique | Partage de secret | Shamir (2 sur 3) |
| Clé en mémoire | Réduction d'exposition | Effacement explicite KEK |
| Stockage en clair | Chiffrement standard | Argon2id + PKCS#12 |
| Modification non détectée | Intégrité | HMAC/GCM |
| Accès direct | Contrôle API | RBAC strict |
| Journal modifiable | Traçabilité | Chaîne de hachage |

## Prérequis

- Java 17+
- Maven 3.8+
- PostgreSQL 14+ (pour les étapes ultérieures)

## Installation

```bash
# Cloner le projet
git clone <repository-url>
cd softHSM

# Compiler
mvn clean install

# Lancer l'application
mvn spring-boot:run
```

## Utilisation (CLI - Phase 1)

```bash
# Générer une clé AES-256
java -cp target/softhsm-1.0.0-SNAPSHOT.jar com.tdsi.softhsm.cli.KeyGeneratorCLI

# Suivre les instructions interactives
```

## Structure du projet

```
softHSM/
├── src/main/java/com/tdsi/softhsm/
│   ├── core/              # Moteur cryptographique
│   ├── security/          # Mitigations de sécurité
│   ├── storage/           # Persistance sécurisée
│   ├── model/             # Entités métier
│   ├── service/           # Services métier
│   ├── api/               # Contrôleurs REST
│   ├── cli/               # Interface ligne de commande
│   └── SoftHSMApplication.java
├── src/main/resources/
│   └── application.properties
└── pom.xml
```

## Développement par étapes

### ✅ Étape 1 : Module 1 - Génération de clés (EN COURS)
- Structure du projet
- Modèle de données
- Générateurs AES et RSA
- CLI de test

### 🔜 Étape 2 : Module 2 - Stockage sécurisé
- Partage de secret Shamir
- Dérivation Argon2id
- KeyStore PKCS#12

### 🔜 Étape 3 : Module 6 - Utilisation cryptographique
- Chiffrement/déchiffrement AES
- Signature/vérification RSA

## Auteur

Projet réalisé dans le cadre du mémoire L3 TDSI 2026

## Licence

Projet académique - Tous droits réservés
