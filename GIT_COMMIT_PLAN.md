# 📋 Plan de Commits Progressifs - SoftHSM

## 🎯 **Stratégie de Commits**

### **Phase 1 : Structure et Documentation**
```bash
# Commit 1 : Structure initiale
git add README.md pom.xml .gitignore
git commit -m "🚀 Initial project setup with Maven configuration"

# Commit 2 : Documentation de base
git add docs/POUR_COMMENCER.md docs/INSTALLATION.md
git commit -m "📚 Add basic project documentation and installation guide"

# Commit 3 : Architecture de base
git add src/main/java/com/tdsi/softhsm/model/
git commit -m "🏗️ Add core model classes and enums"
```

### **Phase 2 : Module 1 - Génération de Clés**
```bash
# Commit 4 : Générateur de base
git add src/main/java/com/tdsi/softhsm/core/
git commit -m "🔑 Implement core key generation functionality"

# Commit 5 : CLI Module 1
git add src/main/java/com/tdsi/softhsm/cli/KeyGeneratorCLI.java
git commit -m "🖥️ Add command-line interface for key generation"

# Commit 6 : Tests Module 1
git add src/test/java/com/tdsi/softhsm/core/
git commit -m "🧪 Add comprehensive tests for Module 1"

# Commit 7 : Documentation Module 1
git add docs/ETAPE_1_COMPLETE.md
git commit -m "📖 Complete Module 1 documentation"
```

### **Phase 3 : Module 2 - Services de Sécurité**
```bash
# Commit 8 : Service de dérivation
git add src/main/java/com/tdsi/softhsm/security/KeyDerivationService.java
git add src/main/java/com/tdsi/softhsm/security/KeyDerivationException.java
git commit -m "🔐 Implement PBKDF2 key derivation service"

# Commit 9 : Service de chiffrement
git add src/main/java/com/tdsi/softhsm/security/KeyEncryptionService.java
git add src/main/java/com/tdsi/softhsm/security/EncryptionException.java
git commit -m "🔒 Add AES-GCM encryption service for key protection"

# Commit 10 : Validation des mots de passe
git add src/main/java/com/tdsi/softhsm/security/PasswordValidator.java
git commit -m "✅ Implement robust password validation"

# Commit 11 : Contrôle d'accès
git add src/main/java/com/tdsi/softhsm/security/KeyAccessControl.java
git add src/main/java/com/tdsi/softhsm/security/AccessDeniedException.java
git commit -m "🛡️ Add RBAC access control with audit logging"
```

### **Phase 4 : Module 2 - Services de Stockage**
```bash
# Commit 12 : Service KeyStore
git add src/main/java/com/tdsi/softhsm/storage/KeyStoreService.java
git add src/main/java/com/tdsi/softhsm/storage/KeyStorageException.java
git commit -m "💾 Implement PKCS#12 KeyStore management"

# Commit 13 : Stockage sécurisé
git add src/main/java/com/tdsi/softhsm/storage/SecureKeyStorage.java
git add src/main/java/com/tdsi/softhsm/storage/KeyStoreEntry.java
git commit -m "🏪 Add secure key storage orchestration"

# Commit 14 : Intégration au générateur
git add -u src/main/java/com/tdsi/softhsm/core/KeyGenerator.java
git commit -m "🔗 Integrate secure storage with key generator"
```

### **Phase 5 : Interface Sécurisée et Tests**
```bash
# Commit 15 : CLI sécurisée
git add src/main/java/com/tdsi/softhsm/cli/SecureKeyManagerCLI.java
git commit -m "🖥️ Add secure CLI with RBAC and audit"

# Commit 16 : Tests sécurité
git add src/test/java/com/tdsi/softhsm/security/
git commit -m "🧪 Add security services test suite"

# Commit 17 : Tests stockage
git add src/test/java/com/tdsi/softhsm/storage/
git commit -m "🧪 Add storage services test suite"

# Commit 18 : Tests intégration
git add src/test/java/com/tdsi/softhsm/Module2IntegrationTest.java
git commit -m "🧪 Add Module 2 integration tests"
```

### **Phase 6 : Documentation Finale**
```bash
# Commit 19 : Documentation Module 2
git add docs/MODULE_2_DOCUMENTATION_COMPLETE.md
git add docs/GUIDE_DEMARRAGE_RAPIDE_MODULE2.md
git commit -m "📚 Complete Module 2 documentation"

# Commit 20 : Documentation projet
git add docs/SYNTHESE_PROJET_COMPLET.md
git add docs/ARCHITECTURE_EXPLIQUEE.md
git commit -m "📖 Add comprehensive project documentation"

# Commit 21 : Finalisation
git add docs/GUIDE_TEST.md
git add LISTE_COMPLETE_FICHIERS.md
git commit -m "🏁 Final project completion with test guide"
```

## 🔧 **Commandes Pratiques**

### **Configuration initiale**
```bash
git config user.name "Votre Nom"
git config user.email "votre.email@example.com"
```

### **Création du remote repository**
```bash
# Sur GitHub/GitLab, créer un repo vide
# Puis :
git remote add origin https://github.com/username/softhsm.git
git branch -M main
```

### **Premier push**
```bash
git push -u origin main
```

### **Vérification avant commit**
```bash
git status
git diff --staged
git log --oneline
```

## 📊 **Organisation Recommandée**

### **Branches suggérées**
- `main` : Version stable
- `develop` : Développement en cours
- `feature/module1` : Module 1 spécifique
- `feature/module2` : Module 2 spécifique
- `hotfix/security` : Corrections sécurité urgentes

### **Tags de version**
- `v1.0.0-module1` : Module 1 complet
- `v2.0.0-module2` : Module 2 complet
- `v2.1.0` : Améliorations post-livraison

---

**🎯 Suivre ce plan pour un historique Git propre et professionnel !**