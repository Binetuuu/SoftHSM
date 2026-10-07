package com.tdsi.softhsm.cli;

import com.tdsi.softhsm.core.KeyGenerationRequest;
import com.tdsi.softhsm.core.KeyGenerationResult;
import com.tdsi.softhsm.core.KeyGenerator;
import com.tdsi.softhsm.model.CryptographicKey;
import com.tdsi.softhsm.model.User;
import com.tdsi.softhsm.model.enums.*;
import com.tdsi.softhsm.security.KeyAccessControl;
import com.tdsi.softhsm.security.PasswordValidator;
import com.tdsi.softhsm.storage.KeyStorageException;
import com.tdsi.softhsm.storage.SecureKeyStorage;

import javax.crypto.SecretKey;
import java.io.Console;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.List;
import java.util.Scanner;

/**
 * Interface en ligne de commande pour le gestionnaire de clés sécurisé.
 * Intègre les Modules 1 et 2 : génération de clés + stockage sécurisé.
 */
public class SecureKeyManagerCLI {
    
    private static final Scanner scanner = new Scanner(System.in);
    private static final KeyGenerator keyGenerator = new KeyGenerator();
    private static final PasswordValidator passwordValidator = new PasswordValidator();
    private static final DateTimeFormatter DATE_FORMATTER = 
        DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm:ss");
    
    private static SecureKeyStorage secureStorage;
    private static KeyAccessControl accessControl;
    private static User currentUser;
    
    public static void main(String[] args) {
        printBanner();
        
        try {
            // Initialiser le système de sécurité
            if (!initialiserSystemeSecurite()) {
                System.out.println("\n❌ Impossible d'initialiser le système de sécurité.");
                return;
            }
            
            // Authentification de l'utilisateur
            if (!authentifierUtilisateur()) {
                System.out.println("\n❌ Authentification échouée.");
                return;
            }
            
            // Boucle principale
            boolean continuer = true;
            while (continuer) {
                try {
                    afficherMenuPrincipal();
                    int choix = lireEntier("Votre choix: ");
                    
                    switch (choix) {
                        case 1 -> genererEtStockerCle();
                        case 2 -> listerCles();
                        case 3 -> consulterCle();
                        case 4 -> supprimerCle();
                        case 5 -> sauvegarderKeyStore();
                        case 6 -> afficherLogsAudit();
                        case 7 -> changerUtilisateur();
                        case 0 -> {
                            System.out.println("\n👋 Au revoir !");
                            continuer = false;
                        }
                        default -> System.out.println("❌ Choix invalide !");
                    }
                    
                } catch (Exception e) {
                    System.err.println("❌ Erreur: " + e.getMessage());
                    if (e.getMessage() == null || e.getMessage().isEmpty()) {
                        e.printStackTrace();
                    }
                }
                
                if (continuer) {
                    System.out.println("\nAppuyez sur Entrée pour continuer...");
                    scanner.nextLine();
                }
            }
            
        } finally {
            // Nettoyer les ressources
            if (secureStorage != null) {
                secureStorage.close();
            }
            scanner.close();
        }
    }
    
    private static void printBanner() {
        System.out.println("""
            ╔═══════════════════════════════════════════════════════╗
            ║                                                       ║
            ║       🔐 SoftHSM - Gestionnaire de Clés 🔐            ║
            ║                                                       ║
            ║     Modules 1 & 2 : Génération + Stockage Sécurisé   ║
            ║              TDSI L3 - 2026                           ║
            ║                                                       ║
            ╚═══════════════════════════════════════════════════════╝
            """);
    }
    
    private static boolean initialiserSystemeSecurite() {
        System.out.println("\n🔧 INITIALISATION DU SYSTÈME DE SÉCURITÉ");
        System.out.println("═".repeat(60));
        
        try {
            // Demander le mot de passe maître du KeyStore
            System.out.println("\n📋 Configuration du KeyStore PKCS12");
            System.out.println("Le mot de passe maître protège l'ensemble du magasin de clés.");
            
            char[] masterPassword = lireMotDePasse(
                "\nEntrez le mot de passe maître du KeyStore: ");
            
            if (masterPassword.length == 0) {
                System.out.println("❌ Le mot de passe ne peut pas être vide.");
                return false;
            }
            
            System.out.println("📝 Mot de passe saisi (" + masterPassword.length + " caractères)");
            
            // Vérifier la robustesse du mot de passe (pour nouveau KeyStore)
            PasswordValidator.ValidationResult validation = 
                passwordValidator.validate(masterPassword);
            
            if (!validation.isValid()) {
                System.out.println("\n⚠️  ATTENTION : " + validation.getMessage());
                if (!lireOuiNon("Continuer quand même ? (o/n): ")) {
                    Arrays.fill(masterPassword, ' ');
                    return false;
                }
            }
            
            // Créer les répertoires nécessaires
            Path keystoreDir = Paths.get("keystore");
            Path logsDir = Paths.get("logs");
            
            try {
                Files.createDirectories(keystoreDir);
                Files.createDirectories(logsDir);
                System.out.println("📁 Répertoires créés avec succès");
            } catch (Exception e) {
                System.err.println("❌ Impossible de créer les répertoires: " + e.getMessage());
                Arrays.fill(masterPassword, ' ');
                return false;
            }
            
            System.out.println("🔧 Initialisation du stockage sécurisé...");
            System.out.println("   Chemin KeyStore: " + keystoreDir.resolve("softhsm.p12"));
            System.out.println("   Longueur mot de passe: " + masterPassword.length + " caractères");
            
            // Initialiser le stockage sécurisé
            secureStorage = new SecureKeyStorage(
                keystoreDir.resolve("softhsm.p12"),
                masterPassword,
                masterPassword
            );
            
            // Initialiser le contrôle d'accès
            accessControl = new KeyAccessControl();
            
            // Initialiser le générateur de clés avec le système de sécurité
            keyGenerator.initializeSecurity(secureStorage, accessControl);
            
            // Effacer le mot de passe de la mémoire
            Arrays.fill(masterPassword, ' ');
            
            System.out.println("\n✅ Système de sécurité initialisé avec succès !");
            System.out.println("   📁 KeyStore: keystore/softhsm.p12");
            System.out.println("   📝 Logs d'audit: logs/access_audit.log");
            
            return true;
            
        } catch (KeyStorageException e) {
            System.err.println("\n❌ Erreur lors de l'initialisation: " + e.getMessage());
            if (e.getCause() != null) {
                System.err.println("   Cause: " + e.getCause().getClass().getSimpleName() + " - " + e.getCause().getMessage());
            }
            return false;
        } catch (Exception e) {
            System.err.println("\n❌ Erreur inattendue: " + e.getClass().getSimpleName() + " - " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }
    
    private static boolean authentifierUtilisateur() {
        System.out.println("\n👤 AUTHENTIFICATION");
        System.out.println("═".repeat(60));
        
        String username = lireChaine("Nom d'utilisateur: ");
        
        // Pour la démo, créer un utilisateur selon le nom
        UserRole role = selectionnerRole();
        
        currentUser = new User(username, role);
        accessControl.registerSession(currentUser);
        
        System.out.println("\n✅ Authentifié en tant que : " + username + 
                         " (Rôle: " + role.getDescription() + ")");
        
        return true;
    }
    
    private static UserRole selectionnerRole() {
        System.out.println("\nRôles disponibles:");
        System.out.println("1. ADMIN - Administrateur système (accès complet)");
        System.out.println("2. OPERATOR - Opérateur de clés");
        System.out.println("3. USER - Utilisateur standard");
        System.out.println("4. AUDITOR - Auditeur (lecture seule)");
        System.out.println("5. GUEST - Invité (accès minimal)");
        
        int choix = lireEntier("Sélectionnez votre rôle (1-5): ");
        
        return switch (choix) {
            case 1 -> UserRole.ADMIN;
            case 2 -> UserRole.OPERATOR;
            case 3 -> UserRole.USER;
            case 4 -> UserRole.AUDITOR;
            case 5 -> UserRole.GUEST;
            default -> {
                System.out.println("Rôle invalide, USER par défaut");
                yield UserRole.USER;
            }
        };
    }
    
    private static void afficherMenuPrincipal() {
        System.out.println("\n" + "═".repeat(60));
        System.out.println("         MENU PRINCIPAL - " + currentUser.getUsername() + 
                         " (" + currentUser.getRole().getDescription() + ")");
        System.out.println("═".repeat(60));
        System.out.println("1. 🔑 Générer et stocker une nouvelle clé");
        System.out.println("2. 📋 Lister toutes les clés");
        System.out.println("3. 🔍 Consulter une clé spécifique");
        System.out.println("4. 🗑️  Supprimer une clé");
        System.out.println("5. 💾 Sauvegarder le KeyStore");
        System.out.println("6. 📊 Afficher les logs d'audit");
        System.out.println("7. 👤 Changer d'utilisateur");
        System.out.println("0. 🚪 Quitter");
        System.out.println("═".repeat(60));
    }
    
    private static void genererEtStockerCle() {
        System.out.println("\n🔑 GÉNÉRATION ET STOCKAGE SÉCURISÉ DE CLÉ");
        System.out.println("═".repeat(60));
        
        try {
            // Vérifier les permissions
            if (!accessControl.hasPermission(currentUser, KeyOperation.GENERATE)) {
                System.out.println("❌ Vous n'avez pas la permission de générer des clés.");
                System.out.println("   Rôle requis: " + KeyOperation.GENERATE.getRequiredRole().getDescription());
                return;
            }
            
            // Sélection du type de clé
            System.out.println("\nType de clé:");
            System.out.println("1. Clé symétrique (AES, ChaCha20)");
            System.out.println("2. Paire de clés asymétriques (RSA, ECC, Ed25519)");
            
            int typeChoix = lireEntier("Type (1-2): ");
            
            if (typeChoix == 1) {
                genererCleSymetriqueSecurisee();
            } else if (typeChoix == 2) {
                genererCleAsymetriqueSecurisee();
            } else {
                System.out.println("❌ Choix invalide");
            }
            
        } catch (Exception e) {
            System.err.println("❌ Erreur: " + e.getMessage());
        }
    }
    
    private static void genererCleSymetriqueSecurisee() {
        System.out.println("\n📦 CLÉS SYMÉTRIQUES");
        
        // Sélection de l'algorithme
        System.out.println("\nAlgorithmes disponibles:");
        System.out.println("1. AES-128");
        System.out.println("2. AES-192");
        System.out.println("3. AES-256 (recommandé)");
        System.out.println("4. ChaCha20");
        
        int algoChoix = lireEntier("Algorithme (1-4): ");
        
        Algorithm algorithm = switch (algoChoix) {
            case 1 -> Algorithm.AES_128;
            case 2 -> Algorithm.AES_192;
            case 3 -> Algorithm.AES_256;
            case 4 -> Algorithm.CHACHA20;
            default -> throw new IllegalArgumentException("Algorithme invalide");
        };
        
        // Paramètres de la clé
        String alias = lireChaine("Alias de la clé (ex: aes-prod-001): ");
        String description = lireChaine("Description (optionnelle): ");
        
        boolean avecExpiration = lireOuiNon("Définir une date d'expiration? (o/n): ");
        LocalDateTime expiration = null;
        if (avecExpiration) {
            int jours = lireEntier("Nombre de jours avant expiration: ");
            expiration = LocalDateTime.now().plusDays(jours);
        }
        
        // Mot de passe de protection de la clé
        char[] keyPassword = lireMotDePasseAvecConfirmation();
        
        try {
            // Créer la requête
            KeyGenerationRequest request = KeyGenerationRequest.builder()
                .alias(alias)
                .algorithm(algorithm)
                .owner(currentUser.getUsername())
                .description(description.isEmpty() ? null : description)
                .expirationDate(expiration)
                .allowedUsages(KeyUsage.getSymmetricKeyUsages())
                .build();
            
            // Générer et stocker
            System.out.println("\n⏳ Génération et chiffrement en cours...");
            KeyGenerationResult result = keyGenerator.generateAndStoreKey(
                request, currentUser, keyPassword);
            
            if (result.isSuccess()) {
                System.out.println("\n✅ " + result.getMessage());
                afficherMetadonneesCle(result.getMetadata());
                System.out.printf("\n⏱️  Temps de génération: %d ms%n", result.getGenerationTimeMs());
            } else {
                System.out.println("\n❌ Échec: " + result.getMessage());
            }
            
        } catch (Exception e) {
            System.err.println("\n❌ Erreur: " + e.getMessage());
        } finally {
            Arrays.fill(keyPassword, ' ');
        }
    }
    
    private static void genererCleAsymetriqueSecurisee() {
        System.out.println("\n🔐 CLÉS ASYMÉTRIQUES");
        
        // Sélection de l'algorithme
        System.out.println("\nAlgorithmes disponibles:");
        System.out.println("1. RSA-2048");
        System.out.println("2. RSA-3072");
        System.out.println("3. RSA-4096 (recommandé pour signatures)");
        System.out.println("4. ECC P-256 (recommandé général)");
        System.out.println("5. ECC P-384");
        System.out.println("6. ECC P-521");
        System.out.println("7. Ed25519 (recommandé pour signatures)");
        System.out.println("8. X25519 (pour échange de clés)");
        
        int algoChoix = lireEntier("Algorithme (1-8): ");
        
        Algorithm algorithm = switch (algoChoix) {
            case 1 -> Algorithm.RSA_2048;
            case 2 -> Algorithm.RSA_3072;
            case 3 -> Algorithm.RSA_4096;
            case 4 -> Algorithm.ECC_P256;
            case 5 -> Algorithm.ECC_P384;
            case 6 -> Algorithm.ECC_P521;
            case 7 -> Algorithm.ED25519;
            case 8 -> Algorithm.X25519;
            default -> throw new IllegalArgumentException("Algorithme invalide");
        };
        
        // Paramètres de la clé
        String alias = lireChaine("Alias de la clé (ex: rsa-prod-001): ");
        String description = lireChaine("Description (optionnelle): ");
        
        boolean avecExpiration = lireOuiNon("Définir une date d'expiration? (o/n): ");
        LocalDateTime expiration = null;
        if (avecExpiration) {
            int jours = lireEntier("Nombre de jours avant expiration: ");
            expiration = LocalDateTime.now().plusDays(jours);
        }
        
        // Mot de passe de protection de la clé
        char[] keyPassword = lireMotDePasseAvecConfirmation();
        
        try {
            // Créer la requête
            KeyGenerationRequest request = KeyGenerationRequest.builder()
                .alias(alias)
                .algorithm(algorithm)
                .owner(currentUser.getUsername())
                .description(description.isEmpty() ? null : description)
                .expirationDate(expiration)
                .build();
            
            // Générer et stocker
            System.out.println("\n⏳ Génération et chiffrement en cours...");
            KeyGenerationResult result = keyGenerator.generateAndStoreKey(
                request, currentUser, keyPassword);
            
            if (result.isSuccess()) {
                System.out.println("\n✅ " + result.getMessage());
                afficherMetadonneesCle(result.getMetadata());
                System.out.printf("\n⏱️  Temps de génération: %d ms%n", result.getGenerationTimeMs());
            } else {
                System.out.println("\n❌ Échec: " + result.getMessage());
            }
            
        } catch (Exception e) {
            System.err.println("\n❌ Erreur: " + e.getMessage());
        } finally {
            Arrays.fill(keyPassword, ' ');
        }
    }
    
    private static void listerCles() {
        System.out.println("\n📋 LISTE DES CLÉS STOCKÉES");
        System.out.println("═".repeat(60));
        
        try {
            // Vérifier les permissions
            if (!accessControl.hasPermission(currentUser, KeyOperation.VIEW_METADATA)) {
                System.out.println("❌ Vous n'avez pas la permission de consulter les clés.");
                return;
            }
            
            List<String> keyIds = secureStorage.listKeyIds();
            
            if (keyIds.isEmpty()) {
                System.out.println("\n📭 Aucune clé stockée.");
                return;
            }
            
            System.out.printf("\n%d clé(s) trouvée(s):%n%n", keyIds.size());
            
            for (String keyId : keyIds) {
                try {
                    SecureKeyStorage.KeyMetadata metadata = secureStorage.getKeyMetadata(keyId);
                    System.out.printf("🔑 %s%n", keyId);
                    System.out.printf("   Algorithme: %s | Type: %s | Créée: %s%n",
                        metadata.getAlgorithm(),
                        metadata.getKeyType().getDisplayName(),
                        metadata.getCreatedAt().format(DATE_FORMATTER));
                    if (metadata.getDescription() != null && !metadata.getDescription().isEmpty()) {
                        System.out.printf("   Description: %s%n", metadata.getDescription());
                    }
                    System.out.println();
                } catch (KeyStorageException e) {
                    System.out.printf("⚠️  %s (métadonnées inaccessibles)%n%n", keyId);
                }
            }
            
        } catch (Exception e) {
            System.err.println("❌ Erreur: " + e.getMessage());
        }
    }
    
    private static void consulterCle() {
        System.out.println("\n🔍 CONSULTATION D'UNE CLÉ");
        System.out.println("═".repeat(60));
        
        try {
            // Vérifier les permissions
            if (!accessControl.hasPermission(currentUser, KeyOperation.VIEW_METADATA)) {
                System.out.println("❌ Vous n'avez pas la permission de consulter les clés.");
                return;
            }
            
            String keyId = lireChaine("ID de la clé: ");
            
            if (!secureStorage.keyExists(keyId)) {
                System.out.println("❌ Aucune clé trouvée avec cet ID.");
                return;
            }
            
            SecureKeyStorage.KeyMetadata metadata = secureStorage.getKeyMetadata(keyId);
            
            System.out.println("\n📄 DÉTAILS DE LA CLÉ");
            System.out.println("─".repeat(60));
            System.out.printf("ID               : %s%n", keyId);
            System.out.printf("Algorithme       : %s%n", metadata.getAlgorithm());
            System.out.printf("Type             : %s%n", metadata.getKeyType().getDisplayName());
            System.out.printf("Date de création : %s%n", 
                metadata.getCreatedAt().format(DATE_FORMATTER));
            
            if (metadata.getDescription() != null && !metadata.getDescription().isEmpty()) {
                System.out.printf("Description      : %s%n", metadata.getDescription());
            }
            
            System.out.println("\n🔒 La clé elle-même est chiffrée et stockée en toute sécurité.");
            System.out.println("   Elle ne peut être déchiffrée qu'avec le mot de passe correct.");
            
        } catch (Exception e) {
            System.err.println("❌ Erreur: " + e.getMessage());
        }
    }
    
    private static void supprimerCle() {
        System.out.println("\n🗑️  SUPPRESSION D'UNE CLÉ");
        System.out.println("═".repeat(60));
        
        try {
            // Vérifier les permissions
            if (!accessControl.hasPermission(currentUser, KeyOperation.DELETE)) {
                System.out.println("❌ Vous n'avez pas la permission de supprimer des clés.");
                System.out.println("   Rôle requis: " + KeyOperation.DELETE.getRequiredRole().getDescription());
                return;
            }
            
            String keyId = lireChaine("ID de la clé à supprimer: ");
            
            if (!secureStorage.keyExists(keyId)) {
                System.out.println("❌ Aucune clé trouvée avec cet ID.");
                return;
            }
            
            // Afficher les détails avant suppression
            SecureKeyStorage.KeyMetadata metadata = secureStorage.getKeyMetadata(keyId);
            System.out.println("\n⚠️  CLÉ À SUPPRIMER:");
            System.out.printf("   ID: %s%n", keyId);
            System.out.printf("   Algorithme: %s%n", metadata.getAlgorithm());
            System.out.printf("   Type: %s%n", metadata.getKeyType().getDisplayName());
            
            // Confirmation
            if (!lireOuiNon("\n⚠️  Confirmer la suppression? Cette action est IRRÉVERSIBLE! (o/n): ")) {
                System.out.println("❌ Suppression annulée.");
                return;
            }
            
            // Supprimer
            secureStorage.deleteKey(keyId);
            System.out.println("\n✅ Clé supprimée avec succès.");
            
        } catch (Exception e) {
            System.err.println("❌ Erreur: " + e.getMessage());
        }
    }
    
    private static void sauvegarderKeyStore() {
        System.out.println("\n💾 SAUVEGARDE DU KEYSTORE");
        System.out.println("═".repeat(60));
        
        try {
            // Vérifier les permissions
            if (!accessControl.hasPermission(currentUser, KeyOperation.MANAGE_KEYSTORE)) {
                System.out.println("❌ Vous n'avez pas la permission de gérer le KeyStore.");
                System.out.println("   Rôle requis: " + KeyOperation.MANAGE_KEYSTORE.getRequiredRole().getDescription());
                return;
            }
            
            String backupName = lireChaine("Nom de la sauvegarde (sans extension): ");
            String backupPath = String.format("keystore/backups/%s_%s.p12", 
                backupName, 
                LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss")));
            
            System.out.println("\n⏳ Création de la sauvegarde...");
            secureStorage.backup(Paths.get(backupPath));
            
            System.out.println("\n✅ Sauvegarde créée avec succès !");
            System.out.println("   📁 Emplacement: " + backupPath);
            
        } catch (Exception e) {
            System.err.println("❌ Erreur: " + e.getMessage());
        }
    }
    
    private static void afficherLogsAudit() {
        System.out.println("\n📊 LOGS D'AUDIT");
        System.out.println("═".repeat(60));
        
        try {
            // Vérifier les permissions
            if (!accessControl.hasPermission(currentUser, KeyOperation.AUDIT)) {
                System.out.println("❌ Vous n'avez pas la permission de consulter les logs.");
                System.out.println("   Rôle requis: " + KeyOperation.AUDIT.getRequiredRole().getDescription());
                return;
            }
            
            int maxLines = lireEntier("Nombre de lignes à afficher (max 100): ");
            maxLines = Math.min(maxLines, 100);
            
            List<String> logs = accessControl.readAuditLog(maxLines);
            
            if (logs.isEmpty()) {
                System.out.println("\n📭 Aucun log disponible.");
                return;
            }
            
            System.out.println("\n📝 Dernières entrées:");
            System.out.println("─".repeat(60));
            for (String log : logs) {
                System.out.println(log);
            }
            
        } catch (Exception e) {
            System.err.println("❌ Erreur: " + e.getMessage());
        }
    }
    
    private static void changerUtilisateur() {
        if (currentUser != null) {
            accessControl.unregisterSession(currentUser.getUserId());
        }
        
        if (authentifierUtilisateur()) {
            System.out.println("\n✅ Utilisateur changé avec succès.");
        }
    }
    
    private static void afficherMetadonneesCle(CryptographicKey key) {
        System.out.println("\n📄 MÉTADONNÉES DE LA CLÉ:");
        System.out.println("─".repeat(60));
        System.out.printf("  ID               : %s%n", key.getId());
        System.out.printf("  Alias            : %s%n", key.getAlias());
        System.out.printf("  Algorithme       : %s%n", key.getAlgorithm().getDisplayName());
        System.out.printf("  Type             : %s%n", key.getKeyType().getDisplayName());
        System.out.printf("  Taille           : %d bits%n", key.getKeySize());
        System.out.printf("  Statut           : %s%n", key.getStatus().getDisplayName());
        System.out.printf("  Propriétaire     : %s%n", key.getOwner());
        System.out.printf("  Date de création : %s%n", 
            key.getCreatedAt().format(DATE_FORMATTER));
        
        if (key.getExpiresAt() != null) {
            System.out.printf("  Date d'expiration: %s%n", 
                key.getExpiresAt().format(DATE_FORMATTER));
        }
        
        if (key.getDescription() != null && !key.getDescription().isEmpty()) {
            System.out.printf("  Description      : %s%n", key.getDescription());
        }
    }
    
    // Méthodes utilitaires
    
    private static String lireChaine(String prompt) {
        System.out.print(prompt);
        try {
            if (scanner.hasNextLine()) {
                return scanner.nextLine().trim();
            } else {
                // Plus d'input disponible - utiliser valeur par défaut
                System.out.println("\n⚠️ Plus d'entrée disponible - utilisation de valeur par défaut");
                return "";
            }
        } catch (Exception e) {
            System.err.println("Erreur lors de la lecture: " + e.getMessage());
            return "";
        }
    }
    
    private static int lireEntier(String prompt) {
        int tentatives = 0;
        while (tentatives < 3) {
            try {
                System.out.print(prompt);
                if (scanner.hasNextLine()) {
                    String line = scanner.nextLine().trim();
                    if (line.isEmpty()) {
                        System.out.println("⚠️ Plus d'entrée disponible - utilisation de valeur par défaut");
                        return 1; // Valeur par défaut: ADMIN
                    }
                    return Integer.parseInt(line);
                } else {
                    System.out.println("⚠️ Plus d'entrée disponible - utilisation de valeur par défaut");
                    return 1; // Valeur par défaut: ADMIN
                }
            } catch (NumberFormatException e) {
                System.out.println("❌ Veuillez entrer un nombre valide.");
                tentatives++;
            }
        }
        System.out.println("Trop de tentatives - utilisation de valeur par défaut: 1");
        return 1;
    }
    
    private static boolean lireOuiNon(String prompt) {
        int tentatives = 0;
        while (tentatives < 3) {
            String reponse = lireChaine(prompt).toLowerCase();
            if (reponse.equals("o") || reponse.equals("oui")) {
                return true;
            } else if (reponse.equals("n") || reponse.equals("non")) {
                return false;
            } else if (reponse.isEmpty()) {
                // Pas de réponse - utiliser "non" par défaut pour sécurité
                System.out.println("Aucune réponse - choix par défaut: NON");
                return false;
            } else {
                System.out.println("❌ Veuillez répondre par 'o' (oui) ou 'n' (non).");
                tentatives++;
            }
        }
        // Après 3 tentatives, utiliser "non" par défaut
        System.out.println("Trop de tentatives - choix par défaut: NON");
        return false;
    }
    
    private static char[] lireMotDePasse(String prompt) {
        System.out.print(prompt);
        
        // Utiliser Console.readPassword() pour masquer la saisie
        Console console = System.console();
        if (console != null) {
            char[] password = console.readPassword();
            if (password == null) {
                // L'utilisateur a appuyé Ctrl+C ou EOF
                return new char[0];
            }
            return password;
        } else {
            // Fallback pour environnements sans console (IDE)
            System.out.print("(ATTENTION: saisie visible) ");
            try {
                String password = scanner.nextLine();
                if (password == null) {
                    return new char[0];
                }
                return password.toCharArray();
            } catch (Exception e) {
                System.err.println("Erreur lors de la saisie: " + e.getMessage());
                return new char[0];
            }
        }
    }
    
    private static char[] lireMotDePasseAvecConfirmation() {
        while (true) {
            System.out.println("\n🔐 Protection de la clé par mot de passe");
            char[] password1 = lireMotDePasse("Mot de passe: ");
            char[] password2 = lireMotDePasse("Confirmation: ");
            
            if (Arrays.equals(password1, password2)) {
                Arrays.fill(password2, ' ');
                return password1;
            }
            
            System.out.println("❌ Les mots de passe ne correspondent pas.");
            Arrays.fill(password1, ' ');
            Arrays.fill(password2, ' ');
        }
    }
}
