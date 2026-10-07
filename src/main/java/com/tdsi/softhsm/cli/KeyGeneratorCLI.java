package com.tdsi.softhsm.cli;

import com.tdsi.softhsm.core.KeyGenerationRequest;
import com.tdsi.softhsm.core.KeyGenerationResult;
import com.tdsi.softhsm.core.KeyGenerator;
import com.tdsi.softhsm.model.CryptographicKey;
import com.tdsi.softhsm.model.enums.Algorithm;
import com.tdsi.softhsm.model.enums.KeyUsage;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Scanner;
import java.util.Set;


public class KeyGeneratorCLI {
    
    private static final Scanner scanner = new Scanner(System.in);
    private static final KeyGenerator keyGenerator = new KeyGenerator();
    private static final DateTimeFormatter DATE_FORMATTER = 
        DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm:ss");
    
    public static void main(String[] args) {
        printBanner();
        
        boolean continuer = true;
        
        while (continuer) {
            try {
                afficherMenu();
                int choix = lireEntier("Votre choix: ");
                
                switch (choix) { 
                    case 1 -> genererCleSymetrique();
                    case 2 -> genererCleAsymetrique();
                    case 3 -> afficherAlgorithmesDisponibles();
                    case 0 -> {
                        System.out.println("\n Au revoir !");
                        continuer = false;
                    }
                    default -> System.out.println(" Choix invalide !");
                }
                
            } catch (Exception e) {
                System.err.println(" Erreur: " + e.getMessage());
                e.printStackTrace();
            }
            
            if (continuer) {
                System.out.println("\nAppuyez sur Entrée pour continuer...");
                scanner.nextLine();
            }
        }
        
        scanner.close();
    }
    
    private static void printBanner() {
        System.out.println("""
            ╔═══════════════════════════════════════════════════════╗
            ║                                                       ║
            ║       SoftHSM - Gestionnaire de Clés                  ║
            ║                                                       ║
            ║          Module 1: Génération de Clés                 ║
            ║              TDSI L3 - 2026                           ║
            ║                                                       ║
            ╚═══════════════════════════════════════════════════════╝
            """);
    }
    
    private static void afficherMenu() {
        System.out.println("\n" + "=".repeat(50));
        System.out.println("           MENU PRINCIPAL");
        System.out.println("=".repeat(50));
        System.out.println("1. Générer une clé symétrique (AES)");
        System.out.println("2. Générer une paire de clés asymétriques (RSA/ECC/Ed25519)");
        System.out.println("3. Afficher les algorithmes disponibles");
        System.out.println("0. Quitter");
        System.out.println("=".repeat(50));
    }
    
    private static void genererCleSymetrique() {
        System.out.println("\n GÉNÉRATION DE CLÉ SYMÉTRIQUE");
        System.out.println("-".repeat(50));
        
        // Choix de l'algorithme
        System.out.println("\nAlgorithmes symétriques disponibles:");
        System.out.println("1. AES-128");
        System.out.println("2. AES-192");
        System.out.println("3. AES-256");
        System.out.println("4. ChaCha20");
        
        int choixAlgo = lireEntier("\nChoisissez l'algorithme (1-4): ");
        
        Algorithm algorithm = switch (choixAlgo) {
            case 1 -> Algorithm.AES_128;
            case 2 -> Algorithm.AES_192;
            case 3 -> Algorithm.AES_256;
            case 4 -> Algorithm.CHACHA20;
            default -> throw new IllegalArgumentException("Algorithme invalide");
        };
        
        // Saisie des paramètres
        String alias = lireChaine("Alias de la clé (ex: aes-prod-001): ");
        String owner = lireChaine("Propriétaire (ex: admin): ");
        String description = lireChaine("Description (optionnelle): ");
        
        boolean avecExpiration = lireOuiNon("Définir une date d'expiration? (o/n): ");
        LocalDateTime expiration = null;
        if (avecExpiration) {
            int jours = lireEntier("Nombre de jours avant expiration: ");
            expiration = LocalDateTime.now().plusDays(jours);
        }
        
        // Créer la requête
        KeyGenerationRequest request = KeyGenerationRequest.builder()
            .alias(alias)
            .algorithm(algorithm)
            .owner(owner)
            .description(description.isEmpty() ? null : description)
            .expirationDate(expiration)
            .allowedUsages(KeyUsage.getSymmetricKeyUsages())
            .build();
        
        // Générer la clé
        genererEtAfficher(request);
    }
    
    private static void genererCleAsymetrique() {
        System.out.println("\n GÉNÉRATION DE CLÉ ASYMÉTRIQUE");
        System.out.println("-".repeat(50));
        
        // Choix de l'algorithme
        System.out.println("\nAlgorithmes asymétriques disponibles:");
        System.out.println("1. RSA-2048");
        System.out.println("2. RSA-3072");
        System.out.println("3. RSA-4096");
        System.out.println("4. ECC P-256");
        System.out.println("5. ECC P-384");
        System.out.println("6. ECC P-521");
        System.out.println("7. Ed25519");
        System.out.println("8. X25519");
        
        int choixAlgo = lireEntier("\nChoisissez l'algorithme (1-8): ");
        
        Algorithm algorithm = switch (choixAlgo) {
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
        
        // Saisie des paramètres
        String alias = lireChaine("Alias de la clé (ex: rsa-prod-001): ");
        String owner = lireChaine("Propriétaire (ex: admin): ");
        String description = lireChaine("Description (optionnelle): ");
        
        boolean avecExpiration = lireOuiNon("Définir une date d'expiration? (o/n): ");
        LocalDateTime expiration = null;
        if (avecExpiration) {
            int jours = lireEntier("Nombre de jours avant expiration: ");
            expiration = LocalDateTime.now().plusDays(jours);
        }
        
        // Créer la requête
        KeyGenerationRequest request = KeyGenerationRequest.builder()
            .alias(alias)
            .algorithm(algorithm)
            .owner(owner)
            .description(description.isEmpty() ? null : description)
            .expirationDate(expiration)
            .build();
        
        // Générer la clé
        genererEtAfficher(request);
    }
    
    private static void genererEtAfficher(KeyGenerationRequest request) {
        System.out.println("\n Génération en cours...");
        
        try {
            KeyGenerationResult result = keyGenerator.generateKey(request);
            
            if (result.isSuccess()) {
                afficherResultat(result);
            } else {
                System.out.println(" Échec: " + result.getMessage());
            }
            
        } catch (Exception e) {
            System.err.println(" Erreur lors de la génération: " + e.getMessage());
        }
    }
    
    private static void afficherResultat(KeyGenerationResult result) {
        CryptographicKey key = result.getMetadata();
        
        System.out.println("\n CLÉ GÉNÉRÉE AVEC SUCCÈS !");
        System.out.println("=".repeat(70));
        System.out.println(" MÉTADONNÉES DE LA CLÉ:");
        System.out.println("-".repeat(70));
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
        } else {
            System.out.println("  Date d'expiration: Aucune (clé permanente)");
        }
        
        if (key.getDescription() != null && !key.getDescription().isEmpty()) {
            System.out.printf("  Description      : %s%n", key.getDescription());
        }
        
        System.out.println("\n  Usages autorisés :");
        for (KeyUsage usage : key.getAllowedUsages()) {
            System.out.printf("    ✓ %s - %s%n", 
                usage.getDisplayName(), usage.getDescription());
        }
        
        System.out.println("-".repeat(70));
        System.out.printf(" Temps de génération : %d ms%n", result.getGenerationTimeMs());
        System.out.println("=".repeat(70));
        
        // Informations sur le matériel cryptographique
        System.out.println("\n MATÉRIEL CRYPTOGRAPHIQUE:");
        if (result.isSymmetric()) {
            System.out.println("  Type: Clé secrète symétrique");
            System.out.printf("  Format: %s%n", result.getSecretKey().getFormat());
            System.out.printf("  Algorithme: %s%n", result.getSecretKey().getAlgorithm());
        } else if (result.isAsymmetric()) {
            System.out.println("  Type: Paire de clés asymétriques");
            System.out.printf("  Clé publique  - Format: %s, Algorithme: %s%n", 
                result.getKeyPair().getPublic().getFormat(),
                result.getKeyPair().getPublic().getAlgorithm());
            System.out.printf("  Clé privée    - Format: %s, Algorithme: %s%n", 
                result.getKeyPair().getPrivate().getFormat(),
                result.getKeyPair().getPrivate().getAlgorithm());
        }
        
        System.out.println("\n  ATTENTION: Les clés réelles ne sont pas affichées pour des raisons de sécurité.");
        System.out.println("    Dans un système complet, elles seraient immédiatement stockées");
        System.out.println("    de manière sécurisée dans un KeyStore chiffré (Module 2).");
    }
    
    private static void afficherAlgorithmesDisponibles() {
        System.out.println("\n ALGORITHMES CRYPTOGRAPHIQUES DISPONIBLES");
        System.out.println("=".repeat(70));
        
        System.out.println("\n ALGORITHMES SYMÉTRIQUES:");
        System.out.println("-".repeat(70));
        for (Algorithm algo : Algorithm.values()) {
            if (algo.isSymmetric()) {
                System.out.printf("  • %s (%d bits)%n", 
                    algo.getDisplayName(), algo.getKeySize());
            }
        }
        
        System.out.println("\n ALGORITHMES ASYMÉTRIQUES:");
        System.out.println("-".repeat(70));
        for (Algorithm algo : Algorithm.values()) {
            if (algo.isAsymmetric()) {
                System.out.printf("  • %s (%d bits)%s%n", 
                    algo.getDisplayName(), 
                    algo.getKeySize(),
                    algo.isEllipticCurve() ? " [Courbe Elliptique]" : "");
            }
        }
        System.out.println("=".repeat(70));
    }
    
    // Méthodes utilitaires de lecture
    
    private static String lireChaine(String prompt) {
        System.out.print(prompt);
        return scanner.nextLine().trim();
    }
    
    private static int lireEntier(String prompt) {
        while (true) {
            try {
                System.out.print(prompt);
                int valeur = Integer.parseInt(scanner.nextLine().trim());
                return valeur;
            } catch (NumberFormatException e) {
                System.out.println(" Veuillez entrer un nombre valide.");
            }
        }
    }
    
    private static boolean lireOuiNon(String prompt) {
        while (true) {
            String reponse = lireChaine(prompt).toLowerCase();
            if (reponse.equals("o") || reponse.equals("oui")) {
                return true;
            } else if (reponse.equals("n") || reponse.equals("non")) {
                return false;
            }
            System.out.println(" Veuillez répondre par 'o' (oui) ou 'n' (non).");
        }
    }
}
