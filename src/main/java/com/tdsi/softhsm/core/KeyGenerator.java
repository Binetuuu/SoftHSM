package com.tdsi.softhsm.core;

import com.tdsi.softhsm.model.AccessContext;
import com.tdsi.softhsm.model.CryptographicKey;
import com.tdsi.softhsm.model.User;
import com.tdsi.softhsm.model.enums.*;
import com.tdsi.softhsm.security.AccessDeniedException;
import com.tdsi.softhsm.security.KeyAccessControl;
import com.tdsi.softhsm.storage.KeyStorageException;
import com.tdsi.softhsm.storage.SecureKeyStorage;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.*;
import java.time.LocalDateTime;
import java.util.Objects;
import java.util.Set;

/**
 * Générateur de clés cryptographiques avec stockage sécurisé intégré.
 * 
 * Utilise SecureRandom pour garantir la sécurité cryptographique
 * des clés générées, et intègre le contrôle d'accès et le stockage sécurisé.
 */
@Slf4j
@Component
public class KeyGenerator {
    
    private final SecureRandom secureRandom;
    private SecureKeyStorage secureStorage;
    private KeyAccessControl accessControl;
    
    public KeyGenerator() {
        // Enregistrer Bouncy Castle comme provider
        Security.addProvider(new BouncyCastleProvider());
        
        // Initialiser SecureRandom avec l'algorithme le plus sûr disponible
        SecureRandom tempRandom;
        try {
            tempRandom = SecureRandom.getInstanceStrong();
            log.info("SecureRandom initialisé avec l'algorithme: {}", 
                tempRandom.getAlgorithm());
        } catch (NoSuchAlgorithmException e) {
            log.warn("Impossible d'obtenir SecureRandom strong, utilisation de l'instance par défaut");
            tempRandom = new SecureRandom();
        }
        this.secureRandom = tempRandom;
    }
    
    /**
     * Initialise le système de stockage sécurisé et de contrôle d'accès
     * 
     * @param secureStorage Gestionnaire de stockage sécurisé
     * @param accessControl Gestionnaire de contrôle d'accès
     */
    public void initializeSecurity(SecureKeyStorage secureStorage, KeyAccessControl accessControl) {
        this.secureStorage = Objects.requireNonNull(secureStorage, 
            "Le gestionnaire de stockage ne peut pas être null");
        this.accessControl = Objects.requireNonNull(accessControl, 
            "Le gestionnaire de contrôle d'accès ne peut pas être null");
        log.info("Système de sécurité initialisé");
    }
    
    /**
     * Vérifie si le système de sécurité est initialisé
     * 
     * @return true si le système est initialisé
     */
    public boolean isSecurityInitialized() {
        return secureStorage != null && accessControl != null;
    }
    
    /**
     * Génère une clé cryptographique selon les paramètres spécifiés
     * Version de base sans stockage automatique (Module 1)
     * 
     * @param request Paramètres de génération de la clé
     * @return Résultat contenant la clé générée et ses métadonnées
     */
    public KeyGenerationResult generateKey(KeyGenerationRequest request) {
        log.info("Génération d'une clé {} pour l'utilisateur {}", 
            request.getAlgorithm(), request.getOwner());
        
        long startTime = System.currentTimeMillis();
        
        try {
            KeyGenerationResult result;
            
            if (request.getAlgorithm().isSymmetric()) {
                result = generateSymmetricKey(request);
            } else if (request.getAlgorithm().isAsymmetric()) {
                result = generateAsymmetricKey(request);
            } else {
                throw new IllegalArgumentException(
                    "Algorithme non supporté: " + request.getAlgorithm());
            }
            
            long duration = System.currentTimeMillis() - startTime;
            result.setGenerationTimeMs(duration);
            
            log.info("Clé {} générée avec succès en {} ms", 
                result.getMetadata().getAlias(), duration);
            
            return result;
            
        } catch (Exception e) {
            log.error("Erreur lors de la génération de la clé: {}", e.getMessage(), e);
            throw new KeyGenerationException(
                "Impossible de générer la clé: " + e.getMessage(), e);
        }
    }
    
    /**
     * Génère et stocke une clé cryptographique de manière sécurisée (Module 2)
     * 
     * @param request Paramètres de génération de la clé
     * @param user Utilisateur effectuant l'opération
     * @param keyPassword Mot de passe pour protéger la clé
     * @return Résultat contenant les métadonnées de la clé stockée
     * @throws AccessDeniedException Si l'utilisateur n'a pas les permissions
     * @throws KeyStorageException Si le stockage échoue
     */
    public KeyGenerationResult generateAndStoreKey(KeyGenerationRequest request, 
                                                   User user, 
                                                   char[] keyPassword) 
            throws AccessDeniedException, KeyStorageException {
        
        // Vérifier que le système de sécurité est initialisé
        if (!isSecurityInitialized()) {
            throw new IllegalStateException(
                "Le système de stockage sécurisé n'est pas initialisé. " +
                "Appelez initializeSecurity() d'abord.");
        }
        
        // Vérifier les permissions de l'utilisateur
        AccessContext context = new AccessContext.Builder()
            .user(user)
            .operation(KeyOperation.GENERATE)
            .additionalInfo("Génération de clé: " + request.getAlias())
            .build();
        
        accessControl.checkAccess(context);
        
        log.info("Génération et stockage sécurisé d'une clé {} pour l'utilisateur {}", 
            request.getAlgorithm(), user.getUsername());
        
        long startTime = System.currentTimeMillis();
        
        try {
            // Générer la clé
            KeyGenerationResult result = generateKey(request);
            
            // Extraire la clé secrète
            SecretKey secretKey;
            if (result.isSymmetric()) {
                secretKey = result.getSecretKey();
            } else if (result.isAsymmetric()) {
                // Pour les clés asymétriques, on stocke la clé privée encodée comme SecretKey
                byte[] privateKeyBytes = result.getKeyPair().getPrivate().getEncoded();
                secretKey = new javax.crypto.spec.SecretKeySpec(privateKeyBytes, 
                    request.getAlgorithm().getAlgorithmName());
            } else {
                throw new KeyGenerationException(
                    "Type de clé non supporté pour le stockage", null);
            }
            
            // Stocker la clé de manière sécurisée
            secureStorage.storeKey(result.getMetadata(), secretKey, keyPassword);
            
            long duration = System.currentTimeMillis() - startTime;
            result.setGenerationTimeMs(duration);
            
            log.info("Clé {} générée et stockée avec succès en {} ms", 
                result.getMetadata().getAlias(), duration);
            
            // Ne pas retourner la clé réelle pour des raisons de sécurité
            result.setSecretKey(null);
            result.setKeyPair(null);
            result.setMessage("Clé générée et stockée avec succès dans le KeyStore sécurisé");
            
            return result;
            
        } catch (KeyStorageException e) {
            log.error("Erreur lors du stockage de la clé: {}", e.getMessage(), e);
            throw e;
        } catch (Exception e) {
            log.error("Erreur lors de la génération de la clé: {}", e.getMessage(), e);
            throw new KeyGenerationException(
                "Impossible de générer et stocker la clé: " + e.getMessage(), e);
        }
    }
    
    /**
     * Génère une clé symétrique (AES, ChaCha20)
     */
    private KeyGenerationResult generateSymmetricKey(KeyGenerationRequest request) 
            throws NoSuchAlgorithmException {
        
        Algorithm algorithm = request.getAlgorithm();
        
        javax.crypto.KeyGenerator keyGen = javax.crypto.KeyGenerator.getInstance(
            algorithm.getAlgorithmName()
        );
        keyGen.init(algorithm.getKeySize(), secureRandom);
        
        SecretKey secretKey = keyGen.generateKey();
        
        // Créer les métadonnées
        CryptographicKey metadata = buildMetadata(request, KeyType.SYMMETRIC);
        
        // Définir les usages par défaut pour une clé symétrique
        if (request.getAllowedUsages() == null || request.getAllowedUsages().isEmpty()) {
            metadata.setAllowedUsages(KeyUsage.getSymmetricKeyUsages());
        }
        
        return KeyGenerationResult.builder()
            .metadata(metadata)
            .secretKey(secretKey)
            .success(true)
            .message("Clé symétrique générée avec succès")
            .build();
    }
    
    /**
     * Génère une paire de clés asymétriques (RSA, ECC, Ed25519)
     */
    private KeyGenerationResult generateAsymmetricKey(KeyGenerationRequest request) 
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        
        Algorithm algorithm = request.getAlgorithm();
        KeyPairGenerator keyPairGen;
        
        // Configuration spécifique selon l'algorithme
        switch (algorithm.getAlgorithmName()) {
            case "RSA":
                keyPairGen = KeyPairGenerator.getInstance("RSA");
                keyPairGen.initialize(algorithm.getKeySize(), secureRandom);
                break;
                
            case "EC":
                keyPairGen = KeyPairGenerator.getInstance("EC");
                // Configurer la courbe selon la taille
                java.security.spec.ECGenParameterSpec ecSpec = 
                    new java.security.spec.ECGenParameterSpec(getCurveName(algorithm));
                keyPairGen.initialize(ecSpec, secureRandom);
                break;
                
            case "Ed25519":
                keyPairGen = KeyPairGenerator.getInstance("Ed25519");
                // Ed25519 a une taille fixe, pas de paramètre nécessaire
                break;
                
            case "X25519":
                keyPairGen = KeyPairGenerator.getInstance("X25519");
                // X25519 a une taille fixe, pas de paramètre nécessaire
                break;
                
            default:
                throw new IllegalArgumentException(
                    "Algorithme asymétrique non supporté: " + algorithm.getAlgorithmName());
        }
        
        KeyPair keyPair = keyPairGen.generateKeyPair();
        
        // Créer les métadonnées
        CryptographicKey metadata = buildMetadata(request, KeyType.KEY_PAIR);
        
        // Définir les usages par défaut pour une paire de clés
        if (request.getAllowedUsages() == null || request.getAllowedUsages().isEmpty()) {
            if (algorithm == Algorithm.X25519) {
                metadata.setAllowedUsages(Set.of(KeyUsage.KEY_AGREEMENT));
            } else if (algorithm == Algorithm.ED25519) {
                metadata.setAllowedUsages(Set.of(KeyUsage.SIGNING, KeyUsage.VERIFICATION));
            } else {
                // RSA et ECC peuvent tout faire
                metadata.setAllowedUsages(Set.of(
                    KeyUsage.ENCRYPTION, 
                    KeyUsage.DECRYPTION,
                    KeyUsage.SIGNING, 
                    KeyUsage.VERIFICATION
                ));
            }
        }
        
        return KeyGenerationResult.builder()
            .metadata(metadata)
            .keyPair(keyPair)
            .success(true)
            .message("Paire de clés asymétriques générée avec succès")
            .build();
    }
    
    /**
     * Construit les métadonnées de la clé à partir de la requête
     */
    private CryptographicKey buildMetadata(KeyGenerationRequest request, KeyType keyType) {
        return CryptographicKey.builder()
            .alias(request.getAlias())
            .algorithm(request.getAlgorithm())
            .keyType(keyType)
            .keySize(request.getAlgorithm().getKeySize())
            .owner(request.getOwner())
            .status(KeyStatus.ACTIVE)
            .createdAt(LocalDateTime.now())
            .expiresAt(request.getExpirationDate())
            .allowedUsages(request.getAllowedUsages() != null ? 
                request.getAllowedUsages() : Set.of())
            .description(request.getDescription())
            .build();
    }
    
    /**
     * Retourne le nom de la courbe elliptique selon l'algorithme
     */
    private String getCurveName(Algorithm algorithm) {
        return switch (algorithm) {
            case ECC_P256 -> "secp256r1";
            case ECC_P384 -> "secp384r1";
            case ECC_P521 -> "secp521r1";
            default -> throw new IllegalArgumentException(
                "Courbe non supportée pour: " + algorithm);
        };
    }
    
    /**
     * Exception levée en cas d'erreur lors de la génération
     */
    public static class KeyGenerationException extends RuntimeException {
        public KeyGenerationException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
