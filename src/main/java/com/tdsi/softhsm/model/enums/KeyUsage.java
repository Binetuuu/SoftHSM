package com.tdsi.softhsm.model.enums;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Usage autorisé pour une clé cryptographique
 */
public enum KeyUsage {
    /**
     * Chiffrement de données
     */
    ENCRYPTION("Encryption", "Chiffrement de données"),
    
    /**
     * Déchiffrement de données
     */
    DECRYPTION("Decryption", "Déchiffrement de données"),
    
    /**
     * Signature numérique
     */
    SIGNING("Signing", "Création de signatures numériques"),
    
    /**
     * Vérification de signature
     */
    VERIFICATION("Verification", "Vérification de signatures numériques"),
    
    /**
     * Accord de clé (Key Agreement - ECDH, X25519)
     */
    KEY_AGREEMENT("Key Agreement", "Échange de clés sécurisé"),
    
    /**
     * Encapsulation de clé (Key Wrapping)
     */
    KEY_WRAPPING("Key Wrapping", "Encapsulation de clés"),
    
    /**
     * Dérivation de clé
     */
    KEY_DERIVATION("Key Derivation", "Dérivation de clés");

    private final String displayName;
    private final String description;

    KeyUsage(String displayName, String description) {
        this.displayName = displayName;
        this.description = description;
    }

    public String getDisplayName() {
        return displayName;
    }

    public String getDescription() {
        return description;
    }

    /**
     * Retourne les usages typiques pour une clé symétrique
     */
    public static Set<KeyUsage> getSymmetricKeyUsages() {
        return Set.of(ENCRYPTION, DECRYPTION, KEY_WRAPPING);
    }

    /**
     * Retourne les usages typiques pour une clé publique
     */
    public static Set<KeyUsage> getPublicKeyUsages() {
        return Set.of(ENCRYPTION, VERIFICATION);
    }

    /**
     * Retourne les usages typiques pour une clé privée
     */
    public static Set<KeyUsage> getPrivateKeyUsages() {
        return Set.of(DECRYPTION, SIGNING, KEY_AGREEMENT);
    }

    /**
     * Vérifie si cet usage est compatible avec le type de clé spécifié
     */
    public boolean isCompatibleWith(KeyType keyType) {
        return switch (keyType) {
            case SYMMETRIC -> getSymmetricKeyUsages().contains(this);
            case PUBLIC -> getPublicKeyUsages().contains(this);
            case PRIVATE -> getPrivateKeyUsages().contains(this);
            case KEY_PAIR -> true; // Une paire peut tout faire
        };
    }

    @Override
    public String toString() {
        return displayName;
    }
}
