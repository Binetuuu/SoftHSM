package com.tdsi.softhsm.model.enums;

/**
 * Type de clé cryptographique
 */
public enum KeyType {
    /**
     * Clé symétrique (ex: AES)
     */
    SYMMETRIC("Symmetric"),
    
    /**
     * Clé publique (partie publique d'une paire asymétrique)
     */
    PUBLIC("Public"),
    
    /**
     * Clé privée (partie privée d'une paire asymétrique)
     */
    PRIVATE("Private"),
    
    /**
     * Paire de clés (publique + privée)
     */
    KEY_PAIR("Key Pair");

    private final String displayName;

    KeyType(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }

    @Override
    public String toString() {
        return displayName;
    }
}
