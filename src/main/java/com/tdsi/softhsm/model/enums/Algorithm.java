package com.tdsi.softhsm.model.enums;

/**
 * Algorithmes cryptographiques supportés
 */
public enum Algorithm {
    // Algorithmes symétriques
    AES_128("AES", 128, KeyType.SYMMETRIC, "AES-128"),
    AES_192("AES", 192, KeyType.SYMMETRIC, "AES-192"),
    AES_256("AES", 256, KeyType.SYMMETRIC, "AES-256"),
    CHACHA20("ChaCha20", 256, KeyType.SYMMETRIC, "ChaCha20"),
    
    // Algorithmes asymétriques RSA
    RSA_2048("RSA", 2048, KeyType.KEY_PAIR, "RSA-2048"),
    RSA_3072("RSA", 3072, KeyType.KEY_PAIR, "RSA-3072"),
    RSA_4096("RSA", 4096, KeyType.KEY_PAIR, "RSA-4096"),
    
    // Courbes elliptiques
    ECC_P256("EC", 256, KeyType.KEY_PAIR, "ECC P-256 (secp256r1)"),
    ECC_P384("EC", 384, KeyType.KEY_PAIR, "ECC P-384 (secp384r1)"),
    ECC_P521("EC", 521, KeyType.KEY_PAIR, "ECC P-521 (secp521r1)"),
    
    // Courbes modernes
    ED25519("Ed25519", 256, KeyType.KEY_PAIR, "Ed25519 (signature)"),
    X25519("X25519", 256, KeyType.KEY_PAIR, "X25519 (échange de clés)");

    private final String algorithmName;
    private final int keySize;
    private final KeyType keyType;
    private final String displayName;

    Algorithm(String algorithmName, int keySize, KeyType keyType, String displayName) {
        this.algorithmName = algorithmName;
        this.keySize = keySize;
        this.keyType = keyType;
        this.displayName = displayName;
    }

    public String getAlgorithmName() {
        return algorithmName;
    }

    public int getKeySize() {
        return keySize;
    }

    public KeyType getKeyType() {
        return keyType;
    }

    public String getDisplayName() {
        return displayName;
    }

    /**
     * Vérifie si l'algorithme est symétrique
     */
    public boolean isSymmetric() {
        return keyType == KeyType.SYMMETRIC;
    }

    /**
     * Vérifie si l'algorithme est asymétrique
     */
    public boolean isAsymmetric() {
        return keyType == KeyType.KEY_PAIR;
    }

    /**
     * Vérifie si l'algorithme est basé sur les courbes elliptiques
     */
    public boolean isEllipticCurve() {
        return algorithmName.equals("EC") || 
               algorithmName.equals("Ed25519") || 
               algorithmName.equals("X25519");
    }

    @Override
    public String toString() {
        return displayName;
    }
}
