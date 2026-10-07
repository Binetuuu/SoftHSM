package com.tdsi.softhsm.security;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;

/**
 * Service de chiffrement/déchiffrement des clés cryptographiques avant stockage.
 * 
 * Utilise AES-256 en mode GCM (Galois/Counter Mode) qui offre :
 * - Chiffrement authentifié (AEAD - Authenticated Encryption with Associated Data)
 * - Protection contre les modifications (intégrité)
 * - Performance élevée
 * - Résistance aux attaques par rejeu
 * 
 * Ce service permet de protéger les clés sensibles avant leur stockage dans le KeyStore.
 */
public class KeyEncryptionService {
    
    /**
     * Algorithme de chiffrement utilisé
     */
    private static final String ENCRYPTION_ALGORITHM = "AES/GCM/NoPadding";
    
    /**
     * Algorithme de la clé
     */
    private static final String KEY_ALGORITHM = "AES";
    
    /**
     * Longueur de la clé en bits (256 bits = 32 octets)
     */
    private static final int KEY_LENGTH = 256;
    
    /**
     * Longueur du vecteur d'initialisation (IV) en octets (96 bits recommandé pour GCM)
     */
    private static final int IV_LENGTH = 12;
    
    /**
     * Longueur du tag d'authentification en bits (128 bits recommandé)
     */
    private static final int GCM_TAG_LENGTH = 128;
    
    private final SecureRandom secureRandom;
    
    /**
     * Constructeur par défaut
     */
    public KeyEncryptionService() {
        this.secureRandom = new SecureRandom();
    }
    
    /**
     * Génère un vecteur d'initialisation (IV) aléatoire
     * 
     * @return IV aléatoire
     */
    private byte[] generateIV() {
        byte[] iv = new byte[IV_LENGTH];
        secureRandom.nextBytes(iv);
        return iv;
    }
    
    /**
     * Chiffre des données avec une clé de chiffrement
     * 
     * @param plaintext Données en clair à chiffrer
     * @param encryptionKey Clé de chiffrement (doit être une clé AES-256)
     * @return Résultat du chiffrement contenant les données chiffrées et l'IV
     * @throws EncryptionException Si le chiffrement échoue
     */
    public EncryptedData encrypt(byte[] plaintext, SecretKey encryptionKey) throws EncryptionException {
        Objects.requireNonNull(plaintext, "Les données à chiffrer ne peuvent pas être null");
        Objects.requireNonNull(encryptionKey, "La clé de chiffrement ne peut pas être null");
        
        if (plaintext.length == 0) {
            throw new IllegalArgumentException("Les données à chiffrer ne peuvent pas être vides");
        }
        
        validateKey(encryptionKey);
        
        try {
            // Générer un IV unique pour ce chiffrement
            byte[] iv = generateIV();
            
            // Initialiser le cipher en mode chiffrement
            Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, gcmSpec);
            
            // Chiffrer les données
            byte[] ciphertext = cipher.doFinal(plaintext);
            
            return new EncryptedData(ciphertext, iv);
            
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | 
                 InvalidKeyException | InvalidAlgorithmParameterException |
                 IllegalBlockSizeException | BadPaddingException e) {
            throw new EncryptionException("Échec du chiffrement des données", e);
        }
    }
    
    /**
     * Déchiffre des données chiffrées
     * 
     * @param encryptedData Données chiffrées avec l'IV
     * @param encryptionKey Clé de chiffrement (même que celle utilisée pour chiffrer)
     * @return Données déchiffrées
     * @throws EncryptionException Si le déchiffrement échoue
     */
    public byte[] decrypt(EncryptedData encryptedData, SecretKey encryptionKey) throws EncryptionException {
        Objects.requireNonNull(encryptedData, "Les données chiffrées ne peuvent pas être null");
        Objects.requireNonNull(encryptionKey, "La clé de chiffrement ne peut pas être null");
        
        validateKey(encryptionKey);
        
        try {
            // Initialiser le cipher en mode déchiffrement
            Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, encryptedData.getIv());
            cipher.init(Cipher.DECRYPT_MODE, encryptionKey, gcmSpec);
            
            // Déchiffrer les données
            return cipher.doFinal(encryptedData.getCiphertext());
            
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | 
                 InvalidKeyException | InvalidAlgorithmParameterException |
                 IllegalBlockSizeException | BadPaddingException e) {
            throw new EncryptionException("Échec du déchiffrement des données", e);
        }
    }
    
    /**
     * Chiffre une clé cryptographique (SecretKey) pour stockage sécurisé
     * 
     * @param keyToEncrypt Clé à chiffrer
     * @param masterKey Clé maître utilisée pour le chiffrement
     * @return Clé chiffrée
     * @throws EncryptionException Si le chiffrement échoue
     */
    public EncryptedData encryptKey(SecretKey keyToEncrypt, SecretKey masterKey) throws EncryptionException {
        Objects.requireNonNull(keyToEncrypt, "La clé à chiffrer ne peut pas être null");
        
        byte[] keyBytes = keyToEncrypt.getEncoded();
        if (keyBytes == null) {
            throw new EncryptionException("Impossible d'obtenir l'encodage de la clé");
        }
        
        try {
            return encrypt(keyBytes, masterKey);
        } finally {
            // Effacer les données sensibles
            Arrays.fill(keyBytes, (byte) 0);
        }
    }
    
    /**
     * Déchiffre une clé cryptographique stockée
     * 
     * @param encryptedKey Clé chiffrée
     * @param masterKey Clé maître utilisée pour le déchiffrement
     * @param algorithm Algorithme de la clé originale (ex: "AES", "RSA")
     * @return Clé déchiffrée
     * @throws EncryptionException Si le déchiffrement échoue
     */
    public SecretKey decryptKey(EncryptedData encryptedKey, SecretKey masterKey, String algorithm) 
            throws EncryptionException {
        Objects.requireNonNull(algorithm, "L'algorithme ne peut pas être null");
        
        byte[] keyBytes = decrypt(encryptedKey, masterKey);
        
        try {
            return new SecretKeySpec(keyBytes, algorithm);
        } finally {
            // Effacer les données sensibles
            Arrays.fill(keyBytes, (byte) 0);
        }
    }
    
    /**
     * Valide qu'une clé est appropriée pour le chiffrement AES-256
     * 
     * @param key Clé à valider
     * @throws EncryptionException Si la clé est invalide
     */
    private void validateKey(SecretKey key) throws EncryptionException {
        if (!KEY_ALGORITHM.equals(key.getAlgorithm())) {
            throw new EncryptionException(
                "Algorithme de clé invalide. Attendu: " + KEY_ALGORITHM + ", reçu: " + key.getAlgorithm()
            );
        }
        
        byte[] encoded = key.getEncoded();
        if (encoded == null) {
            throw new EncryptionException("Impossible d'obtenir l'encodage de la clé");
        }
        
        // Vérifier la longueur de la clé (256 bits = 32 octets)
        if (encoded.length * 8 != KEY_LENGTH) {
            throw new EncryptionException(
                "Longueur de clé invalide. Attendu: " + KEY_LENGTH + " bits, reçu: " + (encoded.length * 8) + " bits"
            );
        }
    }
    
    /**
     * Génère une clé AES-256 aléatoire pour le chiffrement
     * 
     * @return Nouvelle clé AES-256
     * @throws EncryptionException Si la génération échoue
     */
    public SecretKey generateEncryptionKey() throws EncryptionException {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance(KEY_ALGORITHM);
            keyGen.init(KEY_LENGTH, secureRandom);
            return keyGen.generateKey();
        } catch (NoSuchAlgorithmException e) {
            throw new EncryptionException("Échec de la génération de clé de chiffrement", e);
        }
    }
    
    /**
     * Crée une clé AES-256 à partir d'une clé dérivée par PBKDF2
     * 
     * @param derivedKeyBytes Octets de la clé dérivée
     * @return Clé AES-256
     * @throws EncryptionException Si la création échoue
     */
    public SecretKey createKeyFromDerived(byte[] derivedKeyBytes) throws EncryptionException {
        Objects.requireNonNull(derivedKeyBytes, "Les octets de la clé dérivée ne peuvent pas être null");
        
        if (derivedKeyBytes.length * 8 != KEY_LENGTH) {
            throw new EncryptionException(
                "Longueur de clé dérivée invalide. Attendu: " + KEY_LENGTH + " bits"
            );
        }
        
        return new SecretKeySpec(derivedKeyBytes, KEY_ALGORITHM);
    }
    
    /**
     * Classe immuable contenant des données chiffrées et leur IV
     */
    public static class EncryptedData {
        private final byte[] ciphertext;
        private final byte[] iv;
        
        /**
         * Constructeur
         * 
         * @param ciphertext Données chiffrées
         * @param iv Vecteur d'initialisation utilisé
         */
        public EncryptedData(byte[] ciphertext, byte[] iv) {
            this.ciphertext = Objects.requireNonNull(ciphertext, "Le texte chiffré ne peut pas être null");
            this.iv = Objects.requireNonNull(iv, "L'IV ne peut pas être null");
            
            if (iv.length != IV_LENGTH) {
                throw new IllegalArgumentException(
                    "Longueur d'IV invalide. Attendu: " + IV_LENGTH + " octets, reçu: " + iv.length + " octets"
                );
            }
        }
        
        /**
         * @return Données chiffrées (copie pour éviter les modifications)
         */
        public byte[] getCiphertext() {
            return Arrays.copyOf(ciphertext, ciphertext.length);
        }
        
        /**
         * @return Vecteur d'initialisation (copie pour éviter les modifications)
         */
        public byte[] getIv() {
            return Arrays.copyOf(iv, iv.length);
        }
        
        /**
         * Encode les données chiffrées en Base64 pour stockage
         * 
         * @return Texte chiffré encodé en Base64
         */
        public String getCiphertextBase64() {
            return Base64.getEncoder().encodeToString(ciphertext);
        }
        
        /**
         * Encode l'IV en Base64 pour stockage
         * 
         * @return IV encodé en Base64
         */
        public String getIvBase64() {
            return Base64.getEncoder().encodeToString(iv);
        }
        
        /**
         * Combine le ciphertext et l'IV en un seul tableau pour stockage compact
         * Format: [IV (12 octets)][Ciphertext (n octets)]
         * 
         * @return Données combinées
         */
        public byte[] toCombinedArray() {
            byte[] combined = new byte[iv.length + ciphertext.length];
            System.arraycopy(iv, 0, combined, 0, iv.length);
            System.arraycopy(ciphertext, 0, combined, iv.length, ciphertext.length);
            return combined;
        }
        
        /**
         * Crée un EncryptedData depuis un tableau combiné
         * 
         * @param combined Tableau combiné [IV][Ciphertext]
         * @return EncryptedData reconstruit
         */
        public static EncryptedData fromCombinedArray(byte[] combined) {
            Objects.requireNonNull(combined, "Le tableau combiné ne peut pas être null");
            
            if (combined.length <= IV_LENGTH) {
                throw new IllegalArgumentException(
                    "Tableau combiné trop court. Longueur minimale: " + (IV_LENGTH + 1) + " octets"
                );
            }
            
            byte[] iv = Arrays.copyOfRange(combined, 0, IV_LENGTH);
            byte[] ciphertext = Arrays.copyOfRange(combined, IV_LENGTH, combined.length);
            
            return new EncryptedData(ciphertext, iv);
        }
        
        /**
         * Crée un EncryptedData depuis des chaînes Base64
         * 
         * @param ciphertextBase64 Texte chiffré en Base64
         * @param ivBase64 IV en Base64
         * @return EncryptedData reconstruit
         */
        public static EncryptedData fromBase64(String ciphertextBase64, String ivBase64) {
            byte[] ciphertext = Base64.getDecoder().decode(ciphertextBase64);
            byte[] iv = Base64.getDecoder().decode(ivBase64);
            return new EncryptedData(ciphertext, iv);
        }
        
        /**
         * Efface les données sensibles de la mémoire
         */
        public void clear() {
            Arrays.fill(ciphertext, (byte) 0);
            Arrays.fill(iv, (byte) 0);
        }
        
        @Override
        public String toString() {
            return "EncryptedData{" +
                    "ciphertextLength=" + ciphertext.length +
                    ", ivLength=" + iv.length +
                    '}';
        }
    }
}
