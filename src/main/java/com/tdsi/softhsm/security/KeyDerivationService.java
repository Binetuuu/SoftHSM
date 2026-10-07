package com.tdsi.softhsm.security;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;

/**
 * Service de dérivation de clés cryptographiques à partir de mots de passe.
 * Utilise PBKDF2 (Password-Based Key Derivation Function 2) avec HMAC-SHA256.
 * 
 * Ce service protège contre les attaques par force brute en :
 * - Utilisant un salt aléatoire unique pour chaque mot de passe
 * - Appliquant de nombreuses itérations (ralentissement intentionnel)
 * - Générant des clés de longueur configurable
 */
public class KeyDerivationService {
    
    /**
     * Algorithme de dérivation utilisé
     */
    private static final String PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256";
    
    /**
     * Nombre d'itérations PBKDF2 (recommandé : minimum 100,000)
     * Plus élevé = plus sécurisé mais plus lent
     */
    private static final int DEFAULT_ITERATIONS = 210_000;
    
    /**
     * Longueur du salt en octets (recommandé : minimum 16 octets)
     */
    private static final int SALT_LENGTH = 32;
    
    /**
     * Longueur de la clé dérivée en bits (256 bits = 32 octets pour AES-256)
     */
    private static final int DEFAULT_KEY_LENGTH = 256;
    
    private final SecureRandom secureRandom;
    private final int iterations;
    private final int keyLength;
    
    /**
     * Constructeur avec paramètres par défaut
     */
    public KeyDerivationService() {
        this(DEFAULT_ITERATIONS, DEFAULT_KEY_LENGTH);
    }
    
    /**
     * Constructeur avec paramètres personnalisés
     * 
     * @param iterations Nombre d'itérations PBKDF2 (minimum 100,000 recommandé)
     * @param keyLength Longueur de la clé en bits (128, 192 ou 256)
     */
    public KeyDerivationService(int iterations, int keyLength) {
        if (iterations < 100_000) {
            throw new IllegalArgumentException(
                "Le nombre d'itérations doit être d'au moins 100,000 pour une sécurité adéquate"
            );
        }
        if (keyLength != 128 && keyLength != 192 && keyLength != 256) {
            throw new IllegalArgumentException(
                "La longueur de clé doit être 128, 192 ou 256 bits"
            );
        }
        
        this.secureRandom = new SecureRandom();
        this.iterations = iterations;
        this.keyLength = keyLength;
    }
    
    /**
     * Génère un salt cryptographiquement sécurisé
     * 
     * @return Salt aléatoire
     */
    public byte[] generateSalt() {
        byte[] salt = new byte[SALT_LENGTH];
        secureRandom.nextBytes(salt);
        return salt;
    }
    
    /**
     * Dérive une clé cryptographique à partir d'un mot de passe et d'un salt
     * 
     * @param password Mot de passe source (sera effacé après utilisation)
     * @param salt Salt unique pour ce mot de passe
     * @return Clé dérivée
     * @throws KeyDerivationException Si la dérivation échoue
     */
    public byte[] deriveKey(char[] password, byte[] salt) throws KeyDerivationException {
        Objects.requireNonNull(password, "Le mot de passe ne peut pas être null");
        Objects.requireNonNull(salt, "Le salt ne peut pas être null");
        
        if (password.length == 0) {
            throw new IllegalArgumentException("Le mot de passe ne peut pas être vide");
        }
        
        if (salt.length < 16) {
            throw new IllegalArgumentException("Le salt doit faire au moins 16 octets");
        }
        
        try {
            KeySpec spec = new PBEKeySpec(password, salt, iterations, keyLength);
            SecretKeyFactory factory = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
            byte[] derivedKey = factory.generateSecret(spec).getEncoded();
            
            // Nettoyer les données sensibles en mémoire
            clearKeySpec(spec);
            
            return derivedKey;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new KeyDerivationException("Échec de la dérivation de clé", e);
        }
    }
    
    /**
     * Dérive une clé à partir d'un mot de passe avec génération automatique du salt
     * 
     * @param password Mot de passe source
     * @return Résultat contenant la clé dérivée et le salt utilisé
     * @throws KeyDerivationException Si la dérivation échoue
     */
    public DerivedKeyResult deriveKeyWithSalt(char[] password) throws KeyDerivationException {
        byte[] salt = generateSalt();
        byte[] key = deriveKey(password, salt);
        return new DerivedKeyResult(key, salt, iterations, keyLength);
    }
    
    /**
     * Vérifie qu'un mot de passe correspond à une clé dérivée
     * 
     * @param password Mot de passe à vérifier
     * @param expectedKey Clé attendue
     * @param salt Salt utilisé lors de la dérivation originale
     * @return true si le mot de passe est correct
     * @throws KeyDerivationException Si la vérification échoue
     */
    public boolean verifyPassword(char[] password, byte[] expectedKey, byte[] salt) 
            throws KeyDerivationException {
        byte[] derivedKey = deriveKey(password, salt);
        boolean matches = MessageDigest.isEqual(derivedKey, expectedKey);
        
        // Effacer la clé dérivée de la mémoire
        Arrays.fill(derivedKey, (byte) 0);
        
        return matches;
    }
    
    /**
     * Nettoie une KeySpec en mémoire (efface le mot de passe)
     */
    private void clearKeySpec(KeySpec spec) {
        if (spec instanceof PBEKeySpec) {
            ((PBEKeySpec) spec).clearPassword();
        }
    }
    
    /**
     * Encode un salt en Base64 pour stockage
     * 
     * @param salt Salt à encoder
     * @return Salt encodé en Base64
     */
    public static String encodeSalt(byte[] salt) {
        return Base64.getEncoder().encodeToString(salt);
    }
    
    /**
     * Décode un salt depuis Base64
     * 
     * @param encodedSalt Salt encodé en Base64
     * @return Salt décodé
     */
    public static byte[] decodeSalt(String encodedSalt) {
        return Base64.getDecoder().decode(encodedSalt);
    }
    
    /**
     * Obtient le nombre d'itérations configuré
     * 
     * @return Nombre d'itérations
     */
    public int getIterations() {
        return iterations;
    }
    
    /**
     * Obtient la longueur de clé configurée
     * 
     * @return Longueur en bits
     */
    public int getKeyLength() {
        return keyLength;
    }
    
    /**
     * Classe utilitaire pour comparaison sécurisée
     */
    private static class MessageDigest {
        /**
         * Compare deux tableaux d'octets de manière sécurisée (protection contre timing attacks)
         */
        public static boolean isEqual(byte[] a, byte[] b) {
            if (a == null || b == null) {
                return a == b;
            }
            if (a.length != b.length) {
                return false;
            }
            
            int result = 0;
            for (int i = 0; i < a.length; i++) {
                result |= a[i] ^ b[i];
            }
            return result == 0;
        }
    }
    
    /**
     * Résultat d'une dérivation de clé contenant la clé et les paramètres utilisés
     */
    public static class DerivedKeyResult {
        private final byte[] key;
        private final byte[] salt;
        private final int iterations;
        private final int keyLength;
        
        public DerivedKeyResult(byte[] key, byte[] salt, int iterations, int keyLength) {
            this.key = Objects.requireNonNull(key, "La clé ne peut pas être null");
            this.salt = Objects.requireNonNull(salt, "Le salt ne peut pas être null");
            this.iterations = iterations;
            this.keyLength = keyLength;
        }
        
        public byte[] getKey() {
            return key;
        }
        
        public byte[] getSalt() {
            return salt;
        }
        
        public int getIterations() {
            return iterations;
        }
        
        public int getKeyLength() {
            return keyLength;
        }
        
        /**
         * Encode le salt en Base64 pour stockage
         */
        public String getEncodedSalt() {
            return encodeSalt(salt);
        }
        
        /**
         * Efface les données sensibles de la mémoire
         */
        public void clear() {
            Arrays.fill(key, (byte) 0);
            Arrays.fill(salt, (byte) 0);
        }
        
        @Override
        public String toString() {
            return "DerivedKeyResult{" +
                    "iterations=" + iterations +
                    ", keyLength=" + keyLength +
                    ", saltLength=" + salt.length +
                    '}';
        }
    }
}
