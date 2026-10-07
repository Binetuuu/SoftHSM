package com.tdsi.softhsm.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests unitaires pour KeyEncryptionService
 */
@DisplayName("Tests du service de chiffrement de clés")
class KeyEncryptionServiceTest {
    
    private KeyEncryptionService encryptionService;
    private SecretKey testEncryptionKey;
    
    @BeforeEach
    void setUp() throws Exception {
        encryptionService = new KeyEncryptionService();
        
        // Générer une clé de chiffrement AES-256 pour les tests
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        testEncryptionKey = keyGen.generateKey();
    }
    
    @Test
    @DisplayName("Devrait chiffrer et déchiffrer des données correctement")
    void shouldEncryptAndDecryptDataCorrectly() throws EncryptionException {
        byte[] plaintext = "Données sensibles à protéger".getBytes();
        
        // Chiffrer
        KeyEncryptionService.EncryptedData encrypted = 
            encryptionService.encrypt(plaintext, testEncryptionKey);
        
        assertNotNull(encrypted);
        assertNotNull(encrypted.getCiphertext());
        assertNotNull(encrypted.getIv());
        assertEquals(12, encrypted.getIv().length, "L'IV devrait faire 12 octets");
        
        // Déchiffrer
        byte[] decrypted = encryptionService.decrypt(encrypted, testEncryptionKey);
        
        assertArrayEquals(plaintext, decrypted, 
            "Les données déchiffrées devraient être identiques aux données originales");
    }
    
    @Test
    @DisplayName("Devrait produire des ciphertexts différents pour le même plaintext")
    void shouldProduceDifferentCiphertextsForSamePlaintext() throws EncryptionException {
        byte[] plaintext = "Données sensibles".getBytes();
        
        KeyEncryptionService.EncryptedData encrypted1 = 
            encryptionService.encrypt(plaintext, testEncryptionKey);
        KeyEncryptionService.EncryptedData encrypted2 = 
            encryptionService.encrypt(plaintext, testEncryptionKey);
        
        assertFalse(Arrays.equals(encrypted1.getCiphertext(), encrypted2.getCiphertext()),
            "Les ciphertexts devraient être différents (IVs différents)");
        assertFalse(Arrays.equals(encrypted1.getIv(), encrypted2.getIv()),
            "Les IVs devraient être différents");
    }
    
    @Test
    @DisplayName("Devrait échouer à déchiffrer avec une mauvaise clé")
    void shouldFailToDecryptWithWrongKey() throws Exception {
        byte[] plaintext = "Données sensibles".getBytes();
        
        KeyEncryptionService.EncryptedData encrypted = 
            encryptionService.encrypt(plaintext, testEncryptionKey);
        
        // Générer une autre clé
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey wrongKey = keyGen.generateKey();
        
        assertThrows(EncryptionException.class, () -> {
            encryptionService.decrypt(encrypted, wrongKey);
        });
    }
    
    @Test
    @DisplayName("Devrait échouer à déchiffrer avec un IV modifié")
    void shouldFailToDecryptWithModifiedIV() throws EncryptionException {
        byte[] plaintext = "Données sensibles".getBytes();
        
        KeyEncryptionService.EncryptedData encrypted = 
            encryptionService.encrypt(plaintext, testEncryptionKey);
        
        // Modifier l'IV
        byte[] modifiedIv = encrypted.getIv();
        modifiedIv[0] = (byte) (modifiedIv[0] ^ 0xFF);
        KeyEncryptionService.EncryptedData tamperedData = 
            new KeyEncryptionService.EncryptedData(encrypted.getCiphertext(), modifiedIv);
        
        assertThrows(EncryptionException.class, () -> {
            encryptionService.decrypt(tamperedData, testEncryptionKey);
        });
    }
    
    @Test
    @DisplayName("Devrait échouer à déchiffrer avec un ciphertext modifié")
    void shouldFailToDecryptWithModifiedCiphertext() throws EncryptionException {
        byte[] plaintext = "Données sensibles".getBytes();
        
        KeyEncryptionService.EncryptedData encrypted = 
            encryptionService.encrypt(plaintext, testEncryptionKey);
        
        // Modifier le ciphertext
        byte[] modifiedCiphertext = encrypted.getCiphertext();
        modifiedCiphertext[0] = (byte) (modifiedCiphertext[0] ^ 0xFF);
        KeyEncryptionService.EncryptedData tamperedData = 
            new KeyEncryptionService.EncryptedData(modifiedCiphertext, encrypted.getIv());
        
        assertThrows(EncryptionException.class, () -> {
            encryptionService.decrypt(tamperedData, testEncryptionKey);
        });
    }
    
    @Test
    @DisplayName("Devrait chiffrer et déchiffrer une clé secrète")
    void shouldEncryptAndDecryptSecretKey() throws Exception {
        // Générer une clé à chiffrer
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey keyToEncrypt = keyGen.generateKey();
        byte[] originalKeyBytes = keyToEncrypt.getEncoded();
        
        // Chiffrer la clé
        KeyEncryptionService.EncryptedData encrypted = 
            encryptionService.encryptKey(keyToEncrypt, testEncryptionKey);
        
        assertNotNull(encrypted);
        
        // Déchiffrer la clé
        SecretKey decryptedKey = encryptionService.decryptKey(
            encrypted, testEncryptionKey, "AES");
        
        assertArrayEquals(originalKeyBytes, decryptedKey.getEncoded(),
            "La clé déchiffrée devrait être identique à la clé originale");
    }
    
    @Test
    @DisplayName("Devrait lever une exception pour des données null à chiffrer")
    void shouldThrowExceptionForNullDataToEncrypt() {
        assertThrows(NullPointerException.class, () -> {
            encryptionService.encrypt(null, testEncryptionKey);
        });
    }
    
    @Test
    @DisplayName("Devrait lever une exception pour une clé de chiffrement null")
    void shouldThrowExceptionForNullEncryptionKey() {
        byte[] plaintext = "test".getBytes();
        
        assertThrows(NullPointerException.class, () -> {
            encryptionService.encrypt(plaintext, null);
        });
    }
    
    @Test
    @DisplayName("Devrait lever une exception pour des données vides à chiffrer")
    void shouldThrowExceptionForEmptyDataToEncrypt() {
        byte[] plaintext = new byte[0];
        
        assertThrows(IllegalArgumentException.class, () -> {
            encryptionService.encrypt(plaintext, testEncryptionKey);
        });
    }
    
    @Test
    @DisplayName("Devrait générer une clé de chiffrement AES-256")
    void shouldGenerateAES256EncryptionKey() throws EncryptionException {
        SecretKey key = encryptionService.generateEncryptionKey();
        
        assertNotNull(key);
        assertEquals("AES", key.getAlgorithm());
        assertEquals(32, key.getEncoded().length, "La clé devrait faire 32 octets (256 bits)");
    }
    
    @Test
    @DisplayName("Devrait créer une clé à partir d'octets dérivés")
    void shouldCreateKeyFromDerivedBytes() throws EncryptionException {
        byte[] derivedBytes = new byte[32]; // 256 bits
        for (int i = 0; i < derivedBytes.length; i++) {
            derivedBytes[i] = (byte) i;
        }
        
        SecretKey key = encryptionService.createKeyFromDerived(derivedBytes);
        
        assertNotNull(key);
        assertEquals("AES", key.getAlgorithm());
        assertArrayEquals(derivedBytes, key.getEncoded());
    }
    
    @Test
    @DisplayName("Devrait lever une exception pour des octets dérivés de longueur invalide")
    void shouldThrowExceptionForInvalidDerivedBytesLength() {
        byte[] invalidBytes = new byte[16]; // 128 bits au lieu de 256
        
        assertThrows(EncryptionException.class, () -> {
            encryptionService.createKeyFromDerived(invalidBytes);
        });
    }
    
    @Test
    @DisplayName("EncryptedData devrait fournir les données en Base64")
    void encryptedDataShouldProvideBase64Encoding() throws EncryptionException {
        byte[] plaintext = "Test".getBytes();
        
        KeyEncryptionService.EncryptedData encrypted = 
            encryptionService.encrypt(plaintext, testEncryptionKey);
        
        String ciphertextBase64 = encrypted.getCiphertextBase64();
        String ivBase64 = encrypted.getIvBase64();
        
        assertNotNull(ciphertextBase64);
        assertNotNull(ivBase64);
        assertFalse(ciphertextBase64.isEmpty());
        assertFalse(ivBase64.isEmpty());
        
        // Reconstruire depuis Base64
        KeyEncryptionService.EncryptedData reconstructed = 
            KeyEncryptionService.EncryptedData.fromBase64(ciphertextBase64, ivBase64);
        
        assertArrayEquals(encrypted.getCiphertext(), reconstructed.getCiphertext());
        assertArrayEquals(encrypted.getIv(), reconstructed.getIv());
    }
    
    @Test
    @DisplayName("EncryptedData devrait supporter le format combiné")
    void encryptedDataShouldSupportCombinedFormat() throws EncryptionException {
        byte[] plaintext = "Test".getBytes();
        
        KeyEncryptionService.EncryptedData encrypted = 
            encryptionService.encrypt(plaintext, testEncryptionKey);
        
        // Convertir en tableau combiné
        byte[] combined = encrypted.toCombinedArray();
        
        assertNotNull(combined);
        assertEquals(encrypted.getIv().length + encrypted.getCiphertext().length, 
            combined.length);
        
        // Reconstruire depuis le tableau combiné
        KeyEncryptionService.EncryptedData reconstructed = 
            KeyEncryptionService.EncryptedData.fromCombinedArray(combined);
        
        assertArrayEquals(encrypted.getCiphertext(), reconstructed.getCiphertext());
        assertArrayEquals(encrypted.getIv(), reconstructed.getIv());
    }
    
    @Test
    @DisplayName("Devrait lever une exception pour un IV de longueur invalide")
    void shouldThrowExceptionForInvalidIVLength() {
        byte[] ciphertext = new byte[16];
        byte[] invalidIv = new byte[8]; // Trop court
        
        assertThrows(IllegalArgumentException.class, () -> {
            new KeyEncryptionService.EncryptedData(ciphertext, invalidIv);
        });
    }
    
    @Test
    @DisplayName("Devrait chiffrer de grandes quantités de données")
    void shouldEncryptLargeData() throws EncryptionException {
        byte[] largePlaintext = new byte[1024 * 1024]; // 1 MB
        Arrays.fill(largePlaintext, (byte) 42);
        
        KeyEncryptionService.EncryptedData encrypted = 
            encryptionService.encrypt(largePlaintext, testEncryptionKey);
        
        byte[] decrypted = encryptionService.decrypt(encrypted, testEncryptionKey);
        
        assertArrayEquals(largePlaintext, decrypted);
    }
}
