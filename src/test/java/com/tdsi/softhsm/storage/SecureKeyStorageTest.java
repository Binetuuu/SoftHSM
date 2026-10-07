package com.tdsi.softhsm.storage;

import com.tdsi.softhsm.model.CryptographicKey;
import com.tdsi.softhsm.model.enums.Algorithm;
import com.tdsi.softhsm.model.enums.KeyStatus;
import com.tdsi.softhsm.model.enums.KeyType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.io.TempDir;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests unitaires pour SecureKeyStorage
 */
@DisplayName("Tests du stockage sécurisé de clés")
class SecureKeyStorageTest {
    
    private SecureKeyStorage secureStorage;
    private Path tempKeystorePath;
    private char[] keystorePassword;
    private char[] masterPassword;
    
    @BeforeEach
    void setUp(@TempDir Path tempDir) throws Exception {
        tempKeystorePath = tempDir.resolve("test_secure.p12");
        keystorePassword = "KS_P@ssw0rd123!".toCharArray();
        masterPassword = "M@ster_P@ssw0rd456!".toCharArray();
        
        secureStorage = new SecureKeyStorage(
            tempKeystorePath, 
            keystorePassword, 
            masterPassword
        );
    }
    
    @Test
    @DisplayName("Devrait initialiser le stockage sécurisé")
    void shouldInitializeSecureStorage() {
        assertNotNull(secureStorage);
        assertTrue(secureStorage.verifyIntegrity());
    }
    
    @Test
    @DisplayName("Devrait stocker et récupérer une clé")
    void shouldStoreAndRetrieveKey() throws Exception {
        // Créer une clé de test
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey secretKey = keyGen.generateKey();
        
        CryptographicKey keyMetadata = CryptographicKey.builder()
            .alias("test-aes-key")
            .algorithm(Algorithm.AES_256)
            .keyType(KeyType.SYMMETRIC)
            .keySize(256)
            .owner("testuser")
            .status(KeyStatus.ACTIVE)
            .createdAt(LocalDateTime.now())
            .description("Clé de test")
            .build();
        
        char[] keyPassword = "Key_P@ss123!".toCharArray();
        
        // Stocker la clé
        secureStorage.storeKey(keyMetadata, secretKey, keyPassword);
        
        // Vérifier que la clé existe
        assertTrue(secureStorage.keyExists(keyMetadata.getId()));
        assertEquals(1, secureStorage.getKeyCount());
        
        // Récupérer la clé
        SecretKey retrievedKey = secureStorage.retrieveKey(keyMetadata.getId(), keyPassword);
        
        assertNotNull(retrievedKey);
        assertArrayEquals(secretKey.getEncoded(), retrievedKey.getEncoded());
    }
    
    @Test
    @DisplayName("Devrait échouer à récupérer une clé avec un mauvais mot de passe")
    void shouldFailToRetrieveKeyWithWrongPassword() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey secretKey = keyGen.generateKey();
        
        CryptographicKey keyMetadata = CryptographicKey.builder()
            .alias("password-test-key")
            .algorithm(Algorithm.AES_256)
            .keyType(KeyType.SYMMETRIC)
            .keySize(256)
            .owner("testuser")
            .status(KeyStatus.ACTIVE)
            .createdAt(LocalDateTime.now())
            .build();
        
        char[] correctPassword = "Correct123!".toCharArray();
        char[] wrongPassword = "Wrong123!".toCharArray();
        
        secureStorage.storeKey(keyMetadata, secretKey, correctPassword);
        
        assertThrows(KeyStorageException.class, () -> {
            secureStorage.retrieveKey(keyMetadata.getId(), wrongPassword);
        });
    }
    
    @Test
    @DisplayName("Devrait lister toutes les clés stockées")
    void shouldListAllStoredKeys() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        char[] keyPassword = "Key_P@ss123!".toCharArray();
        
        String[] keyAliases = {"key1", "key2", "key3"};
        
        for (String alias : keyAliases) {
            SecretKey secretKey = keyGen.generateKey();
            CryptographicKey keyMetadata = CryptographicKey.builder()
                .alias(alias)
                .algorithm(Algorithm.AES_256)
                .keyType(KeyType.SYMMETRIC)
                .keySize(256)
                .owner("testuser")
                .status(KeyStatus.ACTIVE)
                .createdAt(LocalDateTime.now())
                .build();
            
            secureStorage.storeKey(keyMetadata, secretKey, keyPassword);
        }
        
        List<String> keyIds = secureStorage.listKeyIds();
        assertEquals(keyAliases.length, keyIds.size());
    }
    
    @Test
    @DisplayName("Devrait obtenir les métadonnées d'une clé")
    void shouldGetKeyMetadata() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey secretKey = keyGen.generateKey();
        
        CryptographicKey originalMetadata = CryptographicKey.builder()
            .alias("metadata-test")
            .algorithm(Algorithm.AES_256)
            .keyType(KeyType.SYMMETRIC)
            .keySize(256)
            .owner("testuser")
            .status(KeyStatus.ACTIVE)
            .createdAt(LocalDateTime.now())
            .description("Test metadata")
            .build();
        
        char[] keyPassword = "Key_P@ss123!".toCharArray();
        secureStorage.storeKey(originalMetadata, secretKey, keyPassword);
        
        SecureKeyStorage.KeyMetadata metadata = 
            secureStorage.getKeyMetadata(originalMetadata.getId());
        
        assertNotNull(metadata);
        assertEquals(originalMetadata.getId(), metadata.getKeyId());
        assertEquals(originalMetadata.getAlgorithm().name(), metadata.getAlgorithm());
        assertEquals(originalMetadata.getKeyType(), metadata.getKeyType());
        assertEquals(originalMetadata.getDescription(), metadata.getDescription());
    }
    
    @Test
    @DisplayName("Devrait supprimer une clé")
    void shouldDeleteKey() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey secretKey = keyGen.generateKey();
        
        CryptographicKey keyMetadata = CryptographicKey.builder()
            .alias("key-to-delete")
            .algorithm(Algorithm.AES_256)
            .keyType(KeyType.SYMMETRIC)
            .keySize(256)
            .owner("testuser")
            .status(KeyStatus.ACTIVE)
            .createdAt(LocalDateTime.now())
            .build();
        
        char[] keyPassword = "Key_P@ss123!".toCharArray();
        secureStorage.storeKey(keyMetadata, secretKey, keyPassword);
        
        assertTrue(secureStorage.keyExists(keyMetadata.getId()));
        
        secureStorage.deleteKey(keyMetadata.getId());
        
        assertFalse(secureStorage.keyExists(keyMetadata.getId()));
        assertEquals(0, secureStorage.getKeyCount());
    }
    
    @Test
    @DisplayName("Devrait échouer à supprimer une clé inexistante")
    void shouldFailToDeleteNonExistentKey() {
        assertThrows(KeyStorageException.class, () -> {
            secureStorage.deleteKey("non-existent-key-id");
        });
    }
    
    @Test
    @DisplayName("Devrait échouer à stocker une clé avec le même ID")
    void shouldFailToStoreDuplicateKeyId() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey secretKey = keyGen.generateKey();
        
        CryptographicKey keyMetadata = CryptographicKey.builder()
            .alias("duplicate-test")
            .algorithm(Algorithm.AES_256)
            .keyType(KeyType.SYMMETRIC)
            .keySize(256)
            .owner("testuser")
            .status(KeyStatus.ACTIVE)
            .createdAt(LocalDateTime.now())
            .build();
        
        char[] keyPassword = "Key_P@ss123!".toCharArray();
        
        // Stocker la première fois
        secureStorage.storeKey(keyMetadata, secretKey, keyPassword);
        
        // Tenter de stocker à nouveau avec le même ID
        assertThrows(KeyStorageException.class, () -> {
            secureStorage.storeKey(keyMetadata, secretKey, keyPassword);
        });
    }
    
    @Test
    @DisplayName("Devrait créer une sauvegarde")
    void shouldCreateBackup(@TempDir Path tempDir) throws Exception {
        // Ajouter une clé
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey secretKey = keyGen.generateKey();
        
        CryptographicKey keyMetadata = CryptographicKey.builder()
            .alias("backup-test")
            .algorithm(Algorithm.AES_256)
            .keyType(KeyType.SYMMETRIC)
            .keySize(256)
            .owner("testuser")
            .status(KeyStatus.ACTIVE)
            .createdAt(LocalDateTime.now())
            .build();
        
        secureStorage.storeKey(keyMetadata, secretKey, "Key_P@ss123!".toCharArray());
        
        // Créer une sauvegarde
        Path backupPath = tempDir.resolve("secure_backup.p12");
        secureStorage.backup(backupPath);
        
        assertTrue(java.nio.file.Files.exists(backupPath));
    }
    
    @Test
    @DisplayName("Devrait restaurer depuis une sauvegarde")
    void shouldRestoreFromBackup(@TempDir Path tempDir) throws Exception {
        // Ajouter une clé
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey originalKey = keyGen.generateKey();
        
        CryptographicKey originalMetadata = CryptographicKey.builder()
            .alias("restore-test")
            .algorithm(Algorithm.AES_256)
            .keyType(KeyType.SYMMETRIC)
            .keySize(256)
            .owner("testuser")
            .status(KeyStatus.ACTIVE)
            .createdAt(LocalDateTime.now())
            .build();
        
        char[] keyPassword = "Key_P@ss123!".toCharArray();
        secureStorage.storeKey(originalMetadata, originalKey, keyPassword);
        
        // Créer une sauvegarde
        Path backupPath = tempDir.resolve("restore_backup.p12");
        secureStorage.backup(backupPath);
        
        // Ajouter une autre clé
        SecretKey newKey = keyGen.generateKey();
        CryptographicKey newMetadata = CryptographicKey.builder()
            .alias("new-key")
            .algorithm(Algorithm.AES_256)
            .keyType(KeyType.SYMMETRIC)
            .keySize(256)
            .owner("testuser")
            .status(KeyStatus.ACTIVE)
            .createdAt(LocalDateTime.now())
            .build();
        
        secureStorage.storeKey(newMetadata, newKey, keyPassword);
        assertEquals(2, secureStorage.getKeyCount());
        
        // Restaurer depuis la sauvegarde
        secureStorage.restore(backupPath);
        
        // Vérifier que seule la clé originale existe
        assertEquals(1, secureStorage.getKeyCount());
        assertTrue(secureStorage.keyExists(originalMetadata.getId()));
        assertFalse(secureStorage.keyExists(newMetadata.getId()));
    }
    
    @Test
    @DisplayName("Devrait lever une exception pour des paramètres null")
    void shouldThrowExceptionForNullParameters() {
        assertThrows(NullPointerException.class, () -> {
            new SecureKeyStorage(null, keystorePassword, masterPassword);
        });
        
        assertThrows(NullPointerException.class, () -> {
            new SecureKeyStorage(tempKeystorePath, null, masterPassword);
        });
        
        assertThrows(NullPointerException.class, () -> {
            new SecureKeyStorage(tempKeystorePath, keystorePassword, null);
        });
    }
    
    @Test
    @DisplayName("Devrait vérifier l'intégrité du stockage")
    void shouldVerifyStorageIntegrity() throws Exception {
        assertTrue(secureStorage.verifyIntegrity());
        
        // Ajouter une clé et vérifier à nouveau
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey secretKey = keyGen.generateKey();
        
        CryptographicKey keyMetadata = CryptographicKey.builder()
            .alias("integrity-test")
            .algorithm(Algorithm.AES_256)
            .keyType(KeyType.SYMMETRIC)
            .keySize(256)
            .owner("testuser")
            .status(KeyStatus.ACTIVE)
            .createdAt(LocalDateTime.now())
            .build();
        
        secureStorage.storeKey(keyMetadata, secretKey, "Key_P@ss123!".toCharArray());
        
        assertTrue(secureStorage.verifyIntegrity());
    }
    
    @Test
    @DisplayName("Devrait persister les données entre les instances")
    void shouldPersistDataBetweenInstances() throws Exception {
        // Ajouter une clé avec la première instance
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey secretKey = keyGen.generateKey();
        
        CryptographicKey keyMetadata = CryptographicKey.builder()
            .alias("persistence-test")
            .algorithm(Algorithm.AES_256)
            .keyType(KeyType.SYMMETRIC)
            .keySize(256)
            .owner("testuser")
            .status(KeyStatus.ACTIVE)
            .createdAt(LocalDateTime.now())
            .build();
        
        char[] keyPassword = "Key_P@ss123!".toCharArray();
        secureStorage.storeKey(keyMetadata, secretKey, keyPassword);
        secureStorage.close();
        
        // Créer une nouvelle instance
        SecureKeyStorage newInstance = new SecureKeyStorage(
            tempKeystorePath, 
            keystorePassword, 
            masterPassword
        );
        
        // Vérifier que la clé est toujours là
        assertTrue(newInstance.keyExists(keyMetadata.getId()));
        SecretKey retrievedKey = newInstance.retrieveKey(keyMetadata.getId(), keyPassword);
        assertArrayEquals(secretKey.getEncoded(), retrievedKey.getEncoded());
        
        newInstance.close();
    }
    
    @Test
    @DisplayName("Devrait nettoyer les ressources à la fermeture")
    void shouldCleanupResourcesOnClose() throws Exception {
        // Ajouter une clé
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey secretKey = keyGen.generateKey();
        
        CryptographicKey keyMetadata = CryptographicKey.builder()
            .alias("cleanup-test")
            .algorithm(Algorithm.AES_256)
            .keyType(KeyType.SYMMETRIC)
            .keySize(256)
            .owner("testuser")
            .status(KeyStatus.ACTIVE)
            .createdAt(LocalDateTime.now())
            .build();
        
        secureStorage.storeKey(keyMetadata, secretKey, "Key_P@ss123!".toCharArray());
        
        // Fermer
        secureStorage.close();
        
        // Les fichiers devraient toujours exister
        assertTrue(java.nio.file.Files.exists(tempKeystorePath));
    }
}