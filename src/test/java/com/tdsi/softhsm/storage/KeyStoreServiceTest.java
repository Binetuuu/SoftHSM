package com.tdsi.softhsm.storage;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.io.TempDir;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.nio.file.Path;
import java.security.KeyStoreException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests unitaires pour KeyStoreService
 */
@DisplayName("Tests du service KeyStore")
class KeyStoreServiceTest {
    
    private KeyStoreService keyStoreService;
    private Path tempKeystorePath;
    private char[] testPassword;
    
    @BeforeEach
    void setUp(@TempDir Path tempDir) throws Exception {
        tempKeystorePath = tempDir.resolve("test_keystore.p12");
        testPassword = "TestP@ssw0rd123!".toCharArray();
        keyStoreService = new KeyStoreService(tempKeystorePath, testPassword);
    }
    
    @Test
    @DisplayName("Devrait créer un nouveau KeyStore s'il n'existe pas")
    void shouldCreateNewKeyStoreIfNotExists() throws Exception {
        // Le KeyStore devrait être créé automatiquement dans setUp()
        assertTrue(keyStoreService.verifyIntegrity(), 
            "Le KeyStore nouvellement créé devrait être intègre");
        assertEquals(0, keyStoreService.size(), 
            "Le nouveau KeyStore devrait être vide");
    }
    
    @Test
    @DisplayName("Devrait stocker et récupérer une clé secrète")
    void shouldStoreAndRetrieveSecretKey() throws Exception {
        // Générer une clé de test
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey testKey = keyGen.generateKey();
        
        String alias = "test-aes-key";
        char[] keyPassword = "KeyP@ss123!".toCharArray();
        
        // Stocker la clé
        keyStoreService.storeSecretKey(alias, testKey, keyPassword);
        
        // Vérifier que la clé existe
        assertTrue(keyStoreService.containsAlias(alias));
        assertEquals(1, keyStoreService.size());
        
        // Récupérer la clé
        SecretKey retrievedKey = keyStoreService.getSecretKey(alias, keyPassword);
        
        assertNotNull(retrievedKey);
        assertEquals(testKey.getAlgorithm(), retrievedKey.getAlgorithm());
        assertArrayEquals(testKey.getEncoded(), retrievedKey.getEncoded());
    }
    
    @Test
    @DisplayName("Devrait échouer à récupérer une clé avec un mauvais mot de passe")
    void shouldFailToRetrieveKeyWithWrongPassword() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey testKey = keyGen.generateKey();
        
        String alias = "test-key";
        char[] correctPassword = "Correct123!".toCharArray();
        char[] wrongPassword = "Wrong123!".toCharArray();
        
        keyStoreService.storeSecretKey(alias, testKey, correctPassword);
        
        assertThrows(KeyStoreException.class, () -> {
            keyStoreService.getSecretKey(alias, wrongPassword);
        });
    }
    
    @Test
    @DisplayName("Devrait lister tous les alias")
    void shouldListAllAliases() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        
        String[] aliases = {"key1", "key2", "key3"};
        char[] keyPassword = "KeyP@ss123!".toCharArray();
        
        for (String alias : aliases) {
            SecretKey key = keyGen.generateKey();
            keyStoreService.storeSecretKey(alias, key, keyPassword);
        }
        
        List<String> storedAliases = keyStoreService.listAliases();
        
        assertEquals(aliases.length, storedAliases.size());
        for (String alias : aliases) {
            assertTrue(storedAliases.contains(alias));
        }
    }
    
    @Test
    @DisplayName("Devrait supprimer une entrée")
    void shouldDeleteEntry() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey testKey = keyGen.generateKey();
        
        String alias = "key-to-delete";
        char[] keyPassword = "KeyP@ss123!".toCharArray();
        
        keyStoreService.storeSecretKey(alias, testKey, keyPassword);
        assertTrue(keyStoreService.containsAlias(alias));
        
        keyStoreService.deleteEntry(alias);
        
        assertFalse(keyStoreService.containsAlias(alias));
        assertEquals(0, keyStoreService.size());
    }
    
    @Test
    @DisplayName("Devrait échouer à supprimer une entrée inexistante")
    void shouldFailToDeleteNonExistentEntry() {
        assertThrows(KeyStoreException.class, () -> {
            keyStoreService.deleteEntry("non-existent-key");
        });
    }
    
    @Test
    @DisplayName("Devrait créer une sauvegarde")
    void shouldCreateBackup(@TempDir Path tempDir) throws Exception {
        // Ajouter une clé au KeyStore
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey testKey = keyGen.generateKey();
        
        keyStoreService.storeSecretKey("backup-test", testKey, "Pass123!".toCharArray());
        
        // Créer une sauvegarde
        Path backupPath = tempDir.resolve("backup.p12");
        keyStoreService.backup(backupPath);
        
        assertTrue(java.nio.file.Files.exists(backupPath));
        assertTrue(java.nio.file.Files.size(backupPath) > 0);
    }
    
    @Test
    @DisplayName("Devrait restaurer depuis une sauvegarde")
    void shouldRestoreFromBackup(@TempDir Path tempDir) throws Exception {
        // Créer un KeyStore avec une clé
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey originalKey = keyGen.generateKey();
        String originalAlias = "original-key";
        
        keyStoreService.storeSecretKey(originalAlias, originalKey, "Pass123!".toCharArray());
        
        // Créer une sauvegarde
        Path backupPath = tempDir.resolve("backup.p12");
        keyStoreService.backup(backupPath);
        
        // Ajouter une autre clé
        SecretKey newKey = keyGen.generateKey();
        keyStoreService.storeSecretKey("new-key", newKey, "Pass123!".toCharArray());
        
        assertEquals(2, keyStoreService.size());
        
        // Restaurer depuis la sauvegarde
        keyStoreService.restore(backupPath);
        
        // Vérifier que seule la clé originale existe
        assertEquals(1, keyStoreService.size());
        assertTrue(keyStoreService.containsAlias(originalAlias));
        assertFalse(keyStoreService.containsAlias("new-key"));
    }
    
    @Test
    @DisplayName("Devrait vérifier l'intégrité du KeyStore")
    void shouldVerifyKeyStoreIntegrity() throws Exception {
        // Ajouter une clé
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey testKey = keyGen.generateKey();
        
        keyStoreService.storeSecretKey("integrity-test", testKey, "Pass123!".toCharArray());
        
        // Vérifier l'intégrité
        assertTrue(keyStoreService.verifyIntegrity());
    }
    
    @Test
    @DisplayName("Devrait changer le mot de passe du KeyStore")
    void shouldChangeKeystorePassword() throws Exception {
        // Ajouter une clé avec l'ancien mot de passe
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey testKey = keyGen.generateKey();
        
        keyStoreService.storeSecretKey("password-test", testKey, "KeyPass123!".toCharArray());
        
        // Changer le mot de passe du KeyStore
        char[] newPassword = "NewP@ssw0rd456!".toCharArray();
        keyStoreService.changePassword(newPassword);
        
        // Vérifier que l'intégrité est maintenue
        assertTrue(keyStoreService.verifyIntegrity());
        
        // Vérifier que la clé est toujours accessible
        SecretKey retrievedKey = keyStoreService.getSecretKey("password-test", "KeyPass123!".toCharArray());
        assertNotNull(retrievedKey);
    }
    
    @Test
    @DisplayName("Devrait lever une exception pour un alias null")
    void shouldThrowExceptionForNullAlias() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey testKey = keyGen.generateKey();
        
        assertThrows(NullPointerException.class, () -> {
            keyStoreService.storeSecretKey(null, testKey, "Pass123!".toCharArray());
        });
    }
    
    @Test
    @DisplayName("Devrait lever une exception pour une clé null")
    void shouldThrowExceptionForNullKey() {
        assertThrows(NullPointerException.class, () -> {
            keyStoreService.storeSecretKey("test", null, "Pass123!".toCharArray());
        });
    }
    
    @Test
    @DisplayName("Devrait lever une exception pour un mot de passe null")
    void shouldThrowExceptionForNullKeyPassword() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey testKey = keyGen.generateKey();
        
        assertThrows(NullPointerException.class, () -> {
            keyStoreService.storeSecretKey("test", testKey, null);
        });
    }
    
    @Test
    @DisplayName("Devrait lever une exception pour récupérer une clé inexistante")
    void shouldThrowExceptionForNonExistentKey() {
        assertThrows(KeyStoreException.class, () -> {
            keyStoreService.getSecretKey("non-existent", "Pass123!".toCharArray());
        });
    }
    
    @Test
    @DisplayName("Devrait retourner le bon chemin du KeyStore")
    void shouldReturnCorrectKeystorePath() {
        assertEquals(tempKeystorePath, keyStoreService.getKeystorePath());
    }
    
    @Test
    @DisplayName("Devrait nettoyer les ressources lors de la fermeture")
    void shouldCleanupResourcesOnClose() throws Exception {
        // Ajouter une clé
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey testKey = keyGen.generateKey();
        
        keyStoreService.storeSecretKey("cleanup-test", testKey, "Pass123!".toCharArray());
        
        // Fermer le service
        keyStoreService.close();
        
        // Le KeyStore devrait rester accessible (les données sont sauvegardées)
        assertTrue(java.nio.file.Files.exists(tempKeystorePath));
    }
    
    @Test
    @DisplayName("Devrait persistant les données entre les instances")
    void shouldPersistDataBetweenInstances() throws Exception {
        // Ajouter une clé avec la première instance
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        SecretKey testKey = keyGen.generateKey();
        String alias = "persistent-key";
        char[] keyPassword = "KeyPass123!".toCharArray();
        
        keyStoreService.storeSecretKey(alias, testKey, keyPassword);
        keyStoreService.close();
        
        // Créer une nouvelle instance pointant vers le même fichier
        KeyStoreService newInstance = new KeyStoreService(tempKeystorePath, testPassword);
        
        // Vérifier que la clé est toujours là
        assertTrue(newInstance.containsAlias(alias));
        SecretKey retrievedKey = newInstance.getSecretKey(alias, keyPassword);
        assertArrayEquals(testKey.getEncoded(), retrievedKey.getEncoded());
        
        newInstance.close();
    }
}