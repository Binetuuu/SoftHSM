package com.tdsi.softhsm;

import com.tdsi.softhsm.core.KeyGenerationRequest;
import com.tdsi.softhsm.core.KeyGenerationResult;
import com.tdsi.softhsm.core.KeyGenerator;
import com.tdsi.softhsm.model.User;
import com.tdsi.softhsm.model.enums.Algorithm;
import com.tdsi.softhsm.model.enums.UserRole;
import com.tdsi.softhsm.security.KeyAccessControl;
import com.tdsi.softhsm.storage.SecureKeyStorage;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.LocalDateTime;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test d'intégration pour le Module 2 : Stockage sécurisé des clés
 */
@DisplayName("Tests d'intégration du Module 2")
class Module2IntegrationTest {
    
    private KeyGenerator keyGenerator;
    private SecureKeyStorage secureStorage;
    private KeyAccessControl accessControl;
    private User adminUser;
    private User operatorUser;
    private User regularUser;
    
    @BeforeEach
    void setUp(@TempDir Path tempDir) throws Exception {
        // Initialiser le générateur de clés
        keyGenerator = new KeyGenerator();
        
        // Initialiser le stockage sécurisé
        Path keystorePath = tempDir.resolve("integration_test.p12");
        char[] keystorePassword = "IntegrationP@ss123!".toCharArray();
        char[] masterPassword = "M@sterP@ss456!".toCharArray();
        
        secureStorage = new SecureKeyStorage(keystorePath, keystorePassword, masterPassword);
        
        // Initialiser le contrôle d'accès
        Path auditLogPath = tempDir.resolve("integration_audit.log");
        accessControl = new KeyAccessControl(true, auditLogPath);
        
        // Initialiser le système de sécurité dans le générateur
        keyGenerator.initializeSecurity(secureStorage, accessControl);
        
        // Créer des utilisateurs de test
        adminUser = new User("integration_admin", UserRole.ADMIN);
        operatorUser = new User("integration_operator", UserRole.OPERATOR);
        regularUser = new User("integration_user", UserRole.USER);
        
        // Enregistrer les sessions
        accessControl.registerSession(adminUser);
        accessControl.registerSession(operatorUser);
        accessControl.registerSession(regularUser);
    }
    
    @Test
    @DisplayName("Flux complet : génération, stockage et récupération de clé AES par un opérateur")
    void completeWorkflowAESKeyByOperator() throws Exception {
        // Créer une requête de génération de clé AES
        KeyGenerationRequest request = KeyGenerationRequest.builder()
            .alias("integration-aes-test")
            .algorithm(Algorithm.AES_256)
            .owner(operatorUser.getUsername())
            .description("Clé de test d'intégration AES-256")
            .expirationDate(LocalDateTime.now().plusDays(30))
            .build();
        
        char[] keyPassword = "KeyProtection123!".toCharArray();
        
        // L'opérateur devrait pouvoir générer la clé
        KeyGenerationResult result = keyGenerator.generateAndStoreKey(
            request, operatorUser, keyPassword);
        
        assertTrue(result.isSuccess());
        assertNotNull(result.getMetadata());
        assertEquals("integration-aes-test", result.getMetadata().getAlias());
        
        // Vérifier que la clé est stockée
        assertTrue(secureStorage.keyExists(result.getMetadata().getId()));
        assertEquals(1, secureStorage.getKeyCount());
        
        // Vérifier les métadonnées
        SecureKeyStorage.KeyMetadata metadata = 
            secureStorage.getKeyMetadata(result.getMetadata().getId());
        assertNotNull(metadata);
        assertEquals(Algorithm.AES_256.name(), metadata.getAlgorithm());
        
        // Récupérer la clé
        javax.crypto.SecretKey retrievedKey = 
            secureStorage.retrieveKey(result.getMetadata().getId(), keyPassword);
        assertNotNull(retrievedKey);
        assertEquals("AES", retrievedKey.getAlgorithm());
    }
    
    @Test
    @DisplayName("Un utilisateur régulier ne devrait pas pouvoir générer de clés")
    void regularUserCannotGenerateKeys() throws Exception {
        KeyGenerationRequest request = KeyGenerationRequest.builder()
            .alias("unauthorized-key")
            .algorithm(Algorithm.AES_256)
            .owner(regularUser.getUsername())
            .build();
        
        char[] keyPassword = "KeyProtection123!".toCharArray();
        
        // L'utilisateur régulier ne devrait pas pouvoir générer de clés
        Exception exception = assertThrows(Exception.class, () -> {
            keyGenerator.generateAndStoreKey(request, regularUser, keyPassword);
        });
        
        // Aucune clé ne devrait être stockée
        assertEquals(0, secureStorage.getKeyCount());
    }
    
    @Test
    @DisplayName("L'administrateur devrait pouvoir effectuer toutes les opérations")
    void adminCanPerformAllOperations() throws Exception {
        // Générer une clé RSA
        KeyGenerationRequest request = KeyGenerationRequest.builder()
            .alias("admin-rsa-key")
            .algorithm(Algorithm.RSA_2048)
            .owner(adminUser.getUsername())
            .description("Clé RSA administrateur")
            .build();
        
        char[] keyPassword = "AdminKeyP@ss123!".toCharArray();
        
        // L'admin devrait pouvoir générer la clé
        KeyGenerationResult result = keyGenerator.generateAndStoreKey(
            request, adminUser, keyPassword);
        
        assertTrue(result.isSuccess());
        String keyId = result.getMetadata().getId();
        
        // L'admin devrait pouvoir consulter les métadonnées
        SecureKeyStorage.KeyMetadata metadata = secureStorage.getKeyMetadata(keyId);
        assertNotNull(metadata);
        
        // L'admin devrait pouvoir récupérer la clé
        javax.crypto.SecretKey retrievedKey = secureStorage.retrieveKey(keyId, keyPassword);
        assertNotNull(retrievedKey);
        
        // L'admin devrait pouvoir supprimer la clé
        secureStorage.deleteKey(keyId);
        assertFalse(secureStorage.keyExists(keyId));
    }
    
    @Test
    @DisplayName("Les logs d'audit devraient enregistrer toutes les activités")
    void auditLogsShouldRecordAllActivities() throws Exception {
        // Effectuer plusieurs opérations
        KeyGenerationRequest request1 = KeyGenerationRequest.builder()
            .alias("audit-test-1")
            .algorithm(Algorithm.AES_256)
            .owner(operatorUser.getUsername())
            .build();
        
        KeyGenerationRequest request2 = KeyGenerationRequest.builder()
            .alias("audit-test-2")
            .algorithm(Algorithm.AES_192)
            .owner(adminUser.getUsername())
            .build();
        
        char[] keyPassword = "AuditTest123!".toCharArray();
        
        // Générer les clés
        keyGenerator.generateAndStoreKey(request1, operatorUser, keyPassword);
        keyGenerator.generateAndStoreKey(request2, adminUser, keyPassword);
        
        // Vérifier les logs d'audit
        java.util.List<String> logs = accessControl.readAuditLog(20);
        
        assertFalse(logs.isEmpty());
        
        // Vérifier que les activités sont enregistrées
        boolean operatorActivity = logs.stream()
            .anyMatch(log -> log.contains(operatorUser.getUsername()) && log.contains("GENERATE"));
        boolean adminActivity = logs.stream()
            .anyMatch(log -> log.contains(adminUser.getUsername()) && log.contains("GENERATE"));
        
        assertTrue(operatorActivity, "L'activité de l'opérateur devrait être enregistrée");
        assertTrue(adminActivity, "L'activité de l'admin devrait être enregistrée");
    }
    
    @Test
    @DisplayName("Sauvegarde et restauration complètes du système")
    void completeBackupAndRestore(@TempDir Path tempDir) throws Exception {
        // Générer quelques clés
        KeyGenerationRequest request1 = KeyGenerationRequest.builder()
            .alias("backup-key-1")
            .algorithm(Algorithm.AES_256)
            .owner(operatorUser.getUsername())
            .build();
        
        KeyGenerationRequest request2 = KeyGenerationRequest.builder()
            .alias("backup-key-2")
            .algorithm(Algorithm.ECC_P256)
            .owner(adminUser.getUsername())
            .build();
        
        char[] keyPassword = "BackupTest123!".toCharArray();
        
        KeyGenerationResult result1 = keyGenerator.generateAndStoreKey(request1, operatorUser, keyPassword);
        KeyGenerationResult result2 = keyGenerator.generateAndStoreKey(request2, adminUser, keyPassword);
        
        assertEquals(2, secureStorage.getKeyCount());
        
        // Créer une sauvegarde
        Path backupPath = tempDir.resolve("integration_backup.p12");
        secureStorage.backup(backupPath);
        
        assertTrue(java.nio.file.Files.exists(backupPath));
        
        // Ajouter une autre clé après la sauvegarde
        KeyGenerationRequest request3 = KeyGenerationRequest.builder()
            .alias("post-backup-key")
            .algorithm(Algorithm.CHACHA20)
            .owner(adminUser.getUsername())
            .build();
        
        keyGenerator.generateAndStoreKey(request3, adminUser, keyPassword);
        assertEquals(3, secureStorage.getKeyCount());
        
        // Restaurer depuis la sauvegarde
        secureStorage.restore(backupPath);
        
        // Vérifier que seules les 2 clés originales existent
        assertEquals(2, secureStorage.getKeyCount());
        assertTrue(secureStorage.keyExists(result1.getMetadata().getId()));
        assertTrue(secureStorage.keyExists(result2.getMetadata().getId()));
    }
    
    @Test
    @DisplayName("Vérification de l'intégrité du système complet")
    void completeSystemIntegrityCheck() throws Exception {
        // Test de l'intégrité initiale
        assertTrue(secureStorage.verifyIntegrity());
        
        // Ajouter des clés de différents types
        KeyGenerationRequest[] requests = {
            KeyGenerationRequest.builder()
                .alias("integrity-aes")
                .algorithm(Algorithm.AES_256)
                .owner(operatorUser.getUsername())
                .build(),
            KeyGenerationRequest.builder()
                .alias("integrity-rsa")
                .algorithm(Algorithm.RSA_2048)
                .owner(adminUser.getUsername())
                .build(),
            KeyGenerationRequest.builder()
                .alias("integrity-ecc")
                .algorithm(Algorithm.ECC_P256)
                .owner(operatorUser.getUsername())
                .build()
        };
        
        char[] keyPassword = "IntegrityTest123!".toCharArray();
        
        for (KeyGenerationRequest request : requests) {
            KeyGenerationResult result = keyGenerator.generateAndStoreKey(
                request, 
                request.getOwner().equals(adminUser.getUsername()) ? adminUser : operatorUser, 
                keyPassword
            );
            assertTrue(result.isSuccess());
        }
        
        // Vérifier l'intégrité après ajout de clés
        assertTrue(secureStorage.verifyIntegrity());
        assertEquals(requests.length, secureStorage.getKeyCount());
        
        // Vérifier que toutes les clés sont récupérables
        java.util.List<String> keyIds = secureStorage.listKeyIds();
        assertEquals(requests.length, keyIds.size());
        
        for (String keyId : keyIds) {
            javax.crypto.SecretKey key = secureStorage.retrieveKey(keyId, keyPassword);
            assertNotNull(key);
            
            SecureKeyStorage.KeyMetadata metadata = secureStorage.getKeyMetadata(keyId);
            assertNotNull(metadata);
        }
    }
}