package com.tdsi.softhsm.security;

import com.tdsi.softhsm.model.AccessContext;
import com.tdsi.softhsm.model.User;
import com.tdsi.softhsm.model.enums.KeyOperation;
import com.tdsi.softhsm.model.enums.UserRole;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests unitaires pour KeyAccessControl
 */
@DisplayName("Tests du contrôle d'accès basé sur les rôles")
class KeyAccessControlTest {
    
    private KeyAccessControl accessControl;
    private Path testAuditLogPath;
    
    @BeforeEach
    void setUp(@TempDir Path tempDir) {
        testAuditLogPath = tempDir.resolve("test_audit.log");
        accessControl = new KeyAccessControl(true, testAuditLogPath);
    }
    
    @Test
    @DisplayName("Un administrateur devrait pouvoir effectuer toutes les opérations")
    void adminShouldBeAbleToPerformAllOperations() throws AccessDeniedException {
        User admin = new User("admin", UserRole.ADMIN);
        
        for (KeyOperation operation : KeyOperation.values()) {
            AccessContext context = new AccessContext.Builder()
                .user(admin)
                .operation(operation)
                .build();
            
            assertTrue(accessControl.checkAccess(context),
                "L'admin devrait pouvoir effectuer " + operation);
        }
    }
    
    @Test
    @DisplayName("Un opérateur devrait pouvoir générer des clés")
    void operatorShouldBeAbleToGenerateKeys() throws AccessDeniedException {
        User operator = new User("operator", UserRole.OPERATOR);
        
        AccessContext context = new AccessContext.Builder()
            .user(operator)
            .operation(KeyOperation.GENERATE)
            .build();
        
        assertTrue(accessControl.checkAccess(context));
    }
    
    @Test
    @DisplayName("Un opérateur ne devrait pas pouvoir supprimer des clés")
    void operatorShouldNotBeAbleToDeleteKeys() {
        User operator = new User("operator", UserRole.OPERATOR);
        
        AccessContext context = new AccessContext.Builder()
            .user(operator)
            .operation(KeyOperation.DELETE)
            .build();
        
        assertThrows(AccessDeniedException.class, () -> {
            accessControl.checkAccess(context);
        });
    }
    
    @Test
    @DisplayName("Un utilisateur standard devrait pouvoir chiffrer")
    void userShouldBeAbleToEncrypt() throws AccessDeniedException {
        User user = new User("user", UserRole.USER);
        
        AccessContext context = new AccessContext.Builder()
            .user(user)
            .operation(KeyOperation.ENCRYPT)
            .build();
        
        assertTrue(accessControl.checkAccess(context));
    }
    
    @Test
    @DisplayName("Un utilisateur standard ne devrait pas pouvoir générer de clés")
    void userShouldNotBeAbleToGenerateKeys() {
        User user = new User("user", UserRole.USER);
        
        AccessContext context = new AccessContext.Builder()
            .user(user)
            .operation(KeyOperation.GENERATE)
            .build();
        
        assertThrows(AccessDeniedException.class, () -> {
            accessControl.checkAccess(context);
        });
    }
    
    @Test
    @DisplayName("Un auditeur devrait pouvoir consulter les logs")
    void auditorShouldBeAbleToAudit() throws AccessDeniedException {
        User auditor = new User("auditor", UserRole.AUDITOR);
        
        AccessContext context = new AccessContext.Builder()
            .user(auditor)
            .operation(KeyOperation.AUDIT)
            .build();
        
        assertTrue(accessControl.checkAccess(context));
    }
    
    @Test
    @DisplayName("Un invité devrait seulement pouvoir voir les métadonnées")
    void guestShouldOnlyViewMetadata() throws AccessDeniedException {
        User guest = new User("guest", UserRole.GUEST);
        
        AccessContext context = new AccessContext.Builder()
            .user(guest)
            .operation(KeyOperation.VIEW_METADATA)
            .build();
        
        assertTrue(accessControl.checkAccess(context));
    }
    
    @Test
    @DisplayName("Un invité ne devrait pas pouvoir effectuer d'opérations cryptographiques")
    void guestShouldNotPerformCryptoOperations() {
        User guest = new User("guest", UserRole.GUEST);
        
        AccessContext context = new AccessContext.Builder()
            .user(guest)
            .operation(KeyOperation.ENCRYPT)
            .build();
        
        assertThrows(AccessDeniedException.class, () -> {
            accessControl.checkAccess(context);
        });
    }
    
    @Test
    @DisplayName("Un utilisateur désactivé ne devrait pas pouvoir accéder")
    void disabledUserShouldNotAccess() {
        User user = new User("user", UserRole.USER);
        user.disable();
        
        AccessContext context = new AccessContext.Builder()
            .user(user)
            .operation(KeyOperation.VIEW_METADATA)
            .build();
        
        assertThrows(AccessDeniedException.class, () -> {
            accessControl.checkAccess(context);
        });
    }
    
    @Test
    @DisplayName("Devrait enregistrer une session utilisateur")
    void shouldRegisterUserSession() {
        User user = new User("testuser", UserRole.USER);
        
        accessControl.registerSession(user);
        
        User retrievedUser = accessControl.getActiveUser(user.getUserId());
        assertNotNull(retrievedUser);
        assertEquals(user.getUserId(), retrievedUser.getUserId());
    }
    
    @Test
    @DisplayName("Devrait désenregistrer une session utilisateur")
    void shouldUnregisterUserSession() {
        User user = new User("testuser", UserRole.USER);
        
        accessControl.registerSession(user);
        accessControl.unregisterSession(user.getUserId());
        
        User retrievedUser = accessControl.getActiveUser(user.getUserId());
        assertNull(retrievedUser);
    }
    
    @Test
    @DisplayName("Devrait lister les utilisateurs actifs")
    void shouldListActiveUsers() {
        User user1 = new User("user1", UserRole.USER);
        User user2 = new User("user2", UserRole.OPERATOR);
        
        accessControl.registerSession(user1);
        accessControl.registerSession(user2);
        
        List<User> activeUsers = accessControl.getActiveUsers();
        
        assertEquals(2, activeUsers.size());
        assertTrue(activeUsers.stream().anyMatch(u -> u.getUserId().equals(user1.getUserId())));
        assertTrue(activeUsers.stream().anyMatch(u -> u.getUserId().equals(user2.getUserId())));
    }
    
    @Test
    @DisplayName("Devrait empêcher l'exportation de clés privées pour les non-administrateurs")
    void shouldPreventPrivateKeyExportForNonAdmins() {
        User user = new User("user", UserRole.USER);
        
        assertThrows(AccessDeniedException.class, () -> {
            accessControl.preventPrivateKeyDisplay(user, KeyOperation.EXPORT_PRIVATE);
        });
    }
    
    @Test
    @DisplayName("Devrait autoriser l'exportation de clés privées pour les administrateurs")
    void shouldAllowPrivateKeyExportForAdmins() throws AccessDeniedException {
        User admin = new User("admin", UserRole.ADMIN);
        
        // Ne devrait pas lever d'exception
        accessControl.preventPrivateKeyDisplay(admin, KeyOperation.EXPORT_PRIVATE);
    }
    
    @Test
    @DisplayName("Devrait écrire dans le fichier de log d'audit")
    void shouldWriteToAuditLog() throws AccessDeniedException, IOException {
        User user = new User("testuser", UserRole.ADMIN);
        
        AccessContext context = new AccessContext.Builder()
            .user(user)
            .operation(KeyOperation.GENERATE)
            .keyId("test-key-123")
            .build();
        
        accessControl.checkAccess(context);
        
        // Vérifier que le log a été écrit
        assertTrue(Files.exists(testAuditLogPath));
        String content = Files.readString(testAuditLogPath);
        assertTrue(content.contains("testuser"));
        assertTrue(content.contains("GENERATE"));
    }
    
    @Test
    @DisplayName("Devrait lire les logs d'audit")
    void shouldReadAuditLogs() throws AccessDeniedException, IOException {
        User user = new User("testuser", UserRole.ADMIN);
        
        // Générer quelques entrées de log
        for (int i = 0; i < 5; i++) {
            AccessContext context = new AccessContext.Builder()
                .user(user)
                .operation(KeyOperation.VIEW_METADATA)
                .build();
            accessControl.checkAccess(context);
        }
        
        List<String> logs = accessControl.readAuditLog(10);
        
        assertFalse(logs.isEmpty());
        assertTrue(logs.size() >= 5);
    }
    
    @Test
    @DisplayName("Devrait filtrer les logs par utilisateur")
    void shouldFilterLogsByUser() throws AccessDeniedException, IOException {
        User user1 = new User("user1", UserRole.USER);
        User user2 = new User("user2", UserRole.USER);
        
        AccessContext context1 = new AccessContext.Builder()
            .user(user1)
            .operation(KeyOperation.VIEW_METADATA)
            .build();
        
        AccessContext context2 = new AccessContext.Builder()
            .user(user2)
            .operation(KeyOperation.VIEW_METADATA)
            .build();
        
        accessControl.checkAccess(context1);
        accessControl.checkAccess(context2);
        
        List<String> user1Logs = accessControl.readAuditLogForUser("user1", 10);
        
        assertFalse(user1Logs.isEmpty());
        assertTrue(user1Logs.stream().allMatch(log -> log.contains("user1")));
        assertFalse(user1Logs.stream().anyMatch(log -> log.contains("user2")));
    }
    
    @Test
    @DisplayName("Devrait compter les tentatives d'accès refusées")
    void shouldCountDeniedAccessAttempts() {
        User user = new User("user", UserRole.USER);
        
        // Tenter plusieurs opérations non autorisées
        for (int i = 0; i < 3; i++) {
            AccessContext context = new AccessContext.Builder()
                .user(user)
                .operation(KeyOperation.DELETE)
                .build();
            
            try {
                accessControl.checkAccess(context);
            } catch (AccessDeniedException e) {
                // Attendu
            }
        }
        
        int deniedCount = accessControl.getDeniedAccessCount(user.getUserId());
        assertEquals(3, deniedCount);
    }
    
    @Test
    @DisplayName("Devrait réinitialiser l'historique des accès refusés")
    void shouldClearDeniedAccessHistory() {
        User user = new User("user", UserRole.USER);
        
        // Tenter une opération non autorisée
        AccessContext context = new AccessContext.Builder()
            .user(user)
            .operation(KeyOperation.DELETE)
            .build();
        
        try {
            accessControl.checkAccess(context);
        } catch (AccessDeniedException e) {
            // Attendu
        }
        
        accessControl.clearDeniedAccessHistory(user.getUserId());
        
        int deniedCount = accessControl.getDeniedAccessCount(user.getUserId());
        assertEquals(0, deniedCount);
    }
    
    @Test
    @DisplayName("Devrait vérifier les permissions avec hasPermission")
    void shouldCheckPermissionsWithHasPermission() {
        User admin = new User("admin", UserRole.ADMIN);
        User user = new User("user", UserRole.USER);
        
        assertTrue(accessControl.hasPermission(admin, KeyOperation.DELETE));
        assertFalse(accessControl.hasPermission(user, KeyOperation.DELETE));
        
        assertTrue(accessControl.hasPermission(user, KeyOperation.ENCRYPT));
        assertTrue(accessControl.hasPermission(admin, KeyOperation.ENCRYPT));
    }
    
    @Test
    @DisplayName("Devrait indiquer si l'audit est activé")
    void shouldIndicateIfAuditIsEnabled() {
        assertTrue(accessControl.isAuditEnabled());
        
        KeyAccessControl disabledAudit = new KeyAccessControl(false, testAuditLogPath);
        assertFalse(disabledAudit.isAuditEnabled());
    }
    
    @Test
    @DisplayName("Devrait retourner le chemin du fichier d'audit")
    void shouldReturnAuditLogPath() {
        assertEquals(testAuditLogPath, accessControl.getAuditLogPath());
    }
}
