package com.tdsi.softhsm.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests unitaires pour KeyDerivationService
 */
@DisplayName("Tests du service de dérivation de clés")
class KeyDerivationServiceTest {
    
    private KeyDerivationService service;
    
    @BeforeEach
    void setUp() {
        service = new KeyDerivationService();
    }
    
    @Test
    @DisplayName("Devrait générer un salt de 32 octets")
    void shouldGenerate32ByteSalt() {
        byte[] salt = service.generateSalt();
        
        assertNotNull(salt);
        assertEquals(32, salt.length);
    }
    
    @Test
    @DisplayName("Devrait générer des salts différents")
    void shouldGenerateDifferentSalts() {
        byte[] salt1 = service.generateSalt();
        byte[] salt2 = service.generateSalt();
        
        assertFalse(Arrays.equals(salt1, salt2), 
            "Les salts devraient être différents");
    }
    
    @Test
    @DisplayName("Devrait dériver une clé de 256 bits par défaut")
    void shouldDerive256BitKeyByDefault() throws KeyDerivationException {
        char[] password = "MyStr0ng!P@ssw0rd".toCharArray();
        byte[] salt = service.generateSalt();
        
        byte[] key = service.deriveKey(password, salt);
        
        assertNotNull(key);
        assertEquals(32, key.length, "La clé devrait faire 32 octets (256 bits)");
    }
    
    @Test
    @DisplayName("Devrait produire des clés identiques avec le même mot de passe et salt")
    void shouldProduceSameKeyWithSamePasswordAndSalt() throws KeyDerivationException {
        char[] password = "MyStr0ng!P@ssw0rd".toCharArray();
        byte[] salt = service.generateSalt();
        
        byte[] key1 = service.deriveKey(password, salt);
        byte[] key2 = service.deriveKey(password, salt);
        
        assertArrayEquals(key1, key2, 
            "Les clés devraient être identiques avec le même mot de passe et salt");
    }
    
    @Test
    @DisplayName("Devrait produire des clés différentes avec des salts différents")
    void shouldProduceDifferentKeysWithDifferentSalts() throws KeyDerivationException {
        char[] password = "MyStr0ng!P@ssw0rd".toCharArray();
        byte[] salt1 = service.generateSalt();
        byte[] salt2 = service.generateSalt();
        
        byte[] key1 = service.deriveKey(password, salt1);
        byte[] key2 = service.deriveKey(password, salt2);
        
        assertFalse(Arrays.equals(key1, key2), 
            "Les clés devraient être différentes avec des salts différents");
    }
    
    @Test
    @DisplayName("Devrait produire des clés différentes avec des mots de passe différents")
    void shouldProduceDifferentKeysWithDifferentPasswords() throws KeyDerivationException {
        char[] password1 = "MyStr0ng!P@ssw0rd1".toCharArray();
        char[] password2 = "MyStr0ng!P@ssw0rd2".toCharArray();
        byte[] salt = service.generateSalt();
        
        byte[] key1 = service.deriveKey(password1, salt);
        byte[] key2 = service.deriveKey(password2, salt);
        
        assertFalse(Arrays.equals(key1, key2), 
            "Les clés devraient être différentes avec des mots de passe différents");
    }
    
    @Test
    @DisplayName("Devrait lever une exception pour un mot de passe null")
    void shouldThrowExceptionForNullPassword() {
        byte[] salt = service.generateSalt();
        
        assertThrows(NullPointerException.class, () -> {
            service.deriveKey(null, salt);
        });
    }
    
    @Test
    @DisplayName("Devrait lever une exception pour un salt null")
    void shouldThrowExceptionForNullSalt() {
        char[] password = "MyStr0ng!P@ssw0rd".toCharArray();
        
        assertThrows(NullPointerException.class, () -> {
            service.deriveKey(password, null);
        });
    }
    
    @Test
    @DisplayName("Devrait lever une exception pour un mot de passe vide")
    void shouldThrowExceptionForEmptyPassword() {
        char[] password = "".toCharArray();
        byte[] salt = service.generateSalt();
        
        assertThrows(IllegalArgumentException.class, () -> {
            service.deriveKey(password, salt);
        });
    }
    
    @Test
    @DisplayName("Devrait lever une exception pour un salt trop court")
    void shouldThrowExceptionForShortSalt() {
        char[] password = "MyStr0ng!P@ssw0rd".toCharArray();
        byte[] salt = new byte[8]; // Trop court (< 16 octets)
        
        assertThrows(IllegalArgumentException.class, () -> {
            service.deriveKey(password, salt);
        });
    }
    
    @Test
    @DisplayName("Devrait générer une clé avec salt via deriveKeyWithSalt")
    void shouldDeriveKeyWithSaltGeneration() throws KeyDerivationException {
        char[] password = "MyStr0ng!P@ssw0rd".toCharArray();
        
        KeyDerivationService.DerivedKeyResult result = service.deriveKeyWithSalt(password);
        
        assertNotNull(result);
        assertNotNull(result.getKey());
        assertNotNull(result.getSalt());
        assertEquals(32, result.getKey().length);
        assertEquals(32, result.getSalt().length);
        assertEquals(service.getIterations(), result.getIterations());
        assertEquals(service.getKeyLength(), result.getKeyLength());
    }
    
    @Test
    @DisplayName("Devrait vérifier un mot de passe correct")
    void shouldVerifyCorrectPassword() throws KeyDerivationException {
        char[] password = "MyStr0ng!P@ssw0rd".toCharArray();
        byte[] salt = service.generateSalt();
        byte[] expectedKey = service.deriveKey(password, salt);
        
        boolean verified = service.verifyPassword(password, expectedKey, salt);
        
        assertTrue(verified, "Le mot de passe devrait être vérifié comme correct");
    }
    
    @Test
    @DisplayName("Devrait rejeter un mot de passe incorrect")
    void shouldRejectIncorrectPassword() throws KeyDerivationException {
        char[] correctPassword = "MyStr0ng!P@ssw0rd".toCharArray();
        char[] wrongPassword = "WrongP@ssw0rd123".toCharArray();
        byte[] salt = service.generateSalt();
        byte[] expectedKey = service.deriveKey(correctPassword, salt);
        
        boolean verified = service.verifyPassword(wrongPassword, expectedKey, salt);
        
        assertFalse(verified, "Le mot de passe devrait être rejeté comme incorrect");
    }
    
    @Test
    @DisplayName("Devrait encoder et décoder un salt en Base64")
    void shouldEncodeAndDecodeSalt() {
        byte[] originalSalt = service.generateSalt();
        
        String encoded = KeyDerivationService.encodeSalt(originalSalt);
        byte[] decoded = KeyDerivationService.decodeSalt(encoded);
        
        assertArrayEquals(originalSalt, decoded, 
            "Le salt décodé devrait être identique à l'original");
    }
    
    @Test
    @DisplayName("Devrait supporter des clés de 128 bits")
    void shouldSupport128BitKeys() throws KeyDerivationException {
        KeyDerivationService service128 = new KeyDerivationService(100_000, 128);
        char[] password = "MyStr0ng!P@ssw0rd".toCharArray();
        byte[] salt = service128.generateSalt();
        
        byte[] key = service128.deriveKey(password, salt);
        
        assertEquals(16, key.length, "La clé devrait faire 16 octets (128 bits)");
    }
    
    @Test
    @DisplayName("Devrait supporter des clés de 192 bits")
    void shouldSupport192BitKeys() throws KeyDerivationException {
        KeyDerivationService service192 = new KeyDerivationService(100_000, 192);
        char[] password = "MyStr0ng!P@ssw0rd".toCharArray();
        byte[] salt = service192.generateSalt();
        
        byte[] key = service192.deriveKey(password, salt);
        
        assertEquals(24, key.length, "La clé devrait faire 24 octets (192 bits)");
    }
    
    @Test
    @DisplayName("Devrait lever une exception pour un nombre d'itérations trop faible")
    void shouldThrowExceptionForLowIterations() {
        assertThrows(IllegalArgumentException.class, () -> {
            new KeyDerivationService(50_000, 256);
        });
    }
    
    @Test
    @DisplayName("Devrait lever une exception pour une longueur de clé invalide")
    void shouldThrowExceptionForInvalidKeyLength() {
        assertThrows(IllegalArgumentException.class, () -> {
            new KeyDerivationService(100_000, 512);
        });
    }
    
    @Test
    @DisplayName("DerivedKeyResult devrait fournir le salt encodé")
    void derivedKeyResultShouldProvideEncodedSalt() throws KeyDerivationException {
        char[] password = "MyStr0ng!P@ssw0rd".toCharArray();
        
        KeyDerivationService.DerivedKeyResult result = service.deriveKeyWithSalt(password);
        String encodedSalt = result.getEncodedSalt();
        
        assertNotNull(encodedSalt);
        assertFalse(encodedSalt.isEmpty());
        
        // Vérifier que le décodage fonctionne
        byte[] decoded = KeyDerivationService.decodeSalt(encodedSalt);
        assertArrayEquals(result.getSalt(), decoded);
    }
}
