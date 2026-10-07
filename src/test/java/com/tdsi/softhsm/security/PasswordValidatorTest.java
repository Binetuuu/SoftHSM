package com.tdsi.softhsm.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests unitaires pour PasswordValidator
 */
@DisplayName("Tests du validateur de mots de passe")
class PasswordValidatorTest {
    
    private PasswordValidator validator;
    
    @BeforeEach
    void setUp() {
        validator = new PasswordValidator();
    }
    
    @Test
    @DisplayName("Devrait accepter un mot de passe fort valide")
    void shouldAcceptStrongPassword() {
        char[] password = "MyStr0ng!P@ssw0rd2024".toCharArray();
        
        PasswordValidator.ValidationResult result = validator.validate(password);
        
        assertTrue(result.isValid(), "Le mot de passe devrait être valide");
        assertEquals("Mot de passe valide", result.getMessage());
    }
    
    @Test
    @DisplayName("Devrait rejeter un mot de passe trop court")
    void shouldRejectShortPassword() {
        char[] password = "Short1!".toCharArray();
        
        PasswordValidator.ValidationResult result = validator.validate(password);
        
        assertFalse(result.isValid(), "Le mot de passe devrait être invalide");
        assertTrue(result.getMessage().contains("au moins 12 caractères"));
    }
    
    @Test
    @DisplayName("Devrait rejeter un mot de passe sans majuscule")
    void shouldRejectPasswordWithoutUppercase() {
        char[] password = "mystrongp@ssw0rd".toCharArray();
        
        PasswordValidator.ValidationResult result = validator.validate(password);
        
        assertFalse(result.isValid());
        assertTrue(result.getMessage().contains("lettre majuscule"));
    }
    
    @Test
    @DisplayName("Devrait rejeter un mot de passe sans minuscule")
    void shouldRejectPasswordWithoutLowercase() {
        char[] password = "MYSTRONG!P@SSW0RD123".toCharArray();
        
        PasswordValidator.ValidationResult result = validator.validate(password);
        
        assertFalse(result.isValid());
        assertTrue(result.getMessage().contains("lettre minuscule"));
    }
    
    @Test
    @DisplayName("Devrait rejeter un mot de passe sans chiffre")
    void shouldRejectPasswordWithoutDigit() {
        char[] password = "MyStrongP@ssword!".toCharArray();
        
        PasswordValidator.ValidationResult result = validator.validate(password);
        
        assertFalse(result.isValid());
        assertTrue(result.getMessage().contains("chiffre"));
    }
    
    @Test
    @DisplayName("Devrait rejeter un mot de passe sans caractère spécial")
    void shouldRejectPasswordWithoutSpecialChar() {
        char[] password = "MyStrongPassword123".toCharArray();
        
        PasswordValidator.ValidationResult result = validator.validate(password);
        
        assertFalse(result.isValid());
        assertTrue(result.getMessage().contains("caractère spécial"));
    }
    
    @Test
    @DisplayName("Devrait rejeter un mot de passe commun")
    void shouldRejectCommonPassword() {
        char[] password = "Password123!".toCharArray();
        
        PasswordValidator.ValidationResult result = validator.validate(password);
        
        assertFalse(result.isValid());
        assertTrue(result.getMessage().contains("couramment utilisé"));
    }
    
    @Test
    @DisplayName("Devrait rejeter un mot de passe avec caractères répétitifs")
    void shouldRejectPasswordWithRepetitiveCharacters() {
        char[] password = "MyP@ssw0rd!!!!".toCharArray();
        
        PasswordValidator.ValidationResult result = validator.validate(password);
        
        assertFalse(result.isValid());
        assertTrue(result.getMessage().contains("répété"));
    }
    
    @Test
    @DisplayName("Devrait rejeter un mot de passe null")
    void shouldRejectNullPassword() {
        PasswordValidator.ValidationResult result = validator.validate(null);
        
        assertFalse(result.isValid());
        assertTrue(result.getMessage().contains("vide"));
    }
    
    @Test
    @DisplayName("Devrait rejeter un mot de passe vide")
    void shouldRejectEmptyPassword() {
        char[] password = "".toCharArray();
        
        PasswordValidator.ValidationResult result = validator.validate(password);
        
        assertFalse(result.isValid());
        assertTrue(result.getMessage().contains("vide"));
    }
    
    @Test
    @DisplayName("Devrait calculer un score élevé pour un mot de passe fort")
    void shouldCalculateHighScoreForStrongPassword() {
        char[] password = "MyV3ry!Str0ng#P@ssw0rd$2024".toCharArray();
        
        int score = validator.calculateStrength(password);
        
        assertTrue(score >= 70, "Le score devrait être >= 70 pour un mot de passe fort");
    }
    
    @Test
    @DisplayName("Devrait calculer un score faible pour un mot de passe faible")
    void shouldCalculateLowScoreForWeakPassword() {
        char[] password = "weak".toCharArray();
        
        int score = validator.calculateStrength(password);
        
        assertTrue(score < 30, "Le score devrait être < 30 pour un mot de passe faible");
    }
    
    @Test
    @DisplayName("Devrait retourner 0 pour un mot de passe null")
    void shouldReturnZeroScoreForNullPassword() {
        int score = validator.calculateStrength(null);
        
        assertEquals(0, score);
    }
    
    @Test
    @DisplayName("Devrait fournir des descriptions correctes pour les scores")
    void shouldProvideCorrectStrengthDescriptions() {
        assertEquals("Très faible", validator.getStrengthDescription(20));
        assertEquals("Faible", validator.getStrengthDescription(40));
        assertEquals("Moyen", validator.getStrengthDescription(60));
        assertEquals("Fort", validator.getStrengthDescription(80));
        assertEquals("Très fort", validator.getStrengthDescription(90));
    }
    
    @Test
    @DisplayName("Devrait accepter tous les caractères spéciaux supportés")
    void shouldAcceptAllSupportedSpecialCharacters() {
        String[] specialChars = {"!", "@", "#", "$", "%", "^", "&", "*", "(", ")", 
                                 "_", "+", "-", "=", "[", "]", "{", "}", ";", ":", 
                                 "'", "\"", "\\", "|", ",", ".", "<", ">", "/", "?"};
        
        for (String special : specialChars) {
            char[] password = ("MyP@ssw0rd123" + special).toCharArray();
            PasswordValidator.ValidationResult result = validator.validate(password);
            assertTrue(result.isValid(), 
                "Le mot de passe avec '" + special + "' devrait être valide");
        }
    }
}
