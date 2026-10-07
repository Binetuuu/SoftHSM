package com.tdsi.softhsm.security;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Validateur de robustesse des mots de passe.
 * Applique des règles de sécurité pour s'assurer que les mots de passe sont suffisamment forts.
 */
public class PasswordValidator {
    
    /**
     * Longueur minimale du mot de passe
     */
    private static final int MIN_LENGTH = 12;
    
    /**
     * Longueur maximale du mot de passe
     */
    private static final int MAX_LENGTH = 128;
    
    /**
     * Pattern pour détecter au moins une lettre majuscule
     */
    private static final Pattern UPPERCASE_PATTERN = Pattern.compile("[A-Z]");
    
    /**
     * Pattern pour détecter au moins une lettre minuscule
     */
    private static final Pattern LOWERCASE_PATTERN = Pattern.compile("[a-z]");
    
    /**
     * Pattern pour détecter au moins un chiffre
     */
    private static final Pattern DIGIT_PATTERN = Pattern.compile("[0-9]");
    
    /**
     * Pattern pour détecter au moins un caractère spécial
     */
    private static final Pattern SPECIAL_CHAR_PATTERN = Pattern.compile("[!@#$%^&*()_+\\-=\\[\\]{};':\"\\\\|,.<>/?]");
    
    /**
     * Liste de mots de passe couramment utilisés à éviter
     */
    private static final List<String> COMMON_PASSWORDS = List.of(
        "password", "123456", "123456789", "12345678", "12345", "1234567",
        "password1", "admin", "administrator", "root", "qwerty", "letmein",
        "welcome", "monkey", "dragon", "master", "abc123", "password123"
    );
    
    /**
     * Valide un mot de passe selon les règles de sécurité
     * 
     * @param password Mot de passe à valider
     * @return Résultat de la validation
     */
    public ValidationResult validate(char[] password) {
        if (password == null || password.length == 0) {
            return new ValidationResult(false, "Le mot de passe ne peut pas être vide");
        }
        
        List<String> errors = new ArrayList<>();
        String passwordStr = new String(password);
        
        // Vérifier la longueur
        if (password.length < MIN_LENGTH) {
            errors.add(String.format("Le mot de passe doit contenir au moins %d caractères", MIN_LENGTH));
        }
        
        if (password.length > MAX_LENGTH) {
            errors.add(String.format("Le mot de passe ne doit pas dépasser %d caractères", MAX_LENGTH));
        }
        
        // Vérifier la complexité
        if (!UPPERCASE_PATTERN.matcher(passwordStr).find()) {
            errors.add("Le mot de passe doit contenir au moins une lettre majuscule");
        }
        
        if (!LOWERCASE_PATTERN.matcher(passwordStr).find()) {
            errors.add("Le mot de passe doit contenir au moins une lettre minuscule");
        }
        
        if (!DIGIT_PATTERN.matcher(passwordStr).find()) {
            errors.add("Le mot de passe doit contenir au moins un chiffre");
        }
        
        if (!SPECIAL_CHAR_PATTERN.matcher(passwordStr).find()) {
            errors.add("Le mot de passe doit contenir au moins un caractère spécial (!@#$%^&*()_+-=[]{}...) ");
        }
        
        // Vérifier contre les mots de passe courants
        String lowerPassword = passwordStr.toLowerCase();
        for (String common : COMMON_PASSWORDS) {
            if (lowerPassword.contains(common)) {
                errors.add("Le mot de passe contient un mot couramment utilisé et donc trop faible");
                break;
            }
        }
        
        // Vérifier les séquences répétitives
        if (hasRepetitiveSequence(password)) {
            errors.add("Le mot de passe contient trop de caractères répétés");
        }
        
        if (errors.isEmpty()) {
            return new ValidationResult(true, "Mot de passe valide");
        } else {
            return new ValidationResult(false, String.join("; ", errors));
        }
    }
    
    /**
     * Vérifie si le mot de passe contient des séquences répétitives
     * 
     * @param password Mot de passe à vérifier
     * @return true si des séquences répétitives sont détectées
     */
    private boolean hasRepetitiveSequence(char[] password) {
        int maxRepeat = 3; // Maximum de caractères identiques consécutifs
        
        for (int i = 0; i < password.length - maxRepeat; i++) {
            char current = password[i];
            int repeatCount = 1;
            
            for (int j = i + 1; j < password.length && password[j] == current; j++) {
                repeatCount++;
                if (repeatCount > maxRepeat) {
                    return true;
                }
            }
        }
        
        return false;
    }
    
    /**
     * Calcule un score de robustesse du mot de passe (0-100)
     * 
     * @param password Mot de passe à évaluer
     * @return Score de 0 (très faible) à 100 (très fort)
     */
    public int calculateStrength(char[] password) {
        if (password == null || password.length == 0) {
            return 0;
        }
        
        int score = 0;
        String passwordStr = new String(password);
        
        // Points pour la longueur
        score += Math.min(password.length * 2, 30);
        
        // Points pour la diversité des caractères
        if (UPPERCASE_PATTERN.matcher(passwordStr).find()) score += 10;
        if (LOWERCASE_PATTERN.matcher(passwordStr).find()) score += 10;
        if (DIGIT_PATTERN.matcher(passwordStr).find()) score += 10;
        if (SPECIAL_CHAR_PATTERN.matcher(passwordStr).find()) score += 15;
        
        // Bonus pour plusieurs types de caractères spéciaux
        long specialCharCount = passwordStr.chars()
            .filter(c -> SPECIAL_CHAR_PATTERN.matcher(String.valueOf((char) c)).matches())
            .count();
        score += Math.min(specialCharCount * 2, 15);
        
        // Pénalités
        if (hasRepetitiveSequence(password)) score -= 10;
        
        String lowerPassword = passwordStr.toLowerCase();
        for (String common : COMMON_PASSWORDS) {
            if (lowerPassword.contains(common)) {
                score -= 20;
                break;
            }
        }
        
        return Math.max(0, Math.min(100, score));
    }
    
    /**
     * Obtient une description textuelle de la robustesse
     * 
     * @param score Score de robustesse (0-100)
     * @return Description textuelle
     */
    public String getStrengthDescription(int score) {
        if (score < 30) return "Très faible";
        if (score < 50) return "Faible";
        if (score < 70) return "Moyen";
        if (score < 85) return "Fort";
        return "Très fort";
    }
    
    /**
     * Résultat d'une validation de mot de passe
     */
    public static class ValidationResult {
        private final boolean valid;
        private final String message;
        
        public ValidationResult(boolean valid, String message) {
            this.valid = valid;
            this.message = message;
        }
        
        public boolean isValid() {
            return valid;
        }
        
        public String getMessage() {
            return message;
        }
        
        @Override
        public String toString() {
            return "ValidationResult{" +
                    "valid=" + valid +
                    ", message='" + message + '\'' +
                    '}';
        }
    }
}
