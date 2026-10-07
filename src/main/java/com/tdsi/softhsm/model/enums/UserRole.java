package com.tdsi.softhsm.model.enums;

/**
 * Énumération des rôles utilisateurs avec leur niveau d'accès.
 * Définit les différents niveaux de privilèges pour l'accès aux clés cryptographiques.
 */
public enum UserRole {
    /**
     * Administrateur système - Accès complet à toutes les opérations
     */
    ADMIN(100, "Administrateur système"),
    
    /**
     * Opérateur - Peut générer, utiliser et gérer des clés
     */
    OPERATOR(70, "Opérateur de clés"),
    
    /**
     * Utilisateur - Peut utiliser des clés existantes mais pas les modifier
     */
    USER(50, "Utilisateur standard"),
    
    /**
     * Auditeur - Accès en lecture seule pour audit et conformité
     */
    AUDITOR(30, "Auditeur"),
    
    /**
     * Invité - Accès minimal, consultation limitée uniquement
     */
    GUEST(10, "Invité");
    
    private final int accessLevel;
    private final String description;
    
    UserRole(int accessLevel, String description) {
        this.accessLevel = accessLevel;
        this.description = description;
    }
    
    /**
     * @return Le niveau d'accès numérique (plus élevé = plus de privilèges)
     */
    public int getAccessLevel() {
        return accessLevel;
    }
    
    /**
     * @return La description du rôle
     */
    public String getDescription() {
        return description;
    }
    
    /**
     * Vérifie si ce rôle a un niveau d'accès supérieur ou égal au rôle spécifié
     * 
     * @param requiredRole Le rôle requis pour l'opération
     * @return true si ce rôle a les privilèges suffisants
     */
    public boolean hasAccessLevel(UserRole requiredRole) {
        return this.accessLevel >= requiredRole.accessLevel;
    }
    
    /**
     * Vérifie si ce rôle est administrateur
     * 
     * @return true si le rôle est ADMIN
     */
    public boolean isAdmin() {
        return this == ADMIN;
    }
    
    /**
     * Vérifie si ce rôle peut modifier des clés
     * 
     * @return true si le rôle peut modifier des clés
     */
    public boolean canModifyKeys() {
        return this.accessLevel >= OPERATOR.accessLevel;
    }
    
    /**
     * Vérifie si ce rôle peut utiliser des clés pour des opérations cryptographiques
     * 
     * @return true si le rôle peut utiliser des clés
     */
    public boolean canUseKeys() {
        return this.accessLevel >= USER.accessLevel;
    }
}
