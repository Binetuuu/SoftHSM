package com.tdsi.softhsm.model.enums;

/**
 * Énumération des opérations possibles sur les clés cryptographiques.
 * Chaque opération a un niveau de privilège requis.
 */
public enum KeyOperation {
    /**
     * Consulter les métadonnées d'une clé (sans voir la clé elle-même)
     */
    VIEW_METADATA(UserRole.GUEST, "Consulter les métadonnées"),
    
    /**
     * Exporter la partie publique d'une paire de clés
     */
    EXPORT_PUBLIC(UserRole.USER, "Exporter la clé publique"),
    
    /**
     * Utiliser une clé pour chiffrer des données
     */
    ENCRYPT(UserRole.USER, "Chiffrer avec la clé"),
    
    /**
     * Utiliser une clé pour déchiffrer des données
     */
    DECRYPT(UserRole.USER, "Déchiffrer avec la clé"),
    
    /**
     * Utiliser une clé pour signer des données
     */
    SIGN(UserRole.USER, "Signer avec la clé"),
    
    /**
     * Utiliser une clé pour vérifier une signature
     */
    VERIFY(UserRole.USER, "Vérifier une signature"),
    
    /**
     * Générer une nouvelle clé
     */
    GENERATE(UserRole.OPERATOR, "Générer une nouvelle clé"),
    
    /**
     * Importer une clé existante
     */
    IMPORT(UserRole.OPERATOR, "Importer une clé"),
    
    /**
     * Modifier les métadonnées d'une clé
     */
    MODIFY(UserRole.OPERATOR, "Modifier une clé"),
    
    /**
     * Désactiver une clé (changer son statut)
     */
    DEACTIVATE(UserRole.OPERATOR, "Désactiver une clé"),
    
    /**
     * Supprimer définitivement une clé
     */
    DELETE(UserRole.ADMIN, "Supprimer une clé"),
    
    /**
     * Exporter la partie privée d'une clé (opération très sensible)
     */
    EXPORT_PRIVATE(UserRole.ADMIN, "Exporter la clé privée"),
    
    /**
     * Consulter les logs d'audit
     */
    AUDIT(UserRole.AUDITOR, "Consulter les logs"),
    
    /**
     * Gérer le KeyStore (sauvegarde, restauration, réinitialisation)
     */
    MANAGE_KEYSTORE(UserRole.ADMIN, "Gérer le KeyStore");
    
    private final UserRole requiredRole;
    private final String description;
    
    KeyOperation(UserRole requiredRole, String description) {
        this.requiredRole = requiredRole;
        this.description = description;
    }
    
    /**
     * @return Le rôle minimal requis pour effectuer cette opération
     */
    public UserRole getRequiredRole() {
        return requiredRole;
    }
    
    /**
     * @return La description de l'opération
     */
    public String getDescription() {
        return description;
    }
    
    /**
     * Vérifie si un rôle utilisateur peut effectuer cette opération
     * 
     * @param userRole Le rôle de l'utilisateur
     * @return true si l'utilisateur a les permissions nécessaires
     */
    public boolean isAllowedFor(UserRole userRole) {
        return userRole.hasAccessLevel(this.requiredRole);
    }
}
