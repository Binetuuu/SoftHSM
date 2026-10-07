package com.tdsi.softhsm.model.enums;

/**
 * Statut du cycle de vie d'une clé cryptographique
 */
public enum KeyStatus {
    /**
     * Clé active et utilisable
     */
    ACTIVE("Active", "La clé est active et peut être utilisée"),
    
    /**
     * Clé expirée (date de validité dépassée)
     */
    EXPIRED("Expired", "La clé a dépassé sa date d'expiration"),
    
    /**
     * Clé désactivée temporairement
     */
    DISABLED("Disabled", "La clé a été désactivée temporairement"),
    
    /**
     * Clé archivée (conservation pour accès historique uniquement)
     */
    ARCHIVED("Archived", "La clé est archivée pour consultation historique"),
    
    /**
     * Clé compromise (sécurité compromise)
     */
    COMPROMISED("Compromised", "La clé a été compromise et ne doit plus être utilisée"),
    
    /**
     * Clé supprimée (marquée pour suppression)
     */
    DELETED("Deleted", "La clé a été marquée comme supprimée");

    private final String displayName;
    private final String description;

    KeyStatus(String displayName, String description) {
        this.displayName = displayName;
        this.description = description;
    }

    public String getDisplayName() {
        return displayName;
    }

    public String getDescription() {
        return description;
    }

    /**
     * Vérifie si la clé peut être utilisée pour des opérations cryptographiques
     */
    public boolean isUsable() {
        return this == ACTIVE;
    }

    /**
     * Vérifie si la clé peut être consultée (même si non utilisable)
     */
    public boolean isViewable() {
        return this != DELETED;
    }

    @Override
    public String toString() {
        return displayName;
    }
}
