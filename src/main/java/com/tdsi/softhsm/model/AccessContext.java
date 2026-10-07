package com.tdsi.softhsm.model;

import com.tdsi.softhsm.model.enums.KeyOperation;
import com.tdsi.softhsm.model.enums.UserRole;

import java.time.LocalDateTime;
import java.util.Objects;

/**
 * Représente le contexte d'accès pour une opération sur une clé.
 * Utilisé pour le contrôle d'accès et l'audit.
 */
public class AccessContext {
    private final User user;
    private final KeyOperation operation;
    private final String keyId;
    private final LocalDateTime timestamp;
    private final String ipAddress;
    private final String additionalInfo;
    
    private AccessContext(Builder builder) {
        this.user = Objects.requireNonNull(builder.user, "L'utilisateur ne peut pas être null");
        this.operation = Objects.requireNonNull(builder.operation, "L'opération ne peut pas être null");
        this.keyId = builder.keyId;
        this.timestamp = builder.timestamp != null ? builder.timestamp : LocalDateTime.now();
        this.ipAddress = builder.ipAddress;
        this.additionalInfo = builder.additionalInfo;
    }
    
    /**
     * Vérifie si l'utilisateur a les permissions pour effectuer l'opération
     * 
     * @return true si l'opération est autorisée
     */
    public boolean isAuthorized() {
        if (!user.isActive()) {
            return false;
        }
        return operation.isAllowedFor(user.getRole());
    }
    
    /**
     * Obtient le message d'erreur si l'accès est refusé
     * 
     * @return Message d'erreur descriptif
     */
    public String getDenialReason() {
        if (!user.isActive()) {
            return "L'utilisateur est désactivé";
        }
        if (!operation.isAllowedFor(user.getRole())) {
            return String.format("Le rôle %s n'a pas les permissions pour l'opération %s (rôle requis: %s)",
                    user.getRole().name(),
                    operation.getDescription(),
                    operation.getRequiredRole().name());
        }
        return "Accès refusé";
    }
    
    // Getters
    public User getUser() {
        return user;
    }
    
    public KeyOperation getOperation() {
        return operation;
    }
    
    public String getKeyId() {
        return keyId;
    }
    
    public LocalDateTime getTimestamp() {
        return timestamp;
    }
    
    public String getIpAddress() {
        return ipAddress;
    }
    
    public String getAdditionalInfo() {
        return additionalInfo;
    }
    
    /**
     * Crée une représentation textuelle pour l'audit
     * 
     * @return Chaîne formatée pour les logs d'audit
     */
    public String toAuditString() {
        StringBuilder sb = new StringBuilder();
        sb.append("[").append(timestamp).append("] ");
        sb.append("User: ").append(user.getUsername());
        sb.append(" (").append(user.getRole()).append(") ");
        sb.append("Operation: ").append(operation.getDescription());
        if (keyId != null) {
            sb.append(" KeyId: ").append(keyId);
        }
        if (ipAddress != null) {
            sb.append(" IP: ").append(ipAddress);
        }
        if (additionalInfo != null) {
            sb.append(" Info: ").append(additionalInfo);
        }
        sb.append(" Status: ").append(isAuthorized() ? "AUTHORIZED" : "DENIED");
        return sb.toString();
    }
    
    @Override
    public String toString() {
        return "AccessContext{" +
                "user=" + user.getUsername() +
                ", operation=" + operation +
                ", keyId='" + keyId + '\'' +
                ", timestamp=" + timestamp +
                ", authorized=" + isAuthorized() +
                '}';
    }
    
    /**
     * Builder pour créer un AccessContext
     */
    public static class Builder {
        private User user;
        private KeyOperation operation;
        private String keyId;
        private LocalDateTime timestamp;
        private String ipAddress;
        private String additionalInfo;
        
        public Builder user(User user) {
            this.user = user;
            return this;
        }
        
        public Builder operation(KeyOperation operation) {
            this.operation = operation;
            return this;
        }
        
        public Builder keyId(String keyId) {
            this.keyId = keyId;
            return this;
        }
        
        public Builder timestamp(LocalDateTime timestamp) {
            this.timestamp = timestamp;
            return this;
        }
        
        public Builder ipAddress(String ipAddress) {
            this.ipAddress = ipAddress;
            return this;
        }
        
        public Builder additionalInfo(String additionalInfo) {
            this.additionalInfo = additionalInfo;
            return this;
        }
        
        public AccessContext build() {
            return new AccessContext(this);
        }
    }
}
