package com.tdsi.softhsm.storage;

import com.tdsi.softhsm.model.enums.KeyType;

import java.time.LocalDateTime;
import java.util.Objects;

/**
 * Représente les métadonnées d'une entrée dans le KeyStore.
 * Contient les informations sur une clé stockée sans exposer la clé elle-même.
 */
public class KeyStoreEntry {
    private final String alias;
    private final KeyType keyType;
    private final String algorithm;
    private final LocalDateTime createdAt;
    private final String owner;
    private final boolean hasPrivateKey;
    private final boolean hasCertificate;
    
    private KeyStoreEntry(Builder builder) {
        this.alias = Objects.requireNonNull(builder.alias, "L'alias ne peut pas être null");
        this.keyType = Objects.requireNonNull(builder.keyType, "Le type de clé ne peut pas être null");
        this.algorithm = Objects.requireNonNull(builder.algorithm, "L'algorithme ne peut pas être null");
        this.createdAt = builder.createdAt != null ? builder.createdAt : LocalDateTime.now();
        this.owner = builder.owner;
        this.hasPrivateKey = builder.hasPrivateKey;
        this.hasCertificate = builder.hasCertificate;
    }
    
    // Getters
    public String getAlias() {
        return alias;
    }
    
    public KeyType getKeyType() {
        return keyType;
    }
    
    public String getAlgorithm() {
        return algorithm;
    }
    
    public LocalDateTime getCreatedAt() {
        return createdAt;
    }
    
    public String getOwner() {
        return owner;
    }
    
    public boolean hasPrivateKey() {
        return hasPrivateKey;
    }
    
    public boolean hasCertificate() {
        return hasCertificate;
    }
    
    @Override
    public String toString() {
        return "KeyStoreEntry{" +
                "alias='" + alias + '\'' +
                ", keyType=" + keyType +
                ", algorithm='" + algorithm + '\'' +
                ", createdAt=" + createdAt +
                ", owner='" + owner + '\'' +
                ", hasPrivateKey=" + hasPrivateKey +
                ", hasCertificate=" + hasCertificate +
                '}';
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        KeyStoreEntry that = (KeyStoreEntry) o;
        return Objects.equals(alias, that.alias);
    }
    
    @Override
    public int hashCode() {
        return Objects.hash(alias);
    }
    
    /**
     * Builder pour créer un KeyStoreEntry
     */
    public static class Builder {
        private String alias;
        private KeyType keyType;
        private String algorithm;
        private LocalDateTime createdAt;
        private String owner;
        private boolean hasPrivateKey;
        private boolean hasCertificate;
        
        public Builder alias(String alias) {
            this.alias = alias;
            return this;
        }
        
        public Builder keyType(KeyType keyType) {
            this.keyType = keyType;
            return this;
        }
        
        public Builder algorithm(String algorithm) {
            this.algorithm = algorithm;
            return this;
        }
        
        public Builder createdAt(LocalDateTime createdAt) {
            this.createdAt = createdAt;
            return this;
        }
        
        public Builder owner(String owner) {
            this.owner = owner;
            return this;
        }
        
        public Builder hasPrivateKey(boolean hasPrivateKey) {
            this.hasPrivateKey = hasPrivateKey;
            return this;
        }
        
        public Builder hasCertificate(boolean hasCertificate) {
            this.hasCertificate = hasCertificate;
            return this;
        }
        
        public KeyStoreEntry build() {
            return new KeyStoreEntry(this);
        }
    }
}
