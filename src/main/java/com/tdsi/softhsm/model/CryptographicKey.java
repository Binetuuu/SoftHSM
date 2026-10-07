package com.tdsi.softhsm.model;

import com.tdsi.softhsm.model.enums.Algorithm;
import com.tdsi.softhsm.model.enums.KeyStatus;
import com.tdsi.softhsm.model.enums.KeyType;
import com.tdsi.softhsm.model.enums.KeyUsage;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

/**
 * Modèle représentant une clé cryptographique avec ses métadonnées complètes.
 * 
 * Ce modèle contient uniquement les métadonnées de la clé.
 * Le matériel cryptographique réel (la clé elle-même) est stocké séparément
 * dans le KeyStore sécurisé et n'est jamais exposé directement.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CryptographicKey {
    
    /**
     * Identifiant unique de la clé (UUID)
     */
    @Builder.Default
    private String id = UUID.randomUUID().toString();
    
    /**
     * Alias/nom de la clé (défini par l'utilisateur)
     * Exemples: "rsa-prod-001", "aes-backup-key", "signing-key-2026"
     */
    private String alias;
    
    /**
     * Algorithme cryptographique utilisé
     */
    private Algorithm algorithm;
    
    /**
     * Type de clé (symétrique, publique, privée, paire)
     */
    private KeyType keyType;
    
    /**
     * Taille de la clé en bits
     */
    private Integer keySize;
    
    /**
     * Date et heure de création de la clé
     */
    @Builder.Default
    private LocalDateTime createdAt = LocalDateTime.now();
    
    /**
     * Date et heure d'expiration (optionnelle)
     * null = pas d'expiration
     */
    private LocalDateTime expiresAt;
    
    /**
     * Propriétaire de la clé (utilisateur qui l'a créée/importée)
     */
    private String owner;
    
    /**
     * Statut actuel de la clé dans son cycle de vie
     */
    @Builder.Default
    private KeyStatus status = KeyStatus.ACTIVE;
    
    /**
     * Usages autorisés pour cette clé
     * Une clé peut avoir plusieurs usages (ex: ENCRYPTION + DECRYPTION)
     */
    @Builder.Default
    private Set<KeyUsage> allowedUsages = new HashSet<>();
    
    /**
     * Emplacement de stockage de la clé dans le KeyStore
     * Format: "keystore://alias" ou chemin vers le fichier P12
     */
    private String keyLocation;
    
    /**
     * Description optionnelle de la clé
     */
    private String description;
    
    /**
     * Date de dernière utilisation
     */
    private LocalDateTime lastUsedAt;
    
    /**
     * Date de dernière modification du statut
     */
    private LocalDateTime statusChangedAt;
    
    /**
     * Si la clé fait partie d'une paire, référence vers l'autre clé
     * Pour une clé privée: référence vers la clé publique
     * Pour une clé publique: référence vers la clé privée
     */
    private String pairedKeyId;
    
    /**
     * En cas de rotation, référence vers la nouvelle clé qui remplace celle-ci
     */
    private String replacedByKeyId;
    
    /**
     * En cas de rotation, référence vers l'ancienne clé remplacée par celle-ci
     */
    private String replacesKeyId;
    
    // Méthodes utilitaires
    
    /**
     * Vérifie si la clé est actuellement utilisable pour des opérations cryptographiques
     */
    public boolean isUsable() {
        if (!status.isUsable()) {
            return false;
        }
        
        // Vérifier l'expiration
        if (expiresAt != null && LocalDateTime.now().isAfter(expiresAt)) {
            return false;
        }
        
        return true;
    }
    
    /**
     * Vérifie si la clé est expirée
     */
    public boolean isExpired() {
        return expiresAt != null && LocalDateTime.now().isAfter(expiresAt);
    }
    
    /**
     * Vérifie si la clé expire bientôt (dans les X jours)
     */
    public boolean expiresWithinDays(int days) {
        if (expiresAt == null) {
            return false;
        }
        LocalDateTime threshold = LocalDateTime.now().plusDays(days);
        return expiresAt.isBefore(threshold) && !isExpired();
    }
    
    /**
     * Vérifie si un usage spécifique est autorisé pour cette clé
     */
    public boolean hasUsage(KeyUsage usage) {
        return allowedUsages.contains(usage);
    }
    
    /**
     * Ajoute un usage autorisé (avec validation de compatibilité)
     */
    public void addUsage(KeyUsage usage) {
        if (usage.isCompatibleWith(this.keyType)) {
            allowedUsages.add(usage);
        } else {
            throw new IllegalArgumentException(
                String.format("Usage %s non compatible avec le type de clé %s", 
                    usage, keyType)
            );
        }
    }
    
    /**
     * Marque la clé comme utilisée (met à jour lastUsedAt)
     */
    public void markAsUsed() {
        this.lastUsedAt = LocalDateTime.now();
    }
    
    /**
     * Change le statut de la clé
     */
    public void changeStatus(KeyStatus newStatus) {
        this.status = newStatus;
        this.statusChangedAt = LocalDateTime.now();
    }
    
    /**
     * Retourne un résumé textuel de la clé (pour affichage)
     */
    public String getSummary() {
        return String.format("%s (%s) - %s [%s] - %s", 
            alias, 
            algorithm.getDisplayName(), 
            keyType.getDisplayName(),
            status.getDisplayName(),
            owner != null ? owner : "N/A"
        );
    }
    
    @Override
    public String toString() {
        return String.format("CryptographicKey{id='%s', alias='%s', algorithm=%s, status=%s}", 
            id, alias, algorithm, status);
    }
}
