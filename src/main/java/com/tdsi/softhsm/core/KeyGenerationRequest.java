package com.tdsi.softhsm.core;

import com.tdsi.softhsm.model.enums.Algorithm;
import com.tdsi.softhsm.model.enums.KeyUsage;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.Set;

/**
 * Requête de génération de clé cryptographique.
 * 
 * Contient tous les paramètres nécessaires pour générer une nouvelle clé.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class KeyGenerationRequest {
    
    /**
     * Alias/nom de la clé (obligatoire)
     */
    private String alias;
    
    /**
     * Algorithme cryptographique à utiliser (obligatoire)
     */
    private Algorithm algorithm;
    
    /**
     * Propriétaire de la clé (utilisateur qui la génère)
     */
    private String owner;
    
    /**
     * Date d'expiration optionnelle
     * Si null, la clé n'expire jamais
     */
    private LocalDateTime expirationDate;
    
    /**
     * Usages autorisés pour cette clé
     * Si null ou vide, les usages par défaut seront appliqués selon le type
     */
    private Set<KeyUsage> allowedUsages;
    
    /**
     * Description optionnelle de la clé
     */
    private String description;
    
    /**
     * Validation de la requête
     */
    public void validate() {
        if (alias == null || alias.trim().isEmpty()) {
            throw new IllegalArgumentException("L'alias de la clé est obligatoire");
        }
        
        if (algorithm == null) {
            throw new IllegalArgumentException("L'algorithme est obligatoire");
        }
        
        if (owner == null || owner.trim().isEmpty()) {
            throw new IllegalArgumentException("Le propriétaire est obligatoire");
        }
        
        // Vérifier que la date d'expiration est dans le futur
        if (expirationDate != null && expirationDate.isBefore(LocalDateTime.now())) {
            throw new IllegalArgumentException(
                "La date d'expiration doit être dans le futur");
        }
    }
}
