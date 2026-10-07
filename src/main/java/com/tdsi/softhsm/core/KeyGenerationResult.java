package com.tdsi.softhsm.core;

import com.tdsi.softhsm.model.CryptographicKey;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import javax.crypto.SecretKey;
import java.security.KeyPair;

/**
 * Résultat d'une génération de clé cryptographique.
 * 
 * ATTENTION SÉCURITÉ:
 * Cette classe contient le matériel cryptographique réel (secretKey ou keyPair).
 * Ces objets ne doivent JAMAIS être sérialisés, loggés ou exposés via une API.
 * Ils ne doivent être utilisés que pour le stockage sécurisé immédiat.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class KeyGenerationResult {
    
    /**
     * Métadonnées de la clé générée
     */
    private CryptographicKey metadata;
    
    /**
     * Clé symétrique générée (si algorithme symétrique)
     * NE JAMAIS LOGGER OU EXPOSER CETTE VALEUR
     */
    private SecretKey secretKey;
    
    /**
     * Paire de clés générée (si algorithme asymétrique)
     * NE JAMAIS LOGGER OU EXPOSER CETTE VALEUR
     */
    private KeyPair keyPair;
    
    /**
     * Succès de l'opération
     */
    private boolean success;
    
    /**
     * Message décrivant le résultat
     */
    private String message;
    
    /**
     * Temps de génération en millisecondes
     */
    private long generationTimeMs;
    
    /**
     * Vérifie si c'est une clé symétrique
     */
    public boolean isSymmetric() {
        return secretKey != null;
    }
    
    /**
     * Vérifie si c'est une paire de clés asymétriques
     */
    public boolean isAsymmetric() {
        return keyPair != null;
    }
    
    /**
     * Efface le matériel cryptographique de la mémoire (best effort)
     * À appeler après utilisation pour réduire la fenêtre d'exposition
     */
    public void clearSensitiveData() {
        // Note: Java ne permet pas d'effacer directement la mémoire
        // mais on peut au moins supprimer les références
        this.secretKey = null;
        this.keyPair = null;
    }
    
    @Override
    public String toString() {
        // NE PAS inclure secretKey ou keyPair dans toString() pour éviter les fuites
        return String.format(
            "KeyGenerationResult{success=%s, alias='%s', algorithm=%s, generationTime=%dms}",
            success,
            metadata != null ? metadata.getAlias() : "N/A",
            metadata != null ? metadata.getAlgorithm() : "N/A",
            generationTimeMs
        );
    }
}
