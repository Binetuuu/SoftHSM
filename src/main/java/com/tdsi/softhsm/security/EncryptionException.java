package com.tdsi.softhsm.security;

/**
 * Exception levée lors d'erreurs de chiffrement ou de déchiffrement.
 */
public class EncryptionException extends Exception {
    
    /**
     * Constructeur avec message
     * 
     * @param message Message d'erreur descriptif
     */
    public EncryptionException(String message) {
        super(message);
    }
    
    /**
     * Constructeur avec message et cause
     * 
     * @param message Message d'erreur descriptif
     * @param cause Exception d'origine
     */
    public EncryptionException(String message, Throwable cause) {
        super(message, cause);
    }
    
    /**
     * Constructeur avec cause uniquement
     * 
     * @param cause Exception d'origine
     */
    public EncryptionException(Throwable cause) {
        super(cause);
    }
}
