package com.tdsi.softhsm.security;

/**
 * Exception levée lors d'une erreur de dérivation de clé.
 */
public class KeyDerivationException extends Exception {
    
    /**
     * Constructeur avec message
     * 
     * @param message Message d'erreur descriptif
     */
    public KeyDerivationException(String message) {
        super(message);
    }
    
    /**
     * Constructeur avec message et cause
     * 
     * @param message Message d'erreur descriptif
     * @param cause Exception d'origine
     */
    public KeyDerivationException(String message, Throwable cause) {
        super(message, cause);
    }
    
    /**
     * Constructeur avec cause uniquement
     * 
     * @param cause Exception d'origine
     */
    public KeyDerivationException(Throwable cause) {
        super(cause);
    }
}
