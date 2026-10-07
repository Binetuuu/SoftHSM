package com.tdsi.softhsm.security;

/**
 * Exception levée lorsqu'un accès est refusé en raison de permissions insuffisantes.
 */
public class AccessDeniedException extends Exception {
    
    /**
     * Constructeur avec message
     * 
     * @param message Message d'erreur descriptif
     */
    public AccessDeniedException(String message) {
        super(message);
    }
    
    /**
     * Constructeur avec message et cause
     * 
     * @param message Message d'erreur descriptif
     * @param cause Exception d'origine
     */
    public AccessDeniedException(String message, Throwable cause) {
        super(message, cause);
    }
    
    /**
     * Constructeur avec cause uniquement
     * 
     * @param cause Exception d'origine
     */
    public AccessDeniedException(Throwable cause) {
        super(cause);
    }
}
