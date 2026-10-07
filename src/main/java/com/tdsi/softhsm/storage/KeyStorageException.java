package com.tdsi.softhsm.storage;

/**
 * Exception levée lors d'erreurs liées au stockage des clés.
 */
public class KeyStorageException extends Exception {
    
    /**
     * Constructeur avec message
     * 
     * @param message Message d'erreur descriptif
     */
    public KeyStorageException(String message) {
        super(message);
    }
    
    /**
     * Constructeur avec message et cause
     * 
     * @param message Message d'erreur descriptif
     * @param cause Exception d'origine
     */
    public KeyStorageException(String message, Throwable cause) {
        super(message, cause);
    }
    
    /**
     * Constructeur avec cause uniquement
     * 
     * @param cause Exception d'origine
     */
    public KeyStorageException(Throwable cause) {
        super(cause);
    }
}
