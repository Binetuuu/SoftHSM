package com.tdsi.softhsm.storage;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.*;

/**
 * Service de gestion du Java KeyStore pour le stockage sécurisé des clés.
 * 
 * Ce service gère :
 * - L'initialisation et le chargement du KeyStore
 * - Le stockage et la récupération de clés
 * - La vérification d'intégrité
 * - La sauvegarde et la restauration
 * 
 * Format supporté : PKCS12 (recommandé par Java depuis Java 9)
 */
public class KeyStoreService {
    
    private static final Logger logger = LoggerFactory.getLogger(KeyStoreService.class);
    
    /**
     * Type de KeyStore utilisé (PKCS12 est le standard moderne)
     */
    private static final String KEYSTORE_TYPE = "PKCS12";
    
    /**
     * Extension du fichier KeyStore
     */
    private static final String KEYSTORE_EXTENSION = ".p12";
    
    /**
     * Répertoire par défaut pour le stockage
     */
    private static final String DEFAULT_KEYSTORE_DIR = "keystore";
    
    /**
     * Nom du fichier KeyStore par défaut
     */
    private static final String DEFAULT_KEYSTORE_NAME = "softhsm" + KEYSTORE_EXTENSION;
    
    private final Path keystorePath;
    private KeyStore keyStore;
    private char[] keystorePassword;
    private final Object lock = new Object();
    
    /**
     * Constructeur avec chemin par défaut
     * 
     * @param password Mot de passe du KeyStore
     * @throws KeyStoreException Si l'initialisation échoue
     */
    public KeyStoreService(char[] password) throws KeyStoreException {
        this(getDefaultKeystorePath(), password);
    }
    
    /**
     * Constructeur avec chemin personnalisé
     * 
     * @param keystorePath Chemin vers le fichier KeyStore
     * @param password Mot de passe du KeyStore
     * @throws KeyStoreException Si l'initialisation échoue
     */
    public KeyStoreService(Path keystorePath, char[] password) throws KeyStoreException {
        if (password == null || password.length == 0) {
            throw new IllegalArgumentException("Le mot de passe du KeyStore ne peut pas être vide");
        }
        
        this.keystorePath = Objects.requireNonNull(keystorePath, "Le chemin du KeyStore ne peut pas être null");
        this.keystorePassword = Arrays.copyOf(password, password.length);
        
        initializeKeyStore();
    }
    
    /**
     * Obtient le chemin par défaut du KeyStore
     */
    private static Path getDefaultKeystorePath() {
        Path keystoreDir = Paths.get(DEFAULT_KEYSTORE_DIR);
        return keystoreDir.resolve(DEFAULT_KEYSTORE_NAME);
    }
    
    /**
     * Initialise le KeyStore (charge s'il existe, crée sinon)
     */
    private void initializeKeyStore() throws KeyStoreException {
        synchronized (lock) {
            try {
                keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
                logger.debug("KeyStore PKCS12 créé");
                
                if (Files.exists(keystorePath)) {
                    loadKeyStore();
                    logger.info("KeyStore chargé depuis : {}", keystorePath);
                } else {
                    logger.debug("KeyStore n'existe pas, création d'un nouveau : {}", keystorePath);
                    createNewKeyStore();
                    logger.info("Nouveau KeyStore créé : {}", keystorePath);
                }
                
            } catch (NoSuchAlgorithmException e) {
                logger.error("Algorithme non supporté: {}", e.getMessage());
                throw new KeyStoreException("Échec de l'initialisation du KeyStore - Algorithme", e);
            } catch (CertificateException e) {
                logger.error("Erreur de certificat: {}", e.getMessage());
                throw new KeyStoreException("Échec de l'initialisation du KeyStore - Certificat", e);
            } catch (IOException e) {
                logger.error("Erreur E/S: {}", e.getMessage());
                throw new KeyStoreException("Échec de l'initialisation du KeyStore - IO", e);
            }
        }
    }
    
    /**
     * Charge un KeyStore existant
     */
    private void loadKeyStore() throws IOException, NoSuchAlgorithmException, CertificateException {
        try (InputStream is = Files.newInputStream(keystorePath)) {
            keyStore.load(is, keystorePassword);
        }
    }
    
    /**
     * Crée un nouveau KeyStore vide
     */
    private void createNewKeyStore() throws IOException, NoSuchAlgorithmException, CertificateException, KeyStoreException {
        // Créer le répertoire parent si nécessaire
        Path parentDir = keystorePath.getParent();
        if (parentDir != null && !Files.exists(parentDir)) {
            Files.createDirectories(parentDir);
        }
        
        // Initialiser un KeyStore vide
        keyStore.load(null, keystorePassword);
        
        // Sauvegarder le KeyStore vide
        saveKeyStore();
    }
    
    /**
     * Sauvegarde le KeyStore sur disque
     */
    private void saveKeyStore() throws KeyStoreException {
        synchronized (lock) {
            try (OutputStream os = Files.newOutputStream(keystorePath)) {
                keyStore.store(os, keystorePassword);
                logger.debug("KeyStore sauvegardé : {}", keystorePath);
            } catch (IOException e) {
                logger.error("Erreur E/S lors de la sauvegarde: {}", e.getMessage());
                throw new KeyStoreException("Échec de la sauvegarde du KeyStore - IO", e);
            } catch (NoSuchAlgorithmException e) {
                logger.error("Algorithme non supporté: {}", e.getMessage());
                throw new KeyStoreException("Échec de la sauvegarde du KeyStore - Algorithme", e);
            } catch (CertificateException e) {
                logger.error("Erreur de certificat: {}", e.getMessage());
                throw new KeyStoreException("Échec de la sauvegarde du KeyStore - Certificat", e);
            }
        }
    }
    
    /**
     * Stocke une clé secrète dans le KeyStore
     * 
     * @param alias Alias de la clé
     * @param secretKey Clé secrète à stocker
     * @param keyPassword Mot de passe de protection de la clé
     * @throws KeyStoreException Si le stockage échoue
     */
    public void storeSecretKey(String alias, SecretKey secretKey, char[] keyPassword) 
            throws KeyStoreException {
        Objects.requireNonNull(alias, "L'alias ne peut pas être null");
        Objects.requireNonNull(secretKey, "La clé secrète ne peut pas être null");
        Objects.requireNonNull(keyPassword, "Le mot de passe de la clé ne peut pas être null");
        
        synchronized (lock) {
            KeyStore.SecretKeyEntry keyEntry = new KeyStore.SecretKeyEntry(secretKey);
            KeyStore.ProtectionParameter protection = 
                new KeyStore.PasswordProtection(keyPassword);
            
            keyStore.setEntry(alias, keyEntry, protection);
            saveKeyStore();
            
            logger.debug("Clé secrète stockée avec l'alias : {}", alias);
        }
    }
    
    /**
     * Récupère une clé secrète depuis le KeyStore
     * 
     * @param alias Alias de la clé
     * @param keyPassword Mot de passe de la clé
     * @return La clé secrète
     * @throws KeyStoreException Si la récupération échoue
     */
    public SecretKey getSecretKey(String alias, char[] keyPassword) throws KeyStoreException {
        Objects.requireNonNull(alias, "L'alias ne peut pas être null");
        Objects.requireNonNull(keyPassword, "Le mot de passe de la clé ne peut pas être null");
        
        synchronized (lock) {
            try {
                KeyStore.ProtectionParameter protection = 
                    new KeyStore.PasswordProtection(keyPassword);
                
                KeyStore.Entry entry = keyStore.getEntry(alias, protection);
                
                if (entry == null) {
                    throw new KeyStoreException("Aucune clé trouvée pour l'alias : " + alias);
                }
                
                if (!(entry instanceof KeyStore.SecretKeyEntry)) {
                    throw new KeyStoreException("L'entrée n'est pas une clé secrète : " + alias);
                }
                
                return ((KeyStore.SecretKeyEntry) entry).getSecretKey();
                
            } catch (NoSuchAlgorithmException | UnrecoverableEntryException e) {
                throw new KeyStoreException("Échec de la récupération de la clé : " + alias, e);
            }
        }
    }
    
    /**
     * Stocke une paire de clés (publique/privée) dans le KeyStore
     * 
     * @param alias Alias de la paire de clés
     * @param privateKey Clé privée
     * @param certificate Certificat contenant la clé publique
     * @param keyPassword Mot de passe de protection de la clé privée
     * @throws KeyStoreException Si le stockage échoue
     */
    public void storeKeyPair(String alias, PrivateKey privateKey, 
                             Certificate certificate, char[] keyPassword) 
            throws KeyStoreException {
        Objects.requireNonNull(alias, "L'alias ne peut pas être null");
        Objects.requireNonNull(privateKey, "La clé privée ne peut pas être null");
        Objects.requireNonNull(certificate, "Le certificat ne peut pas être null");
        Objects.requireNonNull(keyPassword, "Le mot de passe de la clé ne peut pas être null");
        
        synchronized (lock) {
            Certificate[] chain = {certificate};
            keyStore.setKeyEntry(alias, privateKey, keyPassword, chain);
            saveKeyStore();
            
            logger.debug("Paire de clés stockée avec l'alias : {}", alias);
        }
    }
    
    /**
     * Récupère une clé privée depuis le KeyStore
     * 
     * @param alias Alias de la clé
     * @param keyPassword Mot de passe de la clé
     * @return La clé privée
     * @throws KeyStoreException Si la récupération échoue
     */
    public PrivateKey getPrivateKey(String alias, char[] keyPassword) throws KeyStoreException {
        Objects.requireNonNull(alias, "L'alias ne peut pas être null");
        Objects.requireNonNull(keyPassword, "Le mot de passe de la clé ne peut pas être null");
        
        synchronized (lock) {
            try {
                Key key = keyStore.getKey(alias, keyPassword);
                
                if (key == null) {
                    throw new KeyStoreException("Aucune clé trouvée pour l'alias : " + alias);
                }
                
                if (!(key instanceof PrivateKey)) {
                    throw new KeyStoreException("La clé n'est pas une clé privée : " + alias);
                }
                
                return (PrivateKey) key;
                
            } catch (NoSuchAlgorithmException | UnrecoverableKeyException e) {
                throw new KeyStoreException("Échec de la récupération de la clé privée : " + alias, e);
            }
        }
    }
    
    /**
     * Récupère un certificat (contenant la clé publique) depuis le KeyStore
     * 
     * @param alias Alias du certificat
     * @return Le certificat
     * @throws KeyStoreException Si la récupération échoue
     */
    public Certificate getCertificate(String alias) throws KeyStoreException {
        Objects.requireNonNull(alias, "L'alias ne peut pas être null");
        
        synchronized (lock) {
            Certificate cert = keyStore.getCertificate(alias);
            
            if (cert == null) {
                throw new KeyStoreException("Aucun certificat trouvé pour l'alias : " + alias);
            }
            
            return cert;
        }
    }
    
    /**
     * Vérifie si un alias existe dans le KeyStore
     * 
     * @param alias Alias à vérifier
     * @return true si l'alias existe
     * @throws KeyStoreException Si la vérification échoue
     */
    public boolean containsAlias(String alias) throws KeyStoreException {
        Objects.requireNonNull(alias, "L'alias ne peut pas être null");
        
        synchronized (lock) {
            return keyStore.containsAlias(alias);
        }
    }
    
    /**
     * Supprime une entrée du KeyStore
     * 
     * @param alias Alias de l'entrée à supprimer
     * @throws KeyStoreException Si la suppression échoue
     */
    public void deleteEntry(String alias) throws KeyStoreException {
        Objects.requireNonNull(alias, "L'alias ne peut pas être null");
        
        synchronized (lock) {
            if (!keyStore.containsAlias(alias)) {
                throw new KeyStoreException("Aucune entrée trouvée pour l'alias : " + alias);
            }
            
            keyStore.deleteEntry(alias);
            saveKeyStore();
            
            logger.info("Entrée supprimée : {}", alias);
        }
    }
    
    /**
     * Liste tous les alias dans le KeyStore
     * 
     * @return Liste des alias
     * @throws KeyStoreException Si l'énumération échoue
     */
    public List<String> listAliases() throws KeyStoreException {
        synchronized (lock) {
            List<String> aliases = new ArrayList<>();
            Enumeration<String> aliasEnum = keyStore.aliases();
            
            while (aliasEnum.hasMoreElements()) {
                aliases.add(aliasEnum.nextElement());
            }
            
            return aliases;
        }
    }
    
    /**
     * Obtient le nombre d'entrées dans le KeyStore
     * 
     * @return Nombre d'entrées
     * @throws KeyStoreException Si le comptage échoue
     */
    public int size() throws KeyStoreException {
        synchronized (lock) {
            return keyStore.size();
        }
    }
    
    /**
     * Vérifie l'intégrité du KeyStore en tentant de le recharger
     * 
     * @return true si le KeyStore est intègre
     */
    public boolean verifyIntegrity() {
        synchronized (lock) {
            try {
                // Tentative de rechargement pour vérifier l'intégrité
                KeyStore testKeyStore = KeyStore.getInstance(KEYSTORE_TYPE);
                
                try (InputStream is = Files.newInputStream(keystorePath)) {
                    testKeyStore.load(is, keystorePassword);
                }
                
                logger.debug("Vérification d'intégrité réussie");
                return true;
                
            } catch (Exception e) {
                logger.error("Échec de la vérification d'intégrité du KeyStore", e);
                return false;
            }
        }
    }
    
    /**
     * Crée une sauvegarde du KeyStore
     * 
     * @param backupPath Chemin de la sauvegarde
     * @throws KeyStoreException Si la sauvegarde échoue
     */
    public void backup(Path backupPath) throws KeyStoreException {
        Objects.requireNonNull(backupPath, "Le chemin de sauvegarde ne peut pas être null");
        
        synchronized (lock) {
            try {
                // Créer le répertoire parent si nécessaire
                Path parentDir = backupPath.getParent();
                if (parentDir != null && !Files.exists(parentDir)) {
                    Files.createDirectories(parentDir);
                }
                
                Files.copy(keystorePath, backupPath);
                logger.info("Sauvegarde du KeyStore créée : {}", backupPath);
                
            } catch (IOException e) {
                throw new KeyStoreException("Échec de la création de la sauvegarde", e);
            }
        }
    }
    
    /**
     * Restaure le KeyStore depuis une sauvegarde
     * 
     * @param backupPath Chemin de la sauvegarde
     * @throws KeyStoreException Si la restauration échoue
     */
    public void restore(Path backupPath) throws KeyStoreException {
        Objects.requireNonNull(backupPath, "Le chemin de sauvegarde ne peut pas être null");
        
        if (!Files.exists(backupPath)) {
            throw new KeyStoreException("La sauvegarde n'existe pas : " + backupPath);
        }
        
        synchronized (lock) {
            try {
                // Vérifier que la sauvegarde est valide
                KeyStore testKeyStore = KeyStore.getInstance(KEYSTORE_TYPE);
                try (InputStream is = Files.newInputStream(backupPath)) {
                    testKeyStore.load(is, keystorePassword);
                }
                
                // Si la validation réussit, copier la sauvegarde
                Files.copy(backupPath, keystorePath, 
                    java.nio.file.StandardCopyOption.REPLACE_EXISTING);
                
                // Recharger le KeyStore
                loadKeyStore();
                
                logger.info("KeyStore restauré depuis : {}", backupPath);
                
            } catch (Exception e) {
                throw new KeyStoreException("Échec de la restauration du KeyStore", e);
            }
        }
    }
    
    /**
     * Obtient le chemin du KeyStore
     * 
     * @return Chemin du fichier KeyStore
     */
    public Path getKeystorePath() {
        return keystorePath;
    }
    
    /**
     * Nettoie les ressources (efface les mots de passe en mémoire)
     */
    public void close() {
        if (keystorePassword != null) {
            Arrays.fill(keystorePassword, (char) 0);
            keystorePassword = null;
        }
        logger.debug("Ressources du KeyStoreService nettoyées");
    }
    
    /**
     * Change le mot de passe du KeyStore
     * 
     * @param newPassword Nouveau mot de passe
     * @throws KeyStoreException Si le changement échoue
     */
    public void changePassword(char[] newPassword) throws KeyStoreException {
        Objects.requireNonNull(newPassword, "Le nouveau mot de passe ne peut pas être null");
        
        if (newPassword.length == 0) {
            throw new IllegalArgumentException("Le nouveau mot de passe ne peut pas être vide");
        }
        
        synchronized (lock) {
            // Effacer l'ancien mot de passe
            Arrays.fill(keystorePassword, (char) 0);
            
            // Définir le nouveau mot de passe
            keystorePassword = Arrays.copyOf(newPassword, newPassword.length);
            
            // Sauvegarder avec le nouveau mot de passe
            saveKeyStore();
            
            logger.info("Mot de passe du KeyStore changé");
        }
    }
}
