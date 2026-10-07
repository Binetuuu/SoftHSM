package com.tdsi.softhsm.storage;

import com.tdsi.softhsm.model.CryptographicKey;
import com.tdsi.softhsm.security.EncryptionException;
import com.tdsi.softhsm.security.KeyDerivationException;
import com.tdsi.softhsm.security.KeyDerivationService;
import com.tdsi.softhsm.security.KeyEncryptionService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.SecretKey;
import java.nio.file.Path;
import java.security.KeyStoreException;
import java.util.*;

/**
 * Gestionnaire de stockage sécurisé des clés cryptographiques.
 * 
 * Cette classe orchestre tous les composants de sécurité pour assurer :
 * - Le chiffrement des clés avant stockage
 * - La dérivation sécurisée de la clé maître depuis un mot de passe
 * - Le stockage dans un KeyStore protégé
 * - La gestion des métadonnées des clés
 * 
 * Architecture de sécurité :
 * 1. L'utilisateur fournit un mot de passe maître
 * 2. Le mot de passe est dérivé en clé maître via PBKDF2 (KeyDerivationService)
 * 3. Chaque clé sensible est chiffrée avec la clé maître via AES-GCM (KeyEncryptionService)
 * 4. Les clés chiffrées sont stockées dans un KeyStore PKCS12 (KeyStoreService)
 * 5. Le KeyStore lui-même est protégé par un mot de passe
 */
public class SecureKeyStorage {
    
    private static final Logger logger = LoggerFactory.getLogger(SecureKeyStorage.class);
    
    /**
     * Préfixe pour les alias de clés dans le KeyStore
     */
    private static final String KEY_ALIAS_PREFIX = "key_";
    
    /**
     * Alias spécial pour stocker le salt de dérivation de la clé maître
     */
    private static final String MASTER_SALT_ALIAS = "master_key_salt";
    
    /**
     * Algorithme par défaut pour les métadonnées
     */
    private static final String METADATA_ALGORITHM = "metadata";
    
    private final KeyStoreService keyStoreService;
    private final KeyEncryptionService encryptionService;
    private final KeyDerivationService derivationService;
    private final SecretKey masterKey;
    private final Map<String, KeyMetadata> metadataCache;
    
    /**
     * Constructeur - Initialise le stockage sécurisé avec un mot de passe maître
     * 
     * @param keystorePath Chemin vers le fichier KeyStore
     * @param keystorePassword Mot de passe du KeyStore
     * @param masterPassword Mot de passe maître pour dériver la clé de chiffrement
     * @throws KeyStorageException Si l'initialisation échoue
     */
    public SecureKeyStorage(Path keystorePath, char[] keystorePassword, char[] masterPassword) 
            throws KeyStorageException {
        Objects.requireNonNull(keystorePath, "Le chemin du KeyStore ne peut pas être null");
        Objects.requireNonNull(keystorePassword, "Le mot de passe du KeyStore ne peut pas être null");
        Objects.requireNonNull(masterPassword, "Le mot de passe maître ne peut pas être null");
        
        try {
            // Initialiser les services
            this.keyStoreService = new KeyStoreService(keystorePath, keystorePassword);
            this.encryptionService = new KeyEncryptionService();
            this.derivationService = new KeyDerivationService();
            this.metadataCache = new HashMap<>();
            
            // Dériver ou récupérer la clé maître
            this.masterKey = initializeMasterKey(masterPassword);
            
            logger.info("SecureKeyStorage initialisé avec succès");
            
        } catch (KeyStoreException e) {
            throw new KeyStorageException("Échec de l'initialisation du stockage sécurisé", e);
        }
    }
    
    /**
     * Initialise la clé maître depuis le mot de passe
     * Si un salt existe déjà dans le KeyStore, il est réutilisé.
     * Sinon, un nouveau salt est généré et stocké.
     * 
     * @param masterPassword Mot de passe maître
     * @return Clé maître dérivée
     * @throws KeyStorageException Si l'initialisation échoue
     */
    private SecretKey initializeMasterKey(char[] masterPassword) throws KeyStorageException {
        try {
            byte[] salt;
            
            // Vérifier si un salt existe déjà
            if (keyStoreService.containsAlias(MASTER_SALT_ALIAS)) {
                // Récupérer le salt existant
                SecretKey saltKey = keyStoreService.getSecretKey(MASTER_SALT_ALIAS, masterPassword);
                byte[] paddedSalt = saltKey.getEncoded();
                // Extraire le salt original (32 bytes)
                salt = new byte[32];
                System.arraycopy(paddedSalt, 0, salt, 0, 32);
                logger.debug("Salt maître existant récupéré");
            } else {
                // Générer un nouveau salt
                salt = derivationService.generateSalt();
                
                // Stocker le salt dans le KeyStore
                // Créer une clé AES valide de 32 bytes pour stocker le salt
                byte[] paddedSalt = new byte[32]; // AES-256 nécessite 32 bytes
                System.arraycopy(salt, 0, paddedSalt, 0, salt.length);
                
                javax.crypto.spec.SecretKeySpec saltKey = 
                    new javax.crypto.spec.SecretKeySpec(paddedSalt, "AES");
                keyStoreService.storeSecretKey(MASTER_SALT_ALIAS, saltKey, masterPassword);
                
                logger.debug("Nouveau salt maître généré et stocké");
            }
            
            // Dériver la clé maître depuis le mot de passe et le salt
            byte[] derivedKeyBytes = derivationService.deriveKey(masterPassword, salt);
            SecretKey masterKey = encryptionService.createKeyFromDerived(derivedKeyBytes);
            
            // Effacer les données sensibles
            Arrays.fill(derivedKeyBytes, (byte) 0);
            Arrays.fill(salt, (byte) 0);
            
            logger.info("Clé maître initialisée avec succès");
            return masterKey;
            
        } catch (KeyStoreException | KeyDerivationException | EncryptionException e) {
            throw new KeyStorageException("Échec de l'initialisation de la clé maître", e);
        }
    }
    
    /**
     * Stocke une clé cryptographique de manière sécurisée
     * 
     * @param key Métadonnées de la clé à stocker
     * @param secretKey La clé secrète à protéger
     * @param keyPassword Mot de passe pour protéger cette clé spécifique
     * @throws KeyStorageException Si le stockage échoue
     */
    public void storeKey(CryptographicKey key, SecretKey secretKey, char[] keyPassword) 
            throws KeyStorageException {
        Objects.requireNonNull(key, "La clé ne peut pas être null");
        Objects.requireNonNull(secretKey, "La clé secrète ne peut pas être null");
        Objects.requireNonNull(keyPassword, "Le mot de passe de la clé ne peut pas être null");
        
        try {
            // Générer l'alias pour cette clé
            String alias = generateAlias(key.getId());
            
            // Vérifier si la clé existe déjà
            if (keyStoreService.containsAlias(alias)) {
                throw new KeyStorageException("Une clé avec l'ID " + key.getId() + " existe déjà");
            }
            
            // Chiffrer la clé avec la clé maître
            KeyEncryptionService.EncryptedData encryptedKey = 
                encryptionService.encryptKey(secretKey, masterKey);
            
            // Convertir les données chiffrées en SecretKey pour stockage dans le KeyStore
            byte[] combinedData = encryptedKey.toCombinedArray();
            
            // Stocker la taille originale dans les 4 premiers bytes
            byte[] sizeHeader = new byte[4];
            sizeHeader[0] = (byte) (combinedData.length >>> 24);
            sizeHeader[1] = (byte) (combinedData.length >>> 16);
            sizeHeader[2] = (byte) (combinedData.length >>> 8);
            sizeHeader[3] = (byte) combinedData.length;
            
            // Créer le payload avec header + données + padding pour AES
            byte[] payload = new byte[sizeHeader.length + combinedData.length];
            System.arraycopy(sizeHeader, 0, payload, 0, sizeHeader.length);
            System.arraycopy(combinedData, 0, payload, sizeHeader.length, combinedData.length);
            
            // Padder à une taille AES valide (multiple de 32)
            int paddedSize = ((payload.length + 31) / 32) * 32;
            byte[] paddedData = new byte[paddedSize];
            System.arraycopy(payload, 0, paddedData, 0, payload.length);
            
            javax.crypto.spec.SecretKeySpec wrappedKey = 
                new javax.crypto.spec.SecretKeySpec(paddedData, "AES");
            
            // Stocker dans le KeyStore
            keyStoreService.storeSecretKey(alias, wrappedKey, keyPassword);
            
            // Stocker les métadonnées en cache
            KeyMetadata metadata = new KeyMetadata(
                key.getId(),
                key.getAlgorithm().name(),
                key.getKeyType(),
                key.getCreatedAt(),
                key.getDescription()
            );
            metadataCache.put(key.getId(), metadata);
            
            // Nettoyer les données sensibles
            encryptedKey.clear();
            Arrays.fill(combinedData, (byte) 0);
            Arrays.fill(paddedData, (byte) 0);
            
            logger.info("Clé stockée avec succès : {}", key.getId());
            
        } catch (KeyStoreException | EncryptionException e) {
            throw new KeyStorageException("Échec du stockage de la clé : " + key.getId(), e);
        }
    }
    
    /**
     * Récupère une clé cryptographique depuis le stockage sécurisé
     * 
     * @param keyId ID de la clé à récupérer
     * @param keyPassword Mot de passe de protection de la clé
     * @return La clé déchiffrée
     * @throws KeyStorageException Si la récupération échoue
     */
    public SecretKey retrieveKey(String keyId, char[] keyPassword) throws KeyStorageException {
        Objects.requireNonNull(keyId, "L'ID de la clé ne peut pas être null");
        Objects.requireNonNull(keyPassword, "Le mot de passe de la clé ne peut pas être null");
        
        try {
            String alias = generateAlias(keyId);
            
            // Vérifier que la clé existe
            if (!keyStoreService.containsAlias(alias)) {
                throw new KeyStorageException("Aucune clé trouvée avec l'ID : " + keyId);
            }
            
            // Récupérer la clé chiffrée depuis le KeyStore
            SecretKey wrappedKey = keyStoreService.getSecretKey(alias, keyPassword);
            byte[] paddedData = wrappedKey.getEncoded();
            
            // Récupérer la taille originale depuis l'header
            int originalSize = ((paddedData[0] & 0xFF) << 24) |
                              ((paddedData[1] & 0xFF) << 16) |
                              ((paddedData[2] & 0xFF) << 8) |
                              (paddedData[3] & 0xFF);
            
            // Extraire les données originales (skip header de 4 bytes)
            byte[] combinedData = new byte[originalSize];
            System.arraycopy(paddedData, 4, combinedData, 0, originalSize);
            
            // Reconstruire les données chiffrées
            KeyEncryptionService.EncryptedData encryptedData = 
                KeyEncryptionService.EncryptedData.fromCombinedArray(combinedData);
            
            // Récupérer les métadonnées
            KeyMetadata metadata = metadataCache.get(keyId);
            if (metadata == null) {
                throw new KeyStorageException("Métadonnées introuvables pour la clé : " + keyId);
            }
            
            // Déchiffrer la clé
            SecretKey secretKey = encryptionService.decryptKey(
                encryptedData, 
                masterKey, 
                metadata.getAlgorithm()
            );
            
            // Nettoyer les données sensibles
            encryptedData.clear();
            Arrays.fill(combinedData, (byte) 0);
            Arrays.fill(paddedData, (byte) 0);
            
            logger.debug("Clé récupérée avec succès : {}", keyId);
            return secretKey;
            
        } catch (KeyStoreException | EncryptionException e) {
            throw new KeyStorageException("Échec de la récupération de la clé : " + keyId, e);
        }
    }
    
    /**
     * Vérifie si une clé existe dans le stockage
     * 
     * @param keyId ID de la clé à vérifier
     * @return true si la clé existe
     * @throws KeyStorageException Si la vérification échoue
     */
    public boolean keyExists(String keyId) throws KeyStorageException {
        Objects.requireNonNull(keyId, "L'ID de la clé ne peut pas être null");
        
        try {
            String alias = generateAlias(keyId);
            return keyStoreService.containsAlias(alias);
        } catch (KeyStoreException e) {
            throw new KeyStorageException("Échec de la vérification de l'existence de la clé", e);
        }
    }
    
    /**
     * Supprime une clé du stockage
     * 
     * @param keyId ID de la clé à supprimer
     * @throws KeyStorageException Si la suppression échoue
     */
    public void deleteKey(String keyId) throws KeyStorageException {
        Objects.requireNonNull(keyId, "L'ID de la clé ne peut pas être null");
        
        try {
            String alias = generateAlias(keyId);
            
            if (!keyStoreService.containsAlias(alias)) {
                throw new KeyStorageException("Aucune clé trouvée avec l'ID : " + keyId);
            }
            
            keyStoreService.deleteEntry(alias);
            metadataCache.remove(keyId);
            
            logger.info("Clé supprimée : {}", keyId);
            
        } catch (KeyStoreException e) {
            throw new KeyStorageException("Échec de la suppression de la clé : " + keyId, e);
        }
    }
    
    /**
     * Liste tous les ID de clés stockées
     * 
     * @return Liste des ID de clés
     * @throws KeyStorageException Si la liste ne peut pas être obtenue
     */
    public List<String> listKeyIds() throws KeyStorageException {
        try {
            List<String> allAliases = keyStoreService.listAliases();
            List<String> keyIds = new ArrayList<>();
            
            for (String alias : allAliases) {
                // Filtrer uniquement les alias de clés (pas le salt maître)
                if (alias.startsWith(KEY_ALIAS_PREFIX)) {
                    String keyId = alias.substring(KEY_ALIAS_PREFIX.length());
                    keyIds.add(keyId);
                }
            }
            
            return keyIds;
            
        } catch (KeyStoreException e) {
            throw new KeyStorageException("Échec de la liste des clés", e);
        }
    }
    
    /**
     * Obtient les métadonnées d'une clé sans la déchiffrer
     * 
     * @param keyId ID de la clé
     * @return Métadonnées de la clé
     * @throws KeyStorageException Si les métadonnées sont introuvables
     */
    public KeyMetadata getKeyMetadata(String keyId) throws KeyStorageException {
        Objects.requireNonNull(keyId, "L'ID de la clé ne peut pas être null");
        
        KeyMetadata metadata = metadataCache.get(keyId);
        if (metadata == null) {
            throw new KeyStorageException("Métadonnées introuvables pour la clé : " + keyId);
        }
        
        return metadata;
    }
    
    /**
     * Vérifie l'intégrité du KeyStore
     * 
     * @return true si le KeyStore est intègre
     */
    public boolean verifyIntegrity() {
        return keyStoreService.verifyIntegrity();
    }
    
    /**
     * Crée une sauvegarde du KeyStore
     * 
     * @param backupPath Chemin de la sauvegarde
     * @throws KeyStorageException Si la sauvegarde échoue
     */
    public void backup(Path backupPath) throws KeyStorageException {
        try {
            keyStoreService.backup(backupPath);
            logger.info("Sauvegarde créée : {}", backupPath);
        } catch (KeyStoreException e) {
            throw new KeyStorageException("Échec de la sauvegarde", e);
        }
    }
    
    /**
     * Restaure le KeyStore depuis une sauvegarde
     * 
     * @param backupPath Chemin de la sauvegarde
     * @throws KeyStorageException Si la restauration échoue
     */
    public void restore(Path backupPath) throws KeyStorageException {
        try {
            keyStoreService.restore(backupPath);
            // Vider le cache de métadonnées car elles pourraient être obsolètes
            metadataCache.clear();
            logger.info("Restauration effectuée depuis : {}", backupPath);
        } catch (KeyStoreException e) {
            throw new KeyStorageException("Échec de la restauration", e);
        }
    }
    
    /**
     * Obtient le nombre de clés stockées
     * 
     * @return Nombre de clés
     * @throws KeyStorageException Si le comptage échoue
     */
    public int getKeyCount() throws KeyStorageException {
        try {
            // Soustraire 1 pour le salt maître qui n'est pas une clé utilisateur
            int totalEntries = keyStoreService.size();
            return Math.max(0, totalEntries - 1);
        } catch (KeyStoreException e) {
            throw new KeyStorageException("Échec du comptage des clés", e);
        }
    }
    
    /**
     * Génère un alias pour le KeyStore à partir d'un ID de clé
     * 
     * @param keyId ID de la clé
     * @return Alias pour le KeyStore
     */
    private String generateAlias(String keyId) {
        return KEY_ALIAS_PREFIX + keyId;
    }
    
    /**
     * Nettoie les ressources et efface les données sensibles
     */
    public void close() {
        keyStoreService.close();
        metadataCache.clear();
        logger.debug("SecureKeyStorage fermé");
    }
    
    /**
     * Classe interne pour stocker les métadonnées des clés
     */
    public static class KeyMetadata {
        private final String keyId;
        private final String algorithm;
        private final com.tdsi.softhsm.model.enums.KeyType keyType;
        private final java.time.LocalDateTime createdAt;
        private final String description;
        
        public KeyMetadata(String keyId, String algorithm, 
                          com.tdsi.softhsm.model.enums.KeyType keyType,
                          java.time.LocalDateTime createdAt, String description) {
            this.keyId = keyId;
            this.algorithm = algorithm;
            this.keyType = keyType;
            this.createdAt = createdAt;
            this.description = description;
        }
        
        public String getKeyId() {
            return keyId;
        }
        
        public String getAlgorithm() {
            return algorithm;
        }
        
        public com.tdsi.softhsm.model.enums.KeyType getKeyType() {
            return keyType;
        }
        
        public java.time.LocalDateTime getCreatedAt() {
            return createdAt;
        }
        
        public String getDescription() {
            return description;
        }
        
        @Override
        public String toString() {
            return "KeyMetadata{" +
                    "keyId='" + keyId + '\'' +
                    ", algorithm='" + algorithm + '\'' +
                    ", keyType=" + keyType +
                    ", createdAt=" + createdAt +
                    ", description='" + description + '\'' +
                    '}';
        }
    }
}
