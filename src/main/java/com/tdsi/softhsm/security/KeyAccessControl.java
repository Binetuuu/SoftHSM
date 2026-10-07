package com.tdsi.softhsm.security;

import com.tdsi.softhsm.model.AccessContext;
import com.tdsi.softhsm.model.User;
import com.tdsi.softhsm.model.enums.KeyOperation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * Service de contrôle d'accès basé sur les rôles (RBAC - Role-Based Access Control).
 * 
 * Ce service :
 * - Vérifie les permissions avant chaque opération sur les clés
 * - Maintient un journal d'audit de tous les accès
 * - Empêche l'affichage direct des clés privées
 * - Limite l'accès selon le rôle de l'utilisateur
 * 
 * Principes de sécurité :
 * - Deny by default : toute opération est refusée sauf autorisation explicite
 * - Least privilege : les utilisateurs n'ont que les permissions strictement nécessaires
 * - Audit trail : toutes les tentatives d'accès sont enregistrées
 * - Separation of duties : les rôles sont clairement séparés
 */
public class KeyAccessControl {
    
    private static final Logger logger = LoggerFactory.getLogger(KeyAccessControl.class);
    
    /**
     * Chemin du fichier de log d'audit
     */
    private static final String DEFAULT_AUDIT_LOG_PATH = "logs/access_audit.log";
    
    /**
     * Format de date pour les logs
     */
    private static final DateTimeFormatter LOG_DATE_FORMAT = 
        DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS");
    
    /**
     * Cache des sessions utilisateurs actives (userId -> User)
     */
    private final ConcurrentHashMap<String, User> activeSessions;
    
    /**
     * Historique des accès refusés pour détection d'attaques
     */
    private final ConcurrentHashMap<String, List<AccessAttempt>> deniedAccessHistory;
    
    /**
     * Chemin du fichier de log d'audit
     */
    private final Path auditLogPath;
    
    /**
     * Active ou désactive l'écriture des logs d'audit
     */
    private final boolean auditEnabled;
    
    /**
     * Constructeur par défaut avec audit activé
     */
    public KeyAccessControl() {
        this(true, Paths.get(DEFAULT_AUDIT_LOG_PATH));
    }
    
    /**
     * Constructeur avec configuration personnalisée
     * 
     * @param auditEnabled Active ou désactive l'audit
     * @param auditLogPath Chemin du fichier de log d'audit
     */
    public KeyAccessControl(boolean auditEnabled, Path auditLogPath) {
        this.auditEnabled = auditEnabled;
        this.auditLogPath = Objects.requireNonNull(auditLogPath, "Le chemin du log d'audit ne peut pas être null");
        this.activeSessions = new ConcurrentHashMap<>();
        this.deniedAccessHistory = new ConcurrentHashMap<>();
        
        if (auditEnabled) {
            initializeAuditLog();
        }
        
        logger.info("KeyAccessControl initialisé (audit: {})", auditEnabled);
    }
    
    /**
     * Initialise le fichier de log d'audit
     */
    private void initializeAuditLog() {
        try {
            // Créer le répertoire parent si nécessaire
            Path parentDir = auditLogPath.getParent();
            if (parentDir != null && !Files.exists(parentDir)) {
                Files.createDirectories(parentDir);
            }
            
            // Créer le fichier s'il n'existe pas
            if (!Files.exists(auditLogPath)) {
                Files.createFile(auditLogPath);
                writeAuditLog("SYSTEM", "Fichier de log d'audit initialisé");
            }
            
        } catch (IOException e) {
            logger.error("Échec de l'initialisation du fichier de log d'audit", e);
        }
    }
    
    /**
     * Vérifie si un utilisateur a la permission d'effectuer une opération
     * 
     * @param context Contexte d'accès contenant l'utilisateur et l'opération
     * @return true si l'opération est autorisée
     * @throws AccessDeniedException Si l'accès est refusé
     */
    public boolean checkAccess(AccessContext context) throws AccessDeniedException {
        Objects.requireNonNull(context, "Le contexte d'accès ne peut pas être null");
        
        // Vérifier l'autorisation
        if (!context.isAuthorized()) {
            // Enregistrer la tentative d'accès refusé
            recordDeniedAccess(context);
            
            // Logger et auditer
            String message = String.format("Accès refusé : %s", context.getDenialReason());
            logger.warn(message);
            writeAuditLog(context.getUser().getUsername(), 
                "ACCESS_DENIED: " + context.toAuditString());
            
            throw new AccessDeniedException(context.getDenialReason());
        }
        
        // Accès autorisé
        logger.debug("Accès autorisé : {}", context);
        writeAuditLog(context.getUser().getUsername(), 
            "ACCESS_GRANTED: " + context.toAuditString());
        
        // Mettre à jour la dernière activité de l'utilisateur
        context.getUser().updateLastAccess();
        
        return true;
    }
    
    /**
     * Vérifie si un utilisateur peut effectuer une opération spécifique
     * Version simplifiée sans créer un AccessContext complet
     * 
     * @param user Utilisateur
     * @param operation Opération à effectuer
     * @return true si l'opération est autorisée
     */
    public boolean hasPermission(User user, KeyOperation operation) {
        Objects.requireNonNull(user, "L'utilisateur ne peut pas être null");
        Objects.requireNonNull(operation, "L'opération ne peut pas être null");
        
        if (!user.isActive()) {
            return false;
        }
        
        return operation.isAllowedFor(user.getRole());
    }
    
    /**
     * Enregistre une session utilisateur active
     * 
     * @param user Utilisateur à enregistrer
     */
    public void registerSession(User user) {
        Objects.requireNonNull(user, "L'utilisateur ne peut pas être null");
        
        activeSessions.put(user.getUserId(), user);
        writeAuditLog(user.getUsername(), "SESSION_STARTED");
        
        logger.info("Session enregistrée pour l'utilisateur : {}", user.getUsername());
    }
    
    /**
     * Termine une session utilisateur
     * 
     * @param userId ID de l'utilisateur
     */
    public void unregisterSession(String userId) {
        Objects.requireNonNull(userId, "L'ID utilisateur ne peut pas être null");
        
        User user = activeSessions.remove(userId);
        if (user != null) {
            writeAuditLog(user.getUsername(), "SESSION_ENDED");
            logger.info("Session terminée pour l'utilisateur : {}", user.getUsername());
        }
    }
    
    /**
     * Obtient un utilisateur depuis une session active
     * 
     * @param userId ID de l'utilisateur
     * @return Utilisateur ou null si la session n'existe pas
     */
    public User getActiveUser(String userId) {
        return activeSessions.get(userId);
    }
    
    /**
     * Liste tous les utilisateurs avec des sessions actives
     * 
     * @return Liste des utilisateurs actifs
     */
    public List<User> getActiveUsers() {
        return new ArrayList<>(activeSessions.values());
    }
    
    /**
     * Enregistre une tentative d'accès refusé pour détection d'attaques
     * 
     * @param context Contexte de la tentative d'accès
     */
    private void recordDeniedAccess(AccessContext context) {
        String userId = context.getUser().getUserId();
        
        deniedAccessHistory.computeIfAbsent(userId, k -> new ArrayList<>())
            .add(new AccessAttempt(context.getOperation(), LocalDateTime.now()));
        
        // Vérifier si l'utilisateur fait trop de tentatives refusées
        checkForSuspiciousActivity(userId);
    }
    
    /**
     * Vérifie si un utilisateur a un comportement suspect
     * (trop de tentatives d'accès refusées en peu de temps)
     * 
     * @param userId ID de l'utilisateur à vérifier
     */
    private void checkForSuspiciousActivity(String userId) {
        List<AccessAttempt> attempts = deniedAccessHistory.get(userId);
        if (attempts == null) {
            return;
        }
        
        // Compter les tentatives des 5 dernières minutes
        LocalDateTime threshold = LocalDateTime.now().minusMinutes(5);
        long recentAttempts = attempts.stream()
            .filter(attempt -> attempt.timestamp.isAfter(threshold))
            .count();
        
        // Seuil d'alerte : 5 tentatives en 5 minutes
        if (recentAttempts >= 5) {
            User user = activeSessions.get(userId);
            String username = user != null ? user.getUsername() : userId;
            
            logger.warn("ALERTE SÉCURITÉ : Activité suspecte détectée pour l'utilisateur {} " +
                       "({} tentatives d'accès refusées en 5 minutes)", username, recentAttempts);
            
            writeAuditLog(username, 
                String.format("SECURITY_ALERT: %d tentatives d'accès refusées en 5 minutes", recentAttempts));
        }
    }
    
    /**
     * Empêche l'affichage direct d'une clé privée
     * Valide que l'opération n'est pas EXPORT_PRIVATE sauf pour les administrateurs
     * 
     * @param user Utilisateur demandant l'accès
     * @param operation Opération demandée
     * @throws AccessDeniedException Si l'exportation de clé privée n'est pas autorisée
     */
    public void preventPrivateKeyDisplay(User user, KeyOperation operation) throws AccessDeniedException {
        if (operation == KeyOperation.EXPORT_PRIVATE && !user.getRole().isAdmin()) {
            String message = "L'exportation de clés privées est réservée aux administrateurs";
            logger.warn("Tentative d'exportation de clé privée refusée pour : {}", user.getUsername());
            writeAuditLog(user.getUsername(), "BLOCKED: Tentative d'exportation de clé privée");
            throw new AccessDeniedException(message);
        }
    }
    
    /**
     * Écrit une entrée dans le log d'audit
     * 
     * @param username Nom de l'utilisateur
     * @param message Message à enregistrer
     */
    private void writeAuditLog(String username, String message) {
        if (!auditEnabled) {
            return;
        }
        
        try {
            String timestamp = LocalDateTime.now().format(LOG_DATE_FORMAT);
            String logEntry = String.format("[%s] User: %s | %s%n", timestamp, username, message);
            
            Files.write(auditLogPath, logEntry.getBytes(), 
                StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            
        } catch (IOException e) {
            logger.error("Échec de l'écriture dans le log d'audit", e);
        }
    }
    
    /**
     * Lit les dernières entrées du log d'audit
     * 
     * @param maxLines Nombre maximum de lignes à lire
     * @return Liste des entrées de log
     * @throws IOException Si la lecture échoue
     */
    public List<String> readAuditLog(int maxLines) throws IOException {
        if (!Files.exists(auditLogPath)) {
            return new ArrayList<>();
        }
        
        List<String> allLines = Files.readAllLines(auditLogPath);
        
        // Retourner les dernières lignes
        int start = Math.max(0, allLines.size() - maxLines);
        return allLines.subList(start, allLines.size());
    }
    
    /**
     * Filtre les logs d'audit par utilisateur
     * 
     * @param username Nom d'utilisateur à filtrer
     * @param maxLines Nombre maximum de lignes à retourner
     * @return Liste des entrées de log pour cet utilisateur
     * @throws IOException Si la lecture échoue
     */
    public List<String> readAuditLogForUser(String username, int maxLines) throws IOException {
        List<String> allLogs = readAuditLog(Integer.MAX_VALUE);
        
        return allLogs.stream()
            .filter(line -> line.contains("User: " + username))
            .skip(Math.max(0, allLogs.size() - maxLines))
            .collect(Collectors.toList());
    }
    
    /**
     * Compte le nombre de tentatives d'accès refusées pour un utilisateur
     * 
     * @param userId ID de l'utilisateur
     * @return Nombre de tentatives refusées
     */
    public int getDeniedAccessCount(String userId) {
        List<AccessAttempt> attempts = deniedAccessHistory.get(userId);
        return attempts != null ? attempts.size() : 0;
    }
    
    /**
     * Réinitialise l'historique des accès refusés pour un utilisateur
     * 
     * @param userId ID de l'utilisateur
     */
    public void clearDeniedAccessHistory(String userId) {
        deniedAccessHistory.remove(userId);
        logger.info("Historique des accès refusés réinitialisé pour l'utilisateur : {}", userId);
    }
    
    /**
     * Obtient le chemin du fichier de log d'audit
     * 
     * @return Chemin du fichier de log
     */
    public Path getAuditLogPath() {
        return auditLogPath;
    }
    
    /**
     * Vérifie si l'audit est activé
     * 
     * @return true si l'audit est activé
     */
    public boolean isAuditEnabled() {
        return auditEnabled;
    }
    
    /**
     * Classe interne représentant une tentative d'accès
     */
    private static class AccessAttempt {
        final KeyOperation operation;
        final LocalDateTime timestamp;
        
        AccessAttempt(KeyOperation operation, LocalDateTime timestamp) {
            this.operation = operation;
            this.timestamp = timestamp;
        }
    }
}
