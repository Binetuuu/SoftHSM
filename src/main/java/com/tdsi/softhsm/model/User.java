package com.tdsi.softhsm.model;

import com.tdsi.softhsm.model.enums.UserRole;

import java.time.LocalDateTime;
import java.util.Objects;
import java.util.UUID;

/**
 * Représente un utilisateur du système HSM.
 * Contient les informations d'identification et les permissions.
 */
public class User {
    private final String userId;
    private final String username;
    private final UserRole role;
    private final LocalDateTime createdAt;
    private LocalDateTime lastAccessAt;
    private boolean enabled;
    
    /**
     * Constructeur pour créer un nouvel utilisateur
     * 
     * @param username Nom d'utilisateur unique
     * @param role Rôle assigné à l'utilisateur
     */
    public User(String username, UserRole role) {
        this.userId = UUID.randomUUID().toString();
        this.username = Objects.requireNonNull(username, "Le nom d'utilisateur ne peut pas être null");
        this.role = Objects.requireNonNull(role, "Le rôle ne peut pas être null");
        this.createdAt = LocalDateTime.now();
        this.lastAccessAt = null;
        this.enabled = true;
    }
    
    /**
     * Constructeur complet pour reconstruction (ex: depuis base de données)
     */
    public User(String userId, String username, UserRole role, 
                LocalDateTime createdAt, LocalDateTime lastAccessAt, boolean enabled) {
        this.userId = userId;
        this.username = username;
        this.role = role;
        this.createdAt = createdAt;
        this.lastAccessAt = lastAccessAt;
        this.enabled = enabled;
    }
    
    /**
     * Met à jour l'horodatage du dernier accès
     */
    public void updateLastAccess() {
        this.lastAccessAt = LocalDateTime.now();
    }
    
    /**
     * Désactive l'utilisateur
     */
    public void disable() {
        this.enabled = false;
    }
    
    /**
     * Active l'utilisateur
     */
    public void enable() {
        this.enabled = true;
    }
    
    // Getters
    public String getUserId() {
        return userId;
    }
    
    public String getUsername() {
        return username;
    }
    
    public UserRole getRole() {
        return role;
    }
    
    public LocalDateTime getCreatedAt() {
        return createdAt;
    }
    
    public LocalDateTime getLastAccessAt() {
        return lastAccessAt;
    }
    
    public boolean isEnabled() {
        return enabled;
    }
    
    /**
     * Vérifie si l'utilisateur est actif et peut accéder au système
     * 
     * @return true si l'utilisateur est actif
     */
    public boolean isActive() {
        return enabled;
    }
    
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        User user = (User) o;
        return Objects.equals(userId, user.userId);
    }
    
    @Override
    public int hashCode() {
        return Objects.hash(userId);
    }
    
    @Override
    public String toString() {
        return "User{" +
                "userId='" + userId + '\'' +
                ", username='" + username + '\'' +
                ", role=" + role +
                ", enabled=" + enabled +
                ", createdAt=" + createdAt +
                '}';
    }
}
