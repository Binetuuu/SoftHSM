package com.tdsi.softhsm;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import lombok.extern.slf4j.Slf4j;

/**
 * Application principale SoftHSM - Gestionnaire de Clés Cryptographiques
 * 
 * Projet de fin d'année L3 TDSI 2026
 * 
 * Cette application implémente un système complet de gestion de clés
 * cryptographiques avec des mécanismes de sécurité avancés.
 */
@Slf4j
@SpringBootApplication
public class SoftHSMApplication {

    public static void main(String[] args) {
        log.info("========================================");
        log.info("  SoftHSM - Gestionnaire de Clés       ");
        log.info("  Version: 1.0.0-SNAPSHOT              ");
        log.info("  TDSI L3 - Projet 2026                ");
        log.info("========================================");
        
        SpringApplication.run(SoftHSMApplication.class, args);
        
        log.info("Application SoftHSM démarrée avec succès");
    }
}
