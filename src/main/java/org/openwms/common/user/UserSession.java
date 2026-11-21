package org.openwms.common.user;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;

/**
 * Anmeldesitzung eines Benutzers. Gespeichert wird nur der Hash des Tokens, nie das Token selbst.
 */
@Entity
@Table(name = "COM_USER_SESSION")
public class UserSession {

    @Id
    @Column(name = "C_TOKEN_HASH", length = 64)
    private String tokenHash;

    @Column(name = "C_USERNAME", nullable = false, length = 64)
    private String username;

    @Column(name = "C_EXPIRES_AT", nullable = false)
    private Instant expiresAt;

    protected UserSession() {
        // for JPA
    }

    public UserSession(String tokenHash, String username, Instant expiresAt) {
        this.tokenHash = tokenHash;
        this.username = username;
        this.expiresAt = expiresAt;
    }

    public String getTokenHash() {
        return tokenHash;
    }

    public String getUsername() {
        return username;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }
}
