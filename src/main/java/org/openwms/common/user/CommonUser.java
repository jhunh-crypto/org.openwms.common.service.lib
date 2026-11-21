package org.openwms.common.user;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;

/**
 * Benutzer mit Anmeldedaten. Passwort und PIN werden nur als PBKDF2-Hash gespeichert. Optional ist ein Ausweis
 * (Badge) hinterlegt. Nach mehreren Fehlversuchen ist die Anmeldung bis {@code lockedUntil} gesperrt.
 */
@Entity
@Table(name = "COM_USER")
public class CommonUser {

    @Id
    @Column(name = "C_USERNAME", length = 64)
    private String username;

    @Column(name = "C_DISPLAY_NAME", length = 128)
    private String displayName;

    @Column(name = "C_PASSWORD_HASH", nullable = false, length = 255)
    private String passwordHash;

    @Column(name = "C_BADGE", unique = true, length = 64)
    private String badge;

    @Column(name = "C_PIN_HASH", length = 255)
    private String pinHash;

    @Column(name = "C_ROLES", length = 255)
    private String roles;

    @Column(name = "C_ACTIVE", nullable = false)
    private boolean active;

    @Column(name = "C_FAILED_LOGINS", nullable = false)
    private int failedLogins;

    @Column(name = "C_LOCKED_UNTIL")
    private Instant lockedUntil;

    protected CommonUser() {
        // for JPA
    }

    public CommonUser(String username, String displayName, String passwordHash, String roles) {
        this.username = username;
        this.displayName = displayName;
        this.passwordHash = passwordHash;
        this.roles = roles;
        this.active = true;
    }

    public void assignBadge(String badge, String pinHash) {
        this.badge = badge;
        this.pinHash = pinHash;
    }

    public void recordFailure(int maxFailures, Instant lockUntil) {
        failedLogins++;
        if (failedLogins >= maxFailures) {
            lockedUntil = lockUntil;
            failedLogins = 0;
        }
    }

    public void recordSuccess() {
        failedLogins = 0;
        lockedUntil = null;
    }

    public void deactivate() {
        this.active = false;
    }

    public String getUsername() {
        return username;
    }

    public String getDisplayName() {
        return displayName;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public String getBadge() {
        return badge;
    }

    public String getPinHash() {
        return pinHash;
    }

    public String getRoles() {
        return roles;
    }

    public boolean isActive() {
        return active;
    }

    public Instant getLockedUntil() {
        return lockedUntil;
    }
}
