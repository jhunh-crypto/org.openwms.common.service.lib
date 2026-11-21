package org.openwms.common.user;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/**
 * Benutzer-Stammdaten und Anmeldung. Nach {@value #MAX_FAILURES} Fehlversuchen ist ein Benutzer für
 * {@value #LOCK_MINUTES} Minuten gesperrt. Ein inaktiver Benutzer kann sich nicht anmelden.
 */
@Service
public class UserService {

    static final int MAX_FAILURES = 5;
    static final int LOCK_MINUTES = 15;
    static final int MIN_PASSWORD_LENGTH = 8;

    private final CommonUserRepository users;
    private final Clock clock;

    public UserService(CommonUserRepository users, Clock clock) {
        this.users = users;
        this.clock = clock;
    }

    /** Legt einen Benutzer an. Rollen als Liste, z. B. {@code ["DISPOSITION", "STAPLER"]}. */
    @Transactional
    public CommonUser create(String username, String displayName, String password, List<String> roles) {
        var name = required(username, "Benutzername fehlt.");
        if (users.existsById(name)) {
            throw new UserException(UserException.Kind.CONFLICT, "Benutzer %s existiert bereits.".formatted(name));
        }
        if (password == null || password.length() < MIN_PASSWORD_LENGTH) {
            throw new UserException(UserException.Kind.INVALID,
                    "Passwort muss mindestens %d Zeichen haben.".formatted(MIN_PASSWORD_LENGTH));
        }
        var rolesText = roles == null ? "" : String.join(",", roles.stream().map(String::trim).filter(r -> !r.isEmpty()).toList());
        return users.save(new CommonUser(name, displayName, Passwords.hash(password), rolesText));
    }

    /**
     * Prüft Benutzername und Passwort. Liefert den Benutzer bei Erfolg. Bei falschem Passwort, gesperrtem oder
     * inaktivem Benutzer wird {@link UserException} geworfen. Unbekannte Benutzer und falsche Passwörter sind nach
     * außen nicht zu unterscheiden.
     */
    @Transactional(noRollbackFor = UserException.class)
    public CommonUser login(String username, String password) {
        var name = username == null ? "" : username.trim();
        Optional<CommonUser> found = users.findById(name);
        if (found.isEmpty()) {
            throw invalidCredentials();
        }
        var user = found.get();
        var now = Instant.now(clock);
        if (!user.isActive()) {
            throw new UserException(UserException.Kind.REJECTED, "Benutzer ist deaktiviert.");
        }
        if (user.getLockedUntil() != null && user.getLockedUntil().isAfter(now)) {
            throw new UserException(UserException.Kind.REJECTED, "Benutzer ist gesperrt, bitte später erneut versuchen.");
        }
        if (!Passwords.verify(password, user.getPasswordHash())) {
            user.recordFailure(MAX_FAILURES, now.plus(Duration.ofMinutes(LOCK_MINUTES)));
            throw invalidCredentials();
        }
        user.recordSuccess();
        return user;
    }

    @Transactional
    public void deactivate(String username) {
        var user = users.findById(username).orElseThrow(() ->
                new UserException(UserException.Kind.NOT_FOUND, "Benutzer %s nicht gefunden.".formatted(username)));
        user.deactivate();
    }

    public static List<String> rolesOf(CommonUser user) {
        var text = user.getRoles();
        return text == null || text.isBlank() ? List.of() : Arrays.asList(text.split(","));
    }

    private static UserException invalidCredentials() {
        return new UserException(UserException.Kind.REJECTED, "Benutzername oder Passwort falsch.");
    }

    private static String required(String s, String message) {
        if (s == null || s.isBlank()) {
            throw new UserException(UserException.Kind.INVALID, message);
        }
        return s.trim();
    }
}
