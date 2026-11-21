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
 * Benutzer-Stammdaten und Anmeldung per Passwort oder Ausweis. Nach {@value #MAX_FAILURES} Fehlversuchen ist ein
 * Benutzer für {@value #LOCK_MINUTES} Minuten gesperrt. Ein inaktiver Benutzer kann sich nicht anmelden.
 */
@Service
public class UserService {

    static final int MAX_FAILURES = 5;
    static final int LOCK_MINUTES = 15;
    static final int MIN_PASSWORD_LENGTH = 8;
    static final int MIN_PIN_LENGTH = 4;

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
     * Hinterlegt einen Ausweis für den Benutzer, optional mit PIN. Ein Ausweis gehört höchstens einem Benutzer.
     */
    @Transactional
    public CommonUser assignBadge(String username, String badge, String pin) {
        var user = find(username);
        var code = required(badge, "Ausweisnummer fehlt.");
        users.findByBadge(code).filter(other -> !other.getUsername().equals(user.getUsername())).ifPresent(other -> {
            throw new UserException(UserException.Kind.CONFLICT, "Ausweis %s gehört bereits einem Benutzer.".formatted(code));
        });
        if (pin != null && !pin.isBlank() && (pin.length() < MIN_PIN_LENGTH || !pin.chars().allMatch(Character::isDigit))) {
            throw new UserException(UserException.Kind.INVALID, "PIN muss aus mindestens %d Ziffern bestehen.".formatted(MIN_PIN_LENGTH));
        }
        user.assignBadge(code, pin == null || pin.isBlank() ? null : Passwords.hash(pin));
        return user;
    }

    /**
     * Prüft Benutzername und Passwort. Liefert den Benutzer bei Erfolg. Bei falschem Passwort, gesperrtem oder
     * inaktivem Benutzer wird {@link UserException} geworfen. Unbekannte Benutzer und falsche Passwörter sind nach
     * außen nicht zu unterscheiden.
     */
    @Transactional(noRollbackFor = UserException.class)
    public CommonUser login(String username, String password) {
        var name = username == null ? "" : username.trim();
        var user = users.findById(name).orElseThrow(UserService::invalidCredentials);
        checkUsable(user);
        if (!Passwords.verify(password, user.getPasswordHash())) {
            fail(user);
        }
        user.recordSuccess();
        return user;
    }

    /**
     * Anmeldung per Ausweis. Ist eine PIN hinterlegt, muss sie stimmen. Fehler werden wie beim Passwort gezählt.
     */
    @Transactional(noRollbackFor = UserException.class)
    public CommonUser loginByBadge(String badge, String pin) {
        var code = badge == null ? "" : badge.trim();
        var user = users.findByBadge(code).orElseThrow(UserService::invalidCredentials);
        checkUsable(user);
        if (user.getPinHash() != null && !Passwords.verify(pin, user.getPinHash())) {
            fail(user);
        }
        user.recordSuccess();
        return user;
    }

    /** Benutzer ohne Passwort, für andere Dienste (z. B. Staplerleitsystem). */
    @Transactional(readOnly = true)
    public CommonUser find(String username) {
        return users.findById(username == null ? "" : username.trim()).orElseThrow(() ->
                new UserException(UserException.Kind.NOT_FOUND, "Benutzer %s nicht gefunden.".formatted(username)));
    }

    @Transactional
    public void deactivate(String username) {
        find(username).deactivate();
    }

    public static List<String> rolesOf(CommonUser user) {
        var text = user.getRoles();
        return text == null || text.isBlank() ? List.of() : Arrays.asList(text.split(","));
    }

    private void checkUsable(CommonUser user) {
        var now = Instant.now(clock);
        if (!user.isActive()) {
            throw new UserException(UserException.Kind.REJECTED, "Benutzer ist deaktiviert.");
        }
        if (user.getLockedUntil() != null && user.getLockedUntil().isAfter(now)) {
            throw new UserException(UserException.Kind.REJECTED, "Benutzer ist gesperrt, bitte später erneut versuchen.");
        }
    }

    private void fail(CommonUser user) {
        user.recordFailure(MAX_FAILURES, Instant.now(clock).plus(Duration.ofMinutes(LOCK_MINUTES)));
        throw invalidCredentials();
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
