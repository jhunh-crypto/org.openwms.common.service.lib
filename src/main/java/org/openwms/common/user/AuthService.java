package org.openwms.common.user;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Optional;

/**
 * Tokenausgang: Anmeldung mit Passwort oder Ausweis liefert ein Token. Andere Dienste prüfen das Token über
 * {@link #resolve} und melden sich mit {@link #logout} ab. Ein Token gilt {@value #HOURS} Stunden und wird
 * ungültig, sobald der Benutzer deaktiviert ist.
 */
@Service
public class AuthService {

    static final int HOURS = 12;

    private static final SecureRandom RANDOM = new SecureRandom();

    private final UserService users;
    private final UserSessionRepository sessions;
    private final Clock clock;

    public AuthService(UserService users, UserSessionRepository sessions, Clock clock) {
        this.users = users;
        this.sessions = sessions;
        this.clock = clock;
    }

    public record Issued(String token, Instant expiresAt, CommonUser user) {
    }

    /** Prüft Kennung und Passwort und stellt ein neues Token aus. */
    @Transactional(noRollbackFor = UserException.class)
    public Issued login(String username, String password) {
        return issue(users.login(username, password));
    }

    /** Prüft Ausweis (und PIN, falls hinterlegt) und stellt ein neues Token aus. */
    @Transactional(noRollbackFor = UserException.class)
    public Issued loginByBadge(String badge, String pin) {
        return issue(users.loginByBadge(badge, pin));
    }

    /** Benutzer zu einem gültigen Token; leer bei unbekanntem, abgelaufenem oder gesperrtem Token. */
    @Transactional(readOnly = true)
    public Optional<CommonUser> resolve(String token) {
        if (token == null || token.isBlank()) {
            return Optional.empty();
        }
        return sessions.findById(hash(token.trim()))
                .filter(s -> s.getExpiresAt().isAfter(Instant.now(clock)))
                .flatMap(s -> {
                    try {
                        var user = users.find(s.getUsername());
                        return user.isActive() ? Optional.of(user) : Optional.empty();
                    } catch (UserException e) {
                        return Optional.empty();
                    }
                });
    }

    @Transactional
    public void logout(String token) {
        if (token != null && !token.isBlank()) {
            sessions.findById(hash(token.trim())).ifPresent(sessions::delete);
        }
    }

    private Issued issue(CommonUser user) {
        var token = newToken();
        var expires = Instant.now(clock).plus(Duration.ofHours(HOURS));
        sessions.save(new UserSession(hash(token), user.getUsername(), expires));
        return new Issued(token, expires, user);
    }

    static String newToken() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    static String hash(String token) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
