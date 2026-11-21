package org.openwms.common.user;

import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuthServiceTest {

    private final Map<String, CommonUser> users = new HashMap<>();
    private final Map<String, UserSession> sessions = new HashMap<>();
    private Instant now = Instant.parse("2026-11-21T10:00:00Z");
    private final Clock clock = new Clock() {
        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    };
    private final UserService userService = new UserService(fakeUsers(), clock);
    private final AuthService auth = new AuthService(userService, fakeSessions(), clock);

    @Test
    void loginIssuesTokenThatResolvesAndLogoutRevokesIt() {
        userService.create("hanna", "Hanna", "geheim-123", List.of("STAPLER"));
        var issued = auth.login("hanna", "geheim-123");
        assertEquals("hanna", auth.resolve(issued.token()).orElseThrow().getUsername());
        assertFalse(sessions.containsKey(issued.token()), "Gespeichert wird nur der Hash, nie das Token");
        auth.logout(issued.token());
        assertEquals(Optional.empty(), auth.resolve(issued.token()));
    }

    @Test
    void wrongPasswordIssuesNoToken() {
        userService.create("ilse", "Ilse", "geheim-123", List.of());
        assertThrows(UserException.class, () -> auth.login("ilse", "falsch-123"));
        assertTrue(sessions.isEmpty());
    }

    @Test
    void tokenExpiresAfterTheLifetime() {
        userService.create("jan", "Jan", "geheim-123", List.of());
        var issued = auth.login("jan", "geheim-123");
        now = now.plus(Duration.ofHours(AuthService.HOURS).plusSeconds(1));
        assertEquals(Optional.empty(), auth.resolve(issued.token()));
    }

    @Test
    void deactivatedUserLosesTheToken() {
        userService.create("kurt", "Kurt", "geheim-123", List.of());
        var issued = auth.login("kurt", "geheim-123");
        userService.deactivate("kurt");
        assertEquals(Optional.empty(), auth.resolve(issued.token()));
    }

    @Test
    void tokensAreUniqueAndUnknownOnesResolveToNothing() {
        assertNotEquals(AuthService.newToken(), AuthService.newToken());
        assertEquals(Optional.empty(), auth.resolve("gibt-es-nicht"));
        assertEquals(Optional.empty(), auth.resolve(null));
    }

    private CommonUserRepository fakeUsers() {
        return (CommonUserRepository) Proxy.newProxyInstance(CommonUserRepository.class.getClassLoader(),
                new Class<?>[]{CommonUserRepository.class}, (proxy, method, args) -> switch (method.getName()) {
                    case "findById" -> Optional.ofNullable(users.get((String) args[0]));
                    case "findByBadge" -> users.values().stream().filter(u -> args[0].equals(u.getBadge())).findFirst();
                    case "existsById" -> users.containsKey((String) args[0]);
                    case "save" -> {
                        CommonUser u = (CommonUser) args[0];
                        users.put(u.getUsername(), u);
                        yield u;
                    }
                    case "hashCode" -> System.identityHashCode(proxy);
                    case "equals" -> proxy == args[0];
                    default -> throw new UnsupportedOperationException(method.getName());
                });
    }

    private UserSessionRepository fakeSessions() {
        return (UserSessionRepository) Proxy.newProxyInstance(UserSessionRepository.class.getClassLoader(),
                new Class<?>[]{UserSessionRepository.class}, (proxy, method, args) -> switch (method.getName()) {
                    case "findById" -> Optional.ofNullable(sessions.get((String) args[0]));
                    case "save" -> {
                        UserSession s = (UserSession) args[0];
                        sessions.put(s.getTokenHash(), s);
                        yield s;
                    }
                    case "delete" -> {
                        UserSession s = (UserSession) args[0];
                        sessions.remove(s.getTokenHash());
                        yield null;
                    }
                    case "hashCode" -> System.identityHashCode(proxy);
                    case "equals" -> proxy == args[0];
                    default -> throw new UnsupportedOperationException(method.getName());
                });
    }
}
