package org.openwms.common.user;

import org.junit.jupiter.api.Test;

import java.lang.reflect.Proxy;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class UserServiceTest {

    private final Map<String, CommonUser> store = new HashMap<>();
    private final CommonUserRepository repo = fakeRepository(store);
    private Instant now = Instant.parse("2026-11-21T10:00:00Z");
    private final Clock clock = new Clock() {
        @Override
        public java.time.ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(java.time.ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    };
    private final UserService service = new UserService(repo, clock);

    @Test
    void passwordsRoundTripAndRejectWrongSecret() {
        String hash = Passwords.hash("geheim-123");
        assertTrue(Passwords.verify("geheim-123", hash));
        assertFalse(Passwords.verify("falsch-123", hash));
        assertFalse(Passwords.verify("geheim-123", "kein-hash"));
        assertFalse(Passwords.hash("geheim-123").equals(hash), "Salt macht jeden Hash eindeutig");
    }

    @Test
    void createAndLoginReturnRoles() {
        service.create("anna", "Anna Test", "geheim-123", List.of("DISPOSITION", "STAPLER"));
        CommonUser u = service.login("anna", "geheim-123");
        assertEquals(List.of("DISPOSITION", "STAPLER"), UserService.rolesOf(u));
    }

    @Test
    void shortPasswordAndDuplicateNameAreRefused() {
        assertThrows(UserException.class, () -> service.create("bert", "Bert", "abc", List.of()));
        service.create("carl", "Carl", "langes-passwort", List.of());
        assertThrows(UserException.class, () -> service.create("carl", "Carl", "langes-passwort", List.of()));
    }

    @Test
    void wrongPasswordLocksAfterFiveFailuresUntilTheLockExpires() {
        service.create("dora", "Dora", "geheim-123", List.of());
        for (int i = 0; i < UserService.MAX_FAILURES; i++) {
            assertThrows(UserException.class, () -> service.login("dora", "falsch-123"));
        }
        // Gesperrt: auch das richtige Passwort wird abgelehnt
        assertThrows(UserException.class, () -> service.login("dora", "geheim-123"));
        // Nach Ablauf der Sperre wieder möglich
        now = now.plus(Duration.ofMinutes(UserService.LOCK_MINUTES + 1));
        assertEquals("dora", service.login("dora", "geheim-123").getUsername());
    }

    @Test
    void deactivatedUserCannotLogin() {
        service.create("erik", "Erik", "geheim-123", List.of());
        service.deactivate("erik");
        assertThrows(UserException.class, () -> service.login("erik", "geheim-123"));
    }

    @Test
    void findReturnsUserWithoutPasswordAndRejectsUnknown() {
        service.create("gina", "Gina", "geheim-123", List.of("STAPLER"));
        CommonUser u = service.find("gina");
        assertEquals("Gina", u.getDisplayName());
        assertTrue(u.isActive());
        assertThrows(UserException.class, () -> service.find("niemand"));
    }

    @Test
    void unknownUserGetsTheSameErrorAsAWrongPassword() {
        service.create("frida", "Frida", "geheim-123", List.of());
        var unknown = assertThrows(UserException.class, () -> service.login("niemand", "x"));
        var wrong = assertThrows(UserException.class, () -> service.login("frida", "falsch-123"));
        assertEquals(wrong.getMessage(), unknown.getMessage());
    }

    @Test
    void badgeLoginWithOptionalPinAndUniqueBadges() {
        service.create("mia", "Mia", "geheim-123", List.of("STAPLER"));
        service.create("nils", "Nils", "geheim-123", List.of());
        service.assignBadge("mia", "BADGE-1", "4711");
        assertEquals("mia", service.loginByBadge("BADGE-1", "4711").getUsername());
        assertThrows(UserException.class, () -> service.loginByBadge("BADGE-1", "0000"));
        assertThrows(UserException.class, () -> service.loginByBadge("BADGE-NICHT", "4711"));
        assertThrows(UserException.class, () -> service.assignBadge("nils", "BADGE-1", null));
        service.assignBadge("nils", "BADGE-2", null);
        assertEquals("nils", service.loginByBadge("BADGE-2", null).getUsername());
    }

    /** Speicher-Fake nur für die Methoden, die der Service nutzt. */
    private static CommonUserRepository fakeRepository(Map<String, CommonUser> store) {
        return (CommonUserRepository) Proxy.newProxyInstance(CommonUserRepository.class.getClassLoader(),
                new Class<?>[]{CommonUserRepository.class}, (proxy, method, args) -> switch (method.getName()) {
                    case "findById" -> Optional.ofNullable(store.get((String) args[0]));
                    case "findByBadge" -> store.values().stream().filter(u -> args[0].equals(u.getBadge())).findFirst();
                    case "existsById" -> store.containsKey((String) args[0]);
                    case "save" -> {
                        CommonUser u = (CommonUser) args[0];
                        store.put(u.getUsername(), u);
                        yield u;
                    }
                    case "hashCode" -> System.identityHashCode(proxy);
                    case "equals" -> proxy == args[0];
                    case "toString" -> "fakeRepository";
                    default -> throw new UnsupportedOperationException(method.getName());
                });
    }
}
