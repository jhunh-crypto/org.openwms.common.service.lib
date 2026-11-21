package org.openwms.common.user;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/**
 * Benutzer-Stammdaten und Anmeldung in Common. Der Staplerleitsystem-Dienst prüft Benutzer über diese Schnittstelle.
 */
@RestController
@RequestMapping("/v1/common/users")
public class UserController {

    private final UserService users;

    public UserController(UserService users) {
        this.users = users;
    }

    public record CreateUserRequest(String username, String displayName, String password, List<String> roles) {
    }

    public record LoginRequest(String username, String password) {
    }

    public record UserResponse(String username, String displayName, List<String> roles, boolean active) {
        static UserResponse of(CommonUser u) {
            return new UserResponse(u.getUsername(), u.getDisplayName(), UserService.rolesOf(u), u.isActive());
        }
    }

    @PostMapping
    public UserResponse create(@RequestBody CreateUserRequest req) {
        return UserResponse.of(users.create(req.username(), req.displayName(), req.password(), req.roles()));
    }

    @PostMapping("/login")
    public UserResponse login(@RequestBody LoginRequest req) {
        return UserResponse.of(users.login(req.username(), req.password()));
    }

    @ExceptionHandler(UserException.class)
    public ResponseEntity<Map<String, String>> handle(UserException e) {
        HttpStatus status = switch (e.getKind()) {
            case INVALID -> HttpStatus.BAD_REQUEST;
            case CONFLICT -> HttpStatus.CONFLICT;
            case NOT_FOUND -> HttpStatus.NOT_FOUND;
            case REJECTED -> HttpStatus.UNAUTHORIZED;
        };
        return ResponseEntity.status(status).body(Map.of("detail", e.getMessage()));
    }
}
