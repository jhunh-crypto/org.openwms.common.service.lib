package org.openwms.common.user;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/**
 * Benutzer-Stammdaten und Anmeldung in Common. Der Staplerleitsystem-Dienst prüft Benutzer über
 * GET /v1/common/users/{username} und Tokens über /v1/common/auth.
 */
@RestController
@RequestMapping("/v1/common/users")
public class UserController {

    private final UserService users;
    private final AuthService auth;

    public UserController(UserService users, AuthService auth) {
        this.users = users;
        this.auth = auth;
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

    public record LoginResponse(String token, Instant expiresAt, UserResponse user) {
    }

    @PostMapping
    public UserResponse create(@RequestBody CreateUserRequest req) {
        return UserResponse.of(users.create(req.username(), req.displayName(), req.password(), req.roles()));
    }

    @GetMapping("/{username}")
    public UserResponse find(@PathVariable String username) {
        return UserResponse.of(users.find(username));
    }

    @PostMapping("/login")
    public LoginResponse login(@RequestBody LoginRequest req) {
        var issued = auth.login(req.username(), req.password());
        return new LoginResponse(issued.token(), issued.expiresAt(), UserResponse.of(issued.user()));
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
