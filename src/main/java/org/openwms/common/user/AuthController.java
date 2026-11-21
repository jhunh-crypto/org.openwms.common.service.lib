package org.openwms.common.user;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

/**
 * Token prüfen und abmelden. Das Token kommt im Header Authorization mit dem Schema Bearer.
 */
@RestController
@RequestMapping("/v1/common/auth")
public class AuthController {

    private final AuthService auth;

    public AuthController(AuthService auth) {
        this.auth = auth;
    }

    @GetMapping("/me")
    public UserController.UserResponse me(@RequestHeader(value = "Authorization", required = false) String authorization) {
        return auth.resolve(bearer(authorization))
                .map(UserController.UserResponse::of)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Token ungültig oder abgelaufen."));
    }

    @PostMapping("/logout")
    public void logout(@RequestHeader(value = "Authorization", required = false) String authorization) {
        auth.logout(bearer(authorization));
    }

    static String bearer(String header) {
        if (header == null || !header.regionMatches(true, 0, "Bearer ", 0, 7)) {
            return null;
        }
        return header.substring(7).trim();
    }
}
