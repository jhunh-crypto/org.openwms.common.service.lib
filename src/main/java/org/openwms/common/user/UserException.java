package org.openwms.common.user;

/**
 * Fehler bei Benutzer und Anmeldung. Die Art bestimmt den HTTP-Status im Controller.
 */
public class UserException extends RuntimeException {

    public enum Kind {INVALID, CONFLICT, NOT_FOUND, REJECTED}

    private final Kind kind;

    public UserException(Kind kind, String message) {
        super(message);
        this.kind = kind;
    }

    public Kind getKind() {
        return kind;
    }
}
