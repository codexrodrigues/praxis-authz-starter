package org.praxisplatform.authz.host.metadata;

import java.util.Objects;

/**
 * Exception raised when an operation requires an authenticated caller context
 * ({@link AuthzCallerContext}) that is missing or cannot be verified ({@code HTTP 401}).
 *
 * <p>Extends {@link SecurityException} for backward compatibility with callers and tests catching
 * {@code SecurityException} while allowing {@link PraxisAuthzExceptionHandler} and
 * {@link AuthzCallerContextFilter} to map missing/unverified identity to {@code HTTP 401}.</p>
 */
public class AuthzUnauthenticatedException extends SecurityException {

    private final String reasonCode;

    public AuthzUnauthenticatedException(String message) {
        this("AUTHZ_UNAUTHENTICATED", message);
    }

    public AuthzUnauthenticatedException(String reasonCode, String message) {
        super(Objects.requireNonNull(message, "message is required"));
        this.reasonCode = normalizeReasonCode(reasonCode, "AUTHZ_UNAUTHENTICATED");
    }

    public AuthzUnauthenticatedException(String reasonCode, String message, Throwable cause) {
        super(Objects.requireNonNull(message, "message is required"), cause);
        this.reasonCode = normalizeReasonCode(reasonCode, "AUTHZ_UNAUTHENTICATED");
    }

    public String getReasonCode() {
        return reasonCode;
    }

    private static String normalizeReasonCode(String reasonCode, String fallback) {
        return (reasonCode == null || reasonCode.isBlank()) ? fallback : reasonCode.trim();
    }
}
