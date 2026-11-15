package org.praxisplatform.authz.autoconfigure;

import java.util.List;
import java.util.Objects;

/**
 * Fail-closed bootstrap exception thrown when {@code praxis-authz-starter} detects missing
 * providers, ambiguous authoritative providers, missing runtime bindings, or host-policy
 * compatibility mismatches at startup ({@code CC08}, {@code P20}, {@code P39}).
 */
public final class PraxisAuthzBootstrapException extends RuntimeException {

    private final String errorCode;
    private final List<String> diagnostics;

    /**
     * Constructs a fail-closed bootstrap exception.
     *
     * @param errorCode machine-readable error code
     * @param message diagnostic summary
     * @param diagnostics individual blocking diagnostics
     */
    public PraxisAuthzBootstrapException(String errorCode, String message, List<String> diagnostics) {
        super(Objects.requireNonNull(message, "message is required"));
        this.errorCode = Objects.requireNonNull(errorCode, "errorCode is required");
        this.diagnostics = diagnostics == null ? List.of() : List.copyOf(diagnostics);
    }

    public String errorCode() {
        return errorCode;
    }

    public List<String> diagnostics() {
        return diagnostics;
    }
}
