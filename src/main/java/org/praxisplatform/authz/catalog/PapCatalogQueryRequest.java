package org.praxisplatform.authz.catalog;

import java.util.Objects;
import java.util.Set;

/**
 * Scoped PAP catalog discovery request ({@code P35}, {@code P43}, {@code P54}, {@code P62}).
 *
 * @param callerPrincipalId authenticated caller principal identifier
 * @param callerAuthorities authenticated caller authorities
 * @param allowedServiceScopes service keys the caller is authorized to inspect in the PAP
 * @param requestedServiceKey target service key requested by the PAP author
 */
public record PapCatalogQueryRequest(
        String callerPrincipalId,
        Set<String> callerAuthorities,
        Set<String> allowedServiceScopes,
        String requestedServiceKey
) {

    /** Validates caller identity and requested service key. */
    public PapCatalogQueryRequest {
        Objects.requireNonNull(callerPrincipalId, "callerPrincipalId is required");
        callerPrincipalId = callerPrincipalId.trim();
        if (callerPrincipalId.isEmpty()) {
            throw new IllegalArgumentException("callerPrincipalId must not be blank");
        }
        callerAuthorities = callerAuthorities == null ? Set.of() : Set.copyOf(callerAuthorities);
        allowedServiceScopes = allowedServiceScopes == null ? Set.of() : Set.copyOf(allowedServiceScopes);
        Objects.requireNonNull(requestedServiceKey, "requestedServiceKey is required");
        requestedServiceKey = requestedServiceKey.trim();
        if (requestedServiceKey.isEmpty()) {
            throw new IllegalArgumentException("requestedServiceKey must not be blank");
        }
    }
}
