package org.praxisplatform.authz.compatibility;

import java.time.Instant;
import java.util.List;
import java.util.Objects;

/**
 * Immutable readiness snapshot for the Praxis Authorization subsystem ({@code CC08}, {@code P20}).
 *
 * @param ready {@code true} iff all provider, binding, and compatibility invariants are satisfied
 * @param statusCode {@code UP} or {@code OUT_OF_SERVICE}
 * @param runtimeRevision active OPA runtime revision (or {@code "UNVERIFIED"})
 * @param policySetDigest active policy set digest (or {@code "UNVERIFIED"})
 * @param verifiedDecisionPointCount number of verified decision points
 * @param diagnostics ordered list of blocking diagnostics when {@code ready == false}
 * @param verifiedAt timestamp of the verification
 */
public record PraxisAuthzReadinessStatus(
        boolean ready,
        String statusCode,
        String runtimeRevision,
        String policySetDigest,
        int verifiedDecisionPointCount,
        List<String> diagnostics,
        Instant verifiedAt
) {

    /** Validates non-null status fields. */
    public PraxisAuthzReadinessStatus {
        Objects.requireNonNull(statusCode, "statusCode is required");
        Objects.requireNonNull(runtimeRevision, "runtimeRevision is required");
        Objects.requireNonNull(policySetDigest, "policySetDigest is required");
        diagnostics = diagnostics == null ? List.of() : List.copyOf(diagnostics);
        Objects.requireNonNull(verifiedAt, "verifiedAt is required");
    }
}
