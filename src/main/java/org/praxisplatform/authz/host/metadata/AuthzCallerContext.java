package org.praxisplatform.authz.host.metadata;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.praxisplatform.authz.contracts.context.FactResolutionStatus;
import org.praxisplatform.authz.contracts.decisionpoint.FieldUseCategory;

/**
 * Immutable per-request caller context consumed by {@link AbstractAuthzGovernedReadOnlyResourceService},
 * {@link AbstractAuthzGovernedResourceService}, and {@link AuthzResourceOperationAvailabilityProvider}
 * ({@code Fases P10.8..P10.9}, {@code CC01}, {@code CC02}, {@code P01}, {@code P02}, {@code P03}).
 *
 * @param tenantId authoritative tenant identifier for hard-scope isolation
 * @param subjectAndEnvironmentFacts authoritative subject and environment facts
 * @param factStatuses resolution statuses for each fact key (defaults to {@link FactResolutionStatus#PRESENT})
 * @param incomingHeaderNames incoming HTTP header names inspected for anti-spoofing guards
 * @param requestedQueryFieldUses requested query field uses ({@code FILTER}, {@code SORT}, {@code GROUP})
 * @param callerMatchesCedente optional explicit {@code Cedente} custody flag (when {@code null}, derived by {@link AuthzResourceGovernanceSpec})
 * @param callerMatchesCessionario optional explicit {@code Cessionário} custody flag (when {@code null}, derived by {@link AuthzResourceGovernanceSpec})
 */
public record AuthzCallerContext(
        String tenantId,
        Map<String, Object> subjectAndEnvironmentFacts,
        Map<String, FactResolutionStatus> factStatuses,
        Set<String> incomingHeaderNames,
        Map<FieldUseCategory, Set<String>> requestedQueryFieldUses,
        Boolean callerMatchesCedente,
        Boolean callerMatchesCessionario
) {

    /** Canonical compact constructor enforcing required invariants and defensive copies. */
    public AuthzCallerContext {
        Objects.requireNonNull(tenantId, "tenantId is required");
        if (tenantId.isBlank()) {
            throw new IllegalArgumentException("tenantId must not be blank");
        }
        subjectAndEnvironmentFacts = subjectAndEnvironmentFacts == null
                ? Map.of()
                : Map.copyOf(subjectAndEnvironmentFacts);
        if (factStatuses == null || factStatuses.isEmpty()) {
            Map<String, FactResolutionStatus> derived = new LinkedHashMap<>();
            for (String key : subjectAndEnvironmentFacts.keySet()) {
                derived.put(key, FactResolutionStatus.PRESENT);
            }
            factStatuses = Map.copyOf(derived);
        } else {
            factStatuses = Map.copyOf(factStatuses);
        }
        incomingHeaderNames = incomingHeaderNames == null ? Set.of() : Set.copyOf(incomingHeaderNames);
        requestedQueryFieldUses = requestedQueryFieldUses == null ? Map.of() : Map.copyOf(requestedQueryFieldUses);
    }

    /**
     * Backward-compatible 5-argument constructor without explicit dual-scope custody overrides.
     *
     * @param tenantId authoritative tenant ID
     * @param subjectAndEnvironmentFacts authoritative subject and environment facts
     * @param factStatuses resolution statuses for each fact key
     * @param incomingHeaderNames incoming HTTP header names
     * @param requestedQueryFieldUses requested query field uses
     */
    public AuthzCallerContext(
            String tenantId,
            Map<String, Object> subjectAndEnvironmentFacts,
            Map<String, FactResolutionStatus> factStatuses,
            Set<String> incomingHeaderNames,
            Map<FieldUseCategory, Set<String>> requestedQueryFieldUses
    ) {
        this(
                tenantId,
                subjectAndEnvironmentFacts,
                factStatuses,
                incomingHeaderNames,
                requestedQueryFieldUses,
                null,
                null
        );
    }

    /**
     * Convenience factory for a caller context with tenant ID and subject/environment facts.
     *
     * @param tenantId authoritative tenant ID
     * @param subjectAndEnvironmentFacts authoritative subject and environment facts
     * @return immutable {@link AuthzCallerContext}
     */
    public static AuthzCallerContext of(String tenantId, Map<String, Object> subjectAndEnvironmentFacts) {
        return new AuthzCallerContext(
                tenantId,
                subjectAndEnvironmentFacts,
                Map.of(),
                Set.of(),
                Map.of(),
                null,
                null
        );
    }

    /**
     * Convenience factory for a caller context with explicit dual-scope custody flags.
     *
     * @param tenantId authoritative tenant ID
     * @param subjectAndEnvironmentFacts authoritative subject and environment facts
     * @param callerMatchesCedente whether caller holds {@code Cedente} custody
     * @param callerMatchesCessionario whether caller holds {@code Cessionário} custody
     * @return immutable {@link AuthzCallerContext}
     */
    public static AuthzCallerContext of(
            String tenantId,
            Map<String, Object> subjectAndEnvironmentFacts,
            boolean callerMatchesCedente,
            boolean callerMatchesCessionario
    ) {
        return new AuthzCallerContext(
                tenantId,
                subjectAndEnvironmentFacts,
                Map.of(),
                Set.of(),
                Map.of(),
                callerMatchesCedente,
                callerMatchesCessionario
        );
    }

    /**
     * Returns a copy of this context with explicit {@code Cedente} and {@code Cessionário} custody flags.
     *
     * @param matchesCedente whether caller holds {@code Cedente} custody
     * @param matchesCessionario whether caller holds {@code Cessionário} custody
     * @return updated immutable {@link AuthzCallerContext}
     */
    public AuthzCallerContext withDualScopeCustody(boolean matchesCedente, boolean matchesCessionario) {
        return new AuthzCallerContext(
                tenantId,
                subjectAndEnvironmentFacts,
                factStatuses,
                incomingHeaderNames,
                requestedQueryFieldUses,
                matchesCedente,
                matchesCessionario
        );
    }

    /**
     * Returns a copy of this context with the given incoming HTTP header names.
     *
     * @param headerNames incoming HTTP header names
     * @return updated immutable {@link AuthzCallerContext}
     */
    public AuthzCallerContext withIncomingHeaderNames(Set<String> headerNames) {
        return new AuthzCallerContext(
                tenantId,
                subjectAndEnvironmentFacts,
                factStatuses,
                headerNames,
                requestedQueryFieldUses,
                callerMatchesCedente,
                callerMatchesCessionario
        );
    }
}
