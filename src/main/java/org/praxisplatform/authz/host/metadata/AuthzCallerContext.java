package org.praxisplatform.authz.host.metadata;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.praxisplatform.authz.contracts.context.FactResolutionStatus;
import org.praxisplatform.authz.contracts.decisionpoint.FieldUseCategory;

/**
 * Immutable per-request caller context consumed by {@link AbstractAuthzGovernedReadOnlyResourceService},
 * {@link AbstractAuthzGovernedResourceService}, {@link AuthzResourceGovernanceInterceptor}, and
 * {@link AuthzResourceOperationAvailabilityProvider}
 * ({@code Fases P10.8..P10.9}, {@code CC01}, {@code CC02}, {@code P01}, {@code P02}, {@code P03}).
 *
 * @param tenantId authoritative tenant identifier for hard-scope isolation
 * @param subjectAndEnvironmentFacts authoritative subject and environment facts
 * @param factStatuses resolution statuses for each fact key (defaults to {@link FactResolutionStatus#PRESENT})
 * @param incomingHeaderNames incoming HTTP header names inspected for anti-spoofing guards
 * @param requestedQueryFieldUses requested query field uses ({@code FILTER}, {@code SORT}, {@code GROUP})
 * @param callerMatchesCedente optional explicit origin custody flag (when {@code null}, derived by {@link AuthzResourceGovernanceSpec})
 * @param callerMatchesCessionario optional explicit destination custody flag (when {@code null}, derived by {@link AuthzResourceGovernanceSpec})
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

    /** Canonical subject fact key carrying multi-organization hard-scope identifiers. */
    public static final String FACT_AUTHORIZED_ORGANIZATION_IDS = "subject.authorizedOrganizationIds";

    /** Canonical subject fact key carrying organizational unit grants. */
    public static final String FACT_ORGANIZATION_UNIT_IDS = "subject.organizationUnitIds";

    /** Canonical environment fact key indicating a read-only multi-organization consolidation scope. */
    public static final String FACT_READ_ONLY_CONSOLIDATION_SCOPE = "env.readOnlyConsolidationScope";

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
     * Neutral factory for a caller context with explicit origin and destination dual-scope custody flags.
     *
     * @param tenantId authoritative tenant ID
     * @param subjectAndEnvironmentFacts authoritative subject and environment facts
     * @param callerMatchesOrigin whether caller holds authoritative origin custody
     * @param callerMatchesDestination whether caller holds delegated destination custody
     * @return immutable {@link AuthzCallerContext}
     */
    public static AuthzCallerContext ofOriginAndDestination(
            String tenantId,
            Map<String, Object> subjectAndEnvironmentFacts,
            boolean callerMatchesOrigin,
            boolean callerMatchesDestination
    ) {
        return new AuthzCallerContext(
                tenantId,
                subjectAndEnvironmentFacts,
                Map.of(),
                Set.of(),
                Map.of(),
                callerMatchesOrigin,
                callerMatchesDestination
        );
    }

    /**
     * Legacy convenience factory for dual-scope custody flags; prefer {@link #ofOriginAndDestination}.
     */
    public static AuthzCallerContext of(
            String tenantId,
            Map<String, Object> subjectAndEnvironmentFacts,
            boolean callerMatchesOrigin,
            boolean callerMatchesDestination
    ) {
        return ofOriginAndDestination(
                tenantId,
                subjectAndEnvironmentFacts,
                callerMatchesOrigin,
                callerMatchesDestination
        );
    }

    /** Neutral accessor for whether the caller explicitly holds origin custody. */
    public Boolean callerMatchesOrigin() {
        return callerMatchesCedente;
    }

    /** Neutral accessor for whether the caller explicitly holds destination custody. */
    public Boolean callerMatchesDestination() {
        return callerMatchesCessionario;
    }

    /**
     * Returns a copy of this context with explicit origin and destination custody flags.
     *
     * @param matchesOrigin whether caller holds origin custody
     * @param matchesDestination whether caller holds destination custody
     * @return updated immutable {@link AuthzCallerContext}
     */
    public AuthzCallerContext withDualScopeCustody(boolean matchesOrigin, boolean matchesDestination) {
        return new AuthzCallerContext(
                tenantId,
                subjectAndEnvironmentFacts,
                factStatuses,
                incomingHeaderNames,
                requestedQueryFieldUses,
                matchesOrigin,
                matchesDestination
        );
    }

    /**
     * Returns a copy of this context populated with multi-organization hard-scope grants
     * ({@link #FACT_AUTHORIZED_ORGANIZATION_IDS}).
     *
     * @param organizationIds authorized organization IDs
     * @return updated immutable {@link AuthzCallerContext}
     */
    public AuthzCallerContext withAuthorizedOrganizations(Collection<?> organizationIds) {
        Map<String, Object> mergedFacts = new LinkedHashMap<>(subjectAndEnvironmentFacts);
        Map<String, FactResolutionStatus> mergedStatuses = new LinkedHashMap<>(factStatuses);
        List<?> cleanList = organizationIds == null ? List.of() : List.copyOf(organizationIds);
        mergedFacts.put(FACT_AUTHORIZED_ORGANIZATION_IDS, cleanList);
        mergedStatuses.put(FACT_AUTHORIZED_ORGANIZATION_IDS, FactResolutionStatus.PRESENT);
        return new AuthzCallerContext(
                tenantId,
                mergedFacts,
                mergedStatuses,
                incomingHeaderNames,
                requestedQueryFieldUses,
                callerMatchesCedente,
                callerMatchesCessionario
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
