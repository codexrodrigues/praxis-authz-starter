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
        Boolean callerMatchesCessionario,
        Map<String, String> incomingHeaders
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
        if (incomingHeaders == null || incomingHeaders.isEmpty()) {
            incomingHeaders = Map.of();
        } else {
            Map<String, String> sanitizedHeaders = new LinkedHashMap<>();
            for (Map.Entry<String, String> entry : incomingHeaders.entrySet()) {
                if (entry.getKey() != null && entry.getValue() != null) {
                    sanitizedHeaders.put(entry.getKey(), entry.getValue());
                }
            }
            incomingHeaders = java.util.Collections.unmodifiableMap(sanitizedHeaders);
        }
    }

    /**
     * Backward-compatible 7-argument constructor without explicit incoming header values.
     */
    public AuthzCallerContext(
            String tenantId,
            Map<String, Object> subjectAndEnvironmentFacts,
            Map<String, FactResolutionStatus> factStatuses,
            Set<String> incomingHeaderNames,
            Map<FieldUseCategory, Set<String>> requestedQueryFieldUses,
            Boolean callerMatchesCedente,
            Boolean callerMatchesCessionario
    ) {
        this(
                tenantId,
                subjectAndEnvironmentFacts,
                factStatuses,
                incomingHeaderNames,
                requestedQueryFieldUses,
                callerMatchesCedente,
                callerMatchesCessionario,
                Map.of()
        );
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
                matchesDestination,
                incomingHeaders
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
                callerMatchesCessionario,
                incomingHeaders
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
                callerMatchesCessionario,
                incomingHeaders
        );
    }

    /**
     * Returns a copy of this context with the validated incoming HTTP headers and header names.
     *
     * @param rawHeaders incoming HTTP request headers
     * @return updated immutable {@link AuthzCallerContext}
     */
    public AuthzCallerContext withIncomingHeaders(Map<String, String> rawHeaders) {
        Map<String, String> cleanHeaders = rawHeaders == null ? Map.of() : rawHeaders;
        Set<String> effectiveNames = !incomingHeaderNames.isEmpty() || cleanHeaders.isEmpty()
                ? incomingHeaderNames
                : cleanHeaders.keySet();
        return new AuthzCallerContext(
                tenantId,
                subjectAndEnvironmentFacts,
                factStatuses,
                effectiveNames,
                requestedQueryFieldUses,
                callerMatchesCedente,
                callerMatchesCessionario,
                cleanHeaders
        );
    }

    /**
     * Builds the header map for {@link org.praxisplatform.authz.enforcement.context.UntrustedRequestHeaderGuard},
     * using real incoming header values when available and falling back to synthetic probes only for
     * header names that have no captured raw value.
     */
    public Map<String, String> effectiveHeaderProbeMap() {
        return buildHeaderProbeMap(incomingHeaderNames, incomingHeaders);
    }

    /**
     * Builds an anti-spoofing verification header map combining captured header values with synthetic
     * probes for header names lacking captured values.
     */
    public static Map<String, String> buildHeaderProbeMap(
            Set<String> headerNames,
            Map<String, String> rawHeaders
    ) {
        boolean noNames = headerNames == null || headerNames.isEmpty();
        boolean noValues = rawHeaders == null || rawHeaders.isEmpty();
        if (noNames && noValues) {
            return Map.of();
        }
        Map<String, String> probe = new LinkedHashMap<>();
        java.util.Set<String> coveredLower = new java.util.LinkedHashSet<>();
        if (!noValues) {
            for (Map.Entry<String, String> entry : rawHeaders.entrySet()) {
                if (entry.getKey() != null && !entry.getKey().isBlank() && entry.getValue() != null) {
                    probe.put(entry.getKey(), entry.getValue());
                    coveredLower.add(entry.getKey().trim().toLowerCase(java.util.Locale.ROOT));
                }
            }
        }
        if (!noNames) {
            for (String h : headerNames) {
                if (h != null && !h.isBlank()
                        && !coveredLower.contains(h.trim().toLowerCase(java.util.Locale.ROOT))) {
                    probe.put(h, "__untrusted_client_header_probe__");
                }
            }
        }
        return java.util.Collections.unmodifiableMap(probe);
    }
}
