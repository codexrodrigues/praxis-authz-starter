package org.praxisplatform.authz.host.metadata;

import jakarta.persistence.criteria.From;
import jakarta.persistence.criteria.JoinType;
import jakarta.persistence.criteria.Path;
import jakarta.persistence.criteria.Predicate;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.praxisplatform.authz.contracts.annotation.AuthzTenantScopeMode;
import org.praxisplatform.uischema.service.base.ResourceFilterAccessScope;

/**
 * Default {@link HardScopeResolver} supporting single-tenant isolation, multi-organization scopes
 * ({@code field IN :__praxis_hard_tenant_ids}), read-only consolidation scope write guards, and
 * authenticated shared catalogs ({@code CC01}, {@code P05}, {@code P06}, {@code P14}).
 *
 * <p>Resolution order for authorized organizational scope values:</p>
 * <ol>
 *   <li>When {@link AuthzResourceGovernanceSpec#tenantScopeMode()} is
 *       {@link AuthzTenantScopeMode#AUTHENTICATED_SHARED}, allows authenticated callers without
 *       row-level tenant filtering (fail-closed if caller context or principal is absent);</li>
 *   <li>Inspects {@link AuthzResourceGovernanceSpec#hardScopeSubjectFactKey()} if explicitly
 *       configured, or {@link AuthzCallerContext#FACT_AUTHORIZED_ORGANIZATION_IDS};</li>
 *   <li>When a collection of authorized units is present and non-empty, resolves either
 *       {@link HardScopeMode#SINGLE_VALUE} (1 unit) or {@link HardScopeMode#MULTI_ORGANIZATION}
 *       (&gt;1 units); an explicitly present empty collection fails closed as
 *       {@link HardScopeMode#DENIED};</li>
 *   <li>Otherwise falls back to {@link AuthzCallerContext#tenantId()} when present and coercible
 *       to {@link AuthzResourceGovernanceSpec#tenantJavaType()}.</li>
 * </ol>
 */
public final class MultiOrganizationHardScopeResolver implements HardScopeResolver {

    /** Canonical JPQL parameter name used when resolving multi-organization scopes ({@code IN}). */
    public static final String HARD_TENANT_IDS_PARAM = "__praxis_hard_tenant_ids";

    private final String preferredSubjectOrganizationFactKey;
    private final boolean allowGlobalNullScopeDefault;

    /** Creates a resolver using default authorized-organization fact discovery and fail-closed nulls. */
    public MultiOrganizationHardScopeResolver() {
        this(AuthzCallerContext.FACT_AUTHORIZED_ORGANIZATION_IDS, false);
    }

    /**
     * Creates a resolver with a custom default subject organization fact key and global-null flag.
     *
     * @param preferredSubjectOrganizationFactKey preferred subject fact key (e.g.
     *     {@code "subject.authorizedOrganizationIds"})
     * @param allowGlobalNullScopeDefault whether {@code null} entity scope values are treated as global
     */
    public MultiOrganizationHardScopeResolver(
            String preferredSubjectOrganizationFactKey,
            boolean allowGlobalNullScopeDefault
    ) {
        this.preferredSubjectOrganizationFactKey = preferredSubjectOrganizationFactKey != null
                && !preferredSubjectOrganizationFactKey.isBlank()
                ? preferredSubjectOrganizationFactKey.trim()
                : AuthzCallerContext.FACT_AUTHORIZED_ORGANIZATION_IDS;
        this.allowGlobalNullScopeDefault = allowGlobalNullScopeDefault;
    }

    @Override
    public <E> HardScopeSelection resolveSelection(
            AuthzResourceGovernanceSpec<E> spec,
            AuthzCallerContext callerContext
    ) {
        Objects.requireNonNull(spec, "spec is required");
        if (callerContext == null) {
            return HardScopeSelection.denied(spec.tenantFieldName(), false);
        }

        boolean readOnlyConsolidation = isReadOnlyConsolidation(callerContext);
        boolean allowNullGlobal = allowGlobalNullScopeDefault || spec.allowGlobalNullScope();

        if (spec.tenantScopeMode() == AuthzTenantScopeMode.AUTHENTICATED_SHARED) {
            Object principal = callerContext.subjectAndEnvironmentFacts().get("subject.principalId");
            if (principal != null && principal.toString().isBlank()) {
                return HardScopeSelection.denied(spec.tenantFieldName(), readOnlyConsolidation);
            }
            return HardScopeSelection.sharedUnrestricted(spec.tenantFieldName(), readOnlyConsolidation);
        }

        String explicitFactKey = spec.hardScopeSubjectFactKey();
        if (explicitFactKey != null && !explicitFactKey.isBlank()) {
            return resolveFromSubjectFactOrFallback(
                    spec,
                    callerContext,
                    explicitFactKey.trim(),
                    true,
                    allowNullGlobal,
                    readOnlyConsolidation
            );
        }

        if (spec.tenantScopeMode() == AuthzTenantScopeMode.ORGANIZATIONAL_UNIT
                && callerContext.subjectAndEnvironmentFacts().containsKey(preferredSubjectOrganizationFactKey)) {
            return resolveFromSubjectFactOrFallback(
                    spec,
                    callerContext,
                    preferredSubjectOrganizationFactKey,
                    false,
                    allowNullGlobal,
                    readOnlyConsolidation
            );
        }

        if (spec.tenantScopeMode() == AuthzTenantScopeMode.ORGANIZATIONAL_UNIT
                && callerContext.subjectAndEnvironmentFacts().containsKey(AuthzCallerContext.FACT_AUTHORIZED_ORGANIZATION_IDS)) {
            return resolveFromSubjectFactOrFallback(
                    spec,
                    callerContext,
                    AuthzCallerContext.FACT_AUTHORIZED_ORGANIZATION_IDS,
                    false,
                    allowNullGlobal,
                    readOnlyConsolidation
            );
        }

        String tenantId = callerContext.tenantId();
        if (tenantId == null || tenantId.isBlank()) {
            return HardScopeSelection.denied(spec.tenantFieldName(), readOnlyConsolidation);
        }
        Object coerced = AuthzResourceGovernanceSpec.coerceScopeValue(spec.tenantJavaType(), tenantId);
        return HardScopeSelection.single(spec.tenantFieldName(), coerced, allowNullGlobal, readOnlyConsolidation);
    }

    @Override
    public <E> ResourceFilterAccessScope<E> buildCriteriaScope(
            AuthzResourceGovernanceSpec<E> spec,
            AuthzCallerContext callerContext
    ) {
        Objects.requireNonNull(spec, "spec is required");
        HardScopeSelection selection = resolveSelection(spec, callerContext);
        return switch (selection.mode()) {
            case SHARED_UNRESTRICTED -> ResourceFilterAccessScope.unrestricted();
            case DENIED -> ResourceFilterAccessScope.denied();
            case SINGLE_VALUE -> ResourceFilterAccessScope.restricted((root, query, cb) -> {
                Path<?> path = resolveCriteriaPath(root, spec.tenantFieldName());
                Class<?> expectedType = path != null && path.getJavaType() != null
                        ? path.getJavaType()
                        : spec.tenantJavaType();
                Object value = coerceForCriteria(expectedType, selection.singleValue());
                Predicate eq = cb.equal(path, value);
                return selection.allowNullGlobal() ? cb.or(cb.isNull(path), eq) : eq;
            });
            case MULTI_ORGANIZATION -> ResourceFilterAccessScope.restricted((root, query, cb) -> {
                Path<?> path = resolveCriteriaPath(root, spec.tenantFieldName());
                Class<?> expectedType = path != null && path.getJavaType() != null
                        ? path.getJavaType()
                        : spec.tenantJavaType();
                Set<Object> coerced = new LinkedHashSet<>();
                for (Object item : selection.multiValues()) {
                    coerced.add(coerceForCriteria(expectedType, item));
                }
                Predicate inClause = path.in(coerced);
                return selection.allowNullGlobal() ? cb.or(cb.isNull(path), inClause) : inClause;
            });
        };
    }

    @Override
    public <E> String buildJpqlPredicate(
            AuthzResourceGovernanceSpec<E> spec,
            AuthzCallerContext callerContext
    ) {
        Objects.requireNonNull(spec, "spec is required");
        HardScopeSelection selection = resolveSelection(spec, callerContext);
        return switch (selection.mode()) {
            case SHARED_UNRESTRICTED -> "1 = 1";
            case DENIED -> "1 = 0";
            case SINGLE_VALUE -> selection.allowNullGlobal()
                    ? "(" + spec.tenantJpqlExpression() + " IS NULL OR " + spec.tenantJpqlExpression()
                            + " = :" + AuthzResourceGovernanceSpec.HARD_TENANT_PARAM + ")"
                    : spec.tenantJpqlExpression() + " = :" + AuthzResourceGovernanceSpec.HARD_TENANT_PARAM;
            case MULTI_ORGANIZATION -> selection.allowNullGlobal()
                    ? "(" + spec.tenantJpqlExpression() + " IS NULL OR " + spec.tenantJpqlExpression()
                            + " IN :" + HARD_TENANT_IDS_PARAM + ")"
                    : spec.tenantJpqlExpression() + " IN :" + HARD_TENANT_IDS_PARAM;
        };
    }

    @Override
    public <E> Map<String, Object> buildJpqlParams(
            AuthzResourceGovernanceSpec<E> spec,
            AuthzCallerContext callerContext
    ) {
        Objects.requireNonNull(spec, "spec is required");
        HardScopeSelection selection = resolveSelection(spec, callerContext);
        return switch (selection.mode()) {
            case SHARED_UNRESTRICTED, DENIED -> Map.of();
            case SINGLE_VALUE -> Map.of(AuthzResourceGovernanceSpec.HARD_TENANT_PARAM, selection.singleValue());
            case MULTI_ORGANIZATION -> Map.of(HARD_TENANT_IDS_PARAM, List.copyOf(selection.multiValues()));
        };
    }

    @Override
    public <E> void verifyEntityAccess(
            AuthzResourceGovernanceSpec<E> spec,
            E entity,
            AuthzCallerContext callerContext
    ) {
        Objects.requireNonNull(spec, "spec is required");
        Objects.requireNonNull(entity, "entity is required");
        Objects.requireNonNull(callerContext, "callerContext is required");

        HardScopeSelection selection = resolveSelection(spec, callerContext);
        if (selection.isSharedUnrestricted()) {
            return;
        }
        if (selection.isDenied()) {
            throw new SecurityException("AUTHZ_HARD_SCOPE_TENANT_MISMATCH: Caller has no admitted tenant/organization scope (403)");
        }

        Object rawEntityValue = spec.extractRawScopeValueFromEntity(entity);
        if (rawEntityValue == null) {
            if (selection.allowNullGlobal()) {
                return;
            }
            throw new SecurityException("AUTHZ_HARD_SCOPE_TENANT_MISMATCH: Entity scope value is null (403)");
        }

        if (!matchesAnyAllowedValue(rawEntityValue, selection.multiValues())) {
            throw new SecurityException("AUTHZ_HARD_SCOPE_TENANT_MISMATCH: Entity scope '"
                    + rawEntityValue + "' is outside caller scope " + selection.multiValues() + " (403)");
        }
    }

    @Override
    public <E> void verifyWritableTarget(
            AuthzResourceGovernanceSpec<E> spec,
            E candidate,
            E previous,
            AuthzCallerContext callerContext
    ) {
        Objects.requireNonNull(spec, "spec is required");
        Objects.requireNonNull(candidate, "candidate is required");
        Objects.requireNonNull(callerContext, "callerContext is required");

        HardScopeSelection selection = resolveSelection(spec, callerContext);
        if (selection.readOnlyConsolidation()) {
            throw new SecurityException(
                    "AUTHZ_CONSOLIDATION_READ_ONLY_SCOPE: Mutations are forbidden in a read-only multi-organization consolidation view (403)");
        }
        if (selection.isSharedUnrestricted()) {
            return;
        }
        if (selection.isDenied()) {
            throw new SecurityException("AUTHZ_HARD_SCOPE_TENANT_MISMATCH: Caller has no writable tenant/organization scope (403)");
        }

        Object candidateValue = spec.extractRawScopeValueFromEntity(candidate);
        if (candidateValue == null) {
            if (selection.isMultiOrganization()) {
                throw new SecurityException(
                        "AUTHZ_MULTI_ORG_TARGET_REQUIRED: Explicit target organization (" + spec.tenantFieldName()
                                + ") is required when operating in multi-organization scope (422)");
            }
            if (!selection.allowNullGlobal()) {
                throw new SecurityException(
                        "AUTHZ_HARD_SCOPE_TENANT_MISMATCH: Target scope field '" + spec.tenantFieldName()
                                + "' must not be null (403)");
            }
            return;
        }

        if (!matchesAnyAllowedValue(candidateValue, selection.multiValues())) {
            throw new SecurityException("AUTHZ_HARD_SCOPE_TENANT_MISMATCH: Target organization '"
                    + candidateValue + "' is outside caller scope " + selection.multiValues() + " (403)");
        }

        if (previous != null && spec.hasImmutableTenantAnchor()) {
            Object previousValue = spec.extractRawScopeValueFromEntity(previous);
            if (previousValue != null && !AuthzResourceGovernanceSpec.scopeValuesEqual(previousValue, candidateValue)) {
                throw new SecurityException("AUTHZ_SCOPE_ANCHOR_IMMUTABLE: Cannot move persisted record scope '"
                        + spec.tenantFieldName() + "' from '" + previousValue + "' to '" + candidateValue + "' (422)");
            }
        }
    }

    private <E> HardScopeSelection resolveFromSubjectFactOrFallback(
            AuthzResourceGovernanceSpec<E> spec,
            AuthzCallerContext callerContext,
            String factKey,
            boolean strictWhenExplicit,
            boolean allowNullGlobal,
            boolean readOnlyConsolidation
    ) {
        Map<String, Object> facts = callerContext.subjectAndEnvironmentFacts();
        if (facts.containsKey(factKey)) {
            Object rawFact = facts.get(factKey);
            if (rawFact == null) {
                return HardScopeSelection.denied(spec.tenantFieldName(), readOnlyConsolidation);
            }
            if (rawFact instanceof Collection<?> col) {
                if (col.isEmpty()) {
                    return HardScopeSelection.denied(spec.tenantFieldName(), readOnlyConsolidation);
                }
                Set<Object> coerced = new LinkedHashSet<>();
                for (Object item : col) {
                    if (item != null) {
                        coerced.add(AuthzResourceGovernanceSpec.coerceScopeValue(
                                spec.tenantJavaType(), String.valueOf(item)));
                    }
                }
                if (coerced.isEmpty()) {
                    return HardScopeSelection.denied(spec.tenantFieldName(), readOnlyConsolidation);
                }
                return HardScopeSelection.multiOrganization(
                        spec.tenantFieldName(), coerced, allowNullGlobal, readOnlyConsolidation);
            }
            Object coerced = AuthzResourceGovernanceSpec.coerceScopeValue(
                    spec.tenantJavaType(), String.valueOf(rawFact));
            return HardScopeSelection.single(spec.tenantFieldName(), coerced, allowNullGlobal, readOnlyConsolidation);
        }

        if (strictWhenExplicit && spec.tenantScopeMode() == AuthzTenantScopeMode.ORGANIZATIONAL_UNIT) {
            if (callerContext.tenantId() == null || callerContext.tenantId().isBlank()) {
                return HardScopeSelection.denied(spec.tenantFieldName(), readOnlyConsolidation);
            }
            try {
                Object coercedTenant = AuthzResourceGovernanceSpec.coerceScopeValue(
                        spec.tenantJavaType(), callerContext.tenantId());
                return HardScopeSelection.single(
                        spec.tenantFieldName(), coercedTenant, allowNullGlobal, readOnlyConsolidation);
            } catch (SecurityException ex) {
                return HardScopeSelection.denied(spec.tenantFieldName(), readOnlyConsolidation);
            }
        }

        String tenantId = callerContext.tenantId();
        if (tenantId == null || tenantId.isBlank()) {
            return HardScopeSelection.denied(spec.tenantFieldName(), readOnlyConsolidation);
        }
        Object coerced = AuthzResourceGovernanceSpec.coerceScopeValue(spec.tenantJavaType(), tenantId);
        return HardScopeSelection.single(spec.tenantFieldName(), coerced, allowNullGlobal, readOnlyConsolidation);
    }

    private static boolean isReadOnlyConsolidation(AuthzCallerContext callerContext) {
        Map<String, Object> facts = callerContext.subjectAndEnvironmentFacts();
        return Boolean.TRUE.equals(facts.get(AuthzCallerContext.FACT_READ_ONLY_CONSOLIDATION_SCOPE))
                || Boolean.TRUE.equals(facts.get("subject.readOnlyConsolidationScope"));
    }

    private static boolean matchesAnyAllowedValue(Object entityValue, Set<Object> allowedValues) {
        for (Object allowed : allowedValues) {
            if (AuthzResourceGovernanceSpec.scopeValuesEqual(entityValue, allowed)) {
                return true;
            }
        }
        return false;
    }

    private static Path<?> resolveCriteriaPath(From<?, ?> root, String dotPath) {
        String[] segments = dotPath.split("\\.");
        From<?, ?> current = root;
        for (int i = 0; i < segments.length - 1; i++) {
            current = current.join(segments[i], JoinType.INNER);
        }
        return current.get(segments[segments.length - 1]);
    }

    private static Object coerceForCriteria(Class<?> expectedType, Object value) {
        if (value == null) {
            return null;
        }
        if (expectedType == null || expectedType.isInstance(value)) {
            return value;
        }
        return AuthzResourceGovernanceSpec.coerceScopeValue(expectedType, String.valueOf(value));
    }
}
