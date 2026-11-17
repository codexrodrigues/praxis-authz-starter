package org.praxisplatform.authz.host.metadata;

import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.praxisplatform.uischema.service.base.ResourceFilterAccessScope;

/**
 * Resolves row-level tenant and multi-organization hard-scope boundaries for governed resources
 * ({@code CC01}, {@code P05}, {@code P06}, {@code P14}).
 *
 * <p>Implementations translate the authoritative {@link AuthzCallerContext} and resource scope
 * metadata into fail-closed JPA Criteria scopes, JPQL predicates/parameters, entity access checks,
 * and write-target scope invariants without ever trusting client filter payloads.</p>
 */
public interface HardScopeResolver {

    /** Effective hard-scope resolution mode derived for a request. */
    enum HardScopeMode {
        /** Scope binds to one coerced tenant/organization discriminator ({@code field = value}). */
        SINGLE_VALUE,
        /** Scope binds to two or more authorized organization units ({@code field IN values}). */
        MULTI_ORGANIZATION,
        /** Explicitly admitted authenticated shared catalog without per-tenant row partitioning. */
        SHARED_UNRESTRICTED,
        /** Fail-closed denial ({@code 1 = 0} / empty result) when scope is absent or empty. */
        DENIED
    }

    /**
     * Immutable hard-scope selection resolved for a single request/resource pair.
     *
     * @param mode resolved hard-scope mode
     * @param scopeFieldName entity field path anchored by hard-scope
     * @param singleValue coerced discriminator value when {@link HardScopeMode#SINGLE_VALUE}
     * @param multiValues coerced discriminator values when {@link HardScopeMode#MULTI_ORGANIZATION}
     * @param allowNullGlobal whether {@code null} scope values represent shared global rows
     * @param readOnlyConsolidation whether the active multi-org/consolidation view is read-only
     */
    record HardScopeSelection(
            HardScopeMode mode,
            String scopeFieldName,
            Object singleValue,
            Set<Object> multiValues,
            boolean allowNullGlobal,
            boolean readOnlyConsolidation
    ) {
        public HardScopeSelection {
            Objects.requireNonNull(mode, "mode is required");
            multiValues = multiValues == null || multiValues.isEmpty()
                    ? Set.of()
                    : java.util.Collections.unmodifiableSet(new java.util.LinkedHashSet<>(multiValues));
        }

        public static HardScopeSelection single(
                String scopeFieldName,
                Object value,
                boolean allowNullGlobal,
                boolean readOnlyConsolidation
        ) {
            return new HardScopeSelection(
                    HardScopeMode.SINGLE_VALUE,
                    scopeFieldName,
                    Objects.requireNonNull(value, "value is required"),
                    Set.of(value),
                    allowNullGlobal,
                    readOnlyConsolidation
            );
        }

        public static HardScopeSelection multiOrganization(
                String scopeFieldName,
                Set<Object> values,
                boolean allowNullGlobal,
                boolean readOnlyConsolidation
        ) {
            Objects.requireNonNull(values, "values is required");
            if (values.isEmpty()) {
                return denied(scopeFieldName, readOnlyConsolidation);
            }
            if (values.size() == 1) {
                return single(scopeFieldName, values.iterator().next(), allowNullGlobal, readOnlyConsolidation);
            }
            return new HardScopeSelection(
                    HardScopeMode.MULTI_ORGANIZATION,
                    scopeFieldName,
                    null,
                    values,
                    allowNullGlobal,
                    readOnlyConsolidation
            );
        }

        public static HardScopeSelection sharedUnrestricted(String scopeFieldName, boolean readOnlyConsolidation) {
            return new HardScopeSelection(
                    HardScopeMode.SHARED_UNRESTRICTED,
                    scopeFieldName,
                    null,
                    Set.of(),
                    true,
                    readOnlyConsolidation
            );
        }

        public static HardScopeSelection denied(String scopeFieldName, boolean readOnlyConsolidation) {
            return new HardScopeSelection(
                    HardScopeMode.DENIED,
                    scopeFieldName,
                    null,
                    Set.of(),
                    false,
                    readOnlyConsolidation
            );
        }

        public boolean isMultiOrganization() {
            return mode == HardScopeMode.MULTI_ORGANIZATION;
        }

        public boolean isSharedUnrestricted() {
            return mode == HardScopeMode.SHARED_UNRESTRICTED;
        }

        public boolean isDenied() {
            return mode == HardScopeMode.DENIED;
        }
    }

    /** Resolves the effective hard-scope selection for {@code spec} and {@code callerContext}. */
    <E> HardScopeSelection resolveSelection(
            AuthzResourceGovernanceSpec<E> spec,
            AuthzCallerContext callerContext
    );

    /** Builds the JPA Criteria {@link ResourceFilterAccessScope} enforcing the resolved hard-scope. */
    <E> ResourceFilterAccessScope<E> buildCriteriaScope(
            AuthzResourceGovernanceSpec<E> spec,
            AuthzCallerContext callerContext
    );

    /** Builds the JPQL predicate expression enforcing the resolved hard-scope. */
    <E> String buildJpqlPredicate(
            AuthzResourceGovernanceSpec<E> spec,
            AuthzCallerContext callerContext
    );

    /** Builds the JPQL named parameter map matching {@link #buildJpqlPredicate}. */
    <E> Map<String, Object> buildJpqlParams(
            AuthzResourceGovernanceSpec<E> spec,
            AuthzCallerContext callerContext
    );

    /** Verifies fail-closed row-level hard-scope access against an entity instance. */
    <E> void verifyEntityAccess(
            AuthzResourceGovernanceSpec<E> spec,
            E entity,
            AuthzCallerContext callerContext
    );

    /**
     * Verifies write-target organizational invariants before mutation persistence
     * (rejects read-only consolidation scopes, missing target organization under multi-org scope,
     * out-of-scope target organizations, and unauthorized immutable anchor moves).
     */
    <E> void verifyWritableTarget(
            AuthzResourceGovernanceSpec<E> spec,
            E candidate,
            E previous,
            AuthzCallerContext callerContext
    );
}
