package org.praxisplatform.authz.host.metadata;

import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.Expression;
import jakarta.persistence.criteria.From;
import jakarta.persistence.criteria.Join;
import jakarta.persistence.criteria.JoinType;
import jakarta.persistence.criteria.Path;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import jakarta.persistence.criteria.Subquery;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import org.praxisplatform.authz.contracts.datascope.ComparisonPredicateIr;
import org.praxisplatform.authz.contracts.datascope.DataScopeOutcome;
import org.praxisplatform.authz.contracts.datascope.DataScopePlan;
import org.praxisplatform.authz.contracts.datascope.FieldRefOperandIr;
import org.praxisplatform.authz.contracts.datascope.LiteralListOperandIr;
import org.praxisplatform.authz.contracts.datascope.LiteralOperandIr;
import org.praxisplatform.authz.contracts.datascope.LogicalPredicateIr;
import org.praxisplatform.authz.contracts.datascope.NullabilityPredicateIr;
import org.praxisplatform.authz.contracts.datascope.QueryableFieldDescriptor;
import org.praxisplatform.authz.contracts.datascope.QueryableResourceProjection;
import org.praxisplatform.authz.contracts.datascope.SearchPredicateIr;
import org.praxisplatform.authz.contracts.datascope.SearchPredicateOperator;
import org.praxisplatform.authz.enforcement.jpa.QueryAdapterFieldBinding;
import org.praxisplatform.authz.enforcement.jpa.RelationTraversalStrategy;
import org.praxisplatform.uischema.service.base.ResourceFilterAccessScope;
import org.springframework.data.jpa.domain.Specification;

/**
 * Translates a canonical {@link DataScopePlan} directly into a Spring Data JPA
 * {@link Specification} and composes it with the host's mandatory {@link ResourceFilterAccessScope}
 * ({@code CC03}, {@code DSP-*}, {@code P05}, {@code P06}, {@code P07}).
 *
 * <p>Enforces Kleene 3-valued logic ({@code P06}) by adding explicit {@code IS NOT NULL} guards
 * when negating comparisons on nullable columns, and supports correlated {@code EXISTS} subqueries
 * ({@code P07}) for {@code 1:N} associations via {@link RelationTraversalStrategy#CORRELATED_EXISTS_SUBQUERY}.</p>
 */
public final class JpaCriteriaDataScopeTranslator {

    private final QueryableResourceProjection projection;
    private final Map<String, QueryAdapterFieldBinding> bindingsByFieldPath;

    /**
     * Creates a JPA Criteria translator for a specific {@link QueryableResourceProjection}.
     *
     * @param projection canonical query projection descriptor
     * @param fieldBindings physical JPA field bindings for the entity
     */
    public JpaCriteriaDataScopeTranslator(
            QueryableResourceProjection projection,
            Collection<QueryAdapterFieldBinding> fieldBindings
    ) {
        this.projection = Objects.requireNonNull(projection, "projection is required");
        Objects.requireNonNull(fieldBindings, "fieldBindings is required");
        Map<String, QueryAdapterFieldBinding> map = new LinkedHashMap<>();
        for (QueryAdapterFieldBinding b : fieldBindings) {
            if (!projection.resourceKey().equals(b.resourceKey())) {
                throw new IllegalArgumentException(
                        "Field binding resourceKey '" + b.resourceKey()
                                + "' does not match projection resourceKey '" + projection.resourceKey() + "'");
            }
            map.put(b.fieldPath(), b);
        }
        this.bindingsByFieldPath = Map.copyOf(map);
    }

    /**
     * Compiles a {@link DataScopePlan} and composes it fail-closed with the host's mandatory
     * {@code hardScope} ({@code P05}, {@code P06}, {@code P07}).
     *
     * @param plan evaluated {@link DataScopePlan}
     * @param hardScope mandatory host tenant/organization {@link ResourceFilterAccessScope}
     * @param <E> JPA entity type
     * @return composed {@link ResourceFilterAccessScope}
     */
    public <E> ResourceFilterAccessScope<E> toResourceFilterAccessScope(
            DataScopePlan plan,
            ResourceFilterAccessScope<E> hardScope
    ) {
        Objects.requireNonNull(plan, "plan is required");
        ResourceFilterAccessScope<E> effectiveHardScope = hardScope == null
                ? ResourceFilterAccessScope.unrestricted()
                : hardScope;
        if (effectiveHardScope.mode() == ResourceFilterAccessScope.Mode.DENIED) {
            return ResourceFilterAccessScope.denied();
        }
        if (!projection.projectionId().equals(plan.queryProjectionRef())
                || !projection.projectionDigest().equals(plan.queryProjectionDigest())) {
            throw new IllegalArgumentException(
                    "DataScopePlan projection identity/digest mismatch against registered QueryableResourceProjection");
        }

        if (plan.scopeOutcome() == DataScopeOutcome.NONE) {
            return ResourceFilterAccessScope.denied();
        }
        if (plan.scopeOutcome() == DataScopeOutcome.ALL) {
            return effectiveHardScope;
        }

        SearchPredicateIr rootPredicate = Objects.requireNonNull(
                plan.predicateIr(), "FILTER outcome requires non-null predicateIr");
        projection.validatePredicateIr(rootPredicate);
        Specification<E> policySpec = (root, query, cb) -> translateNode(rootPredicate, false, root, query, cb);
        Specification<E> composedSpec = effectiveHardScope.specification().and(policySpec);
        return ResourceFilterAccessScope.restricted(composedSpec);
    }

    private <E> Predicate translateNode(
            SearchPredicateIr node,
            boolean negated,
            Root<E> root,
            jakarta.persistence.criteria.CriteriaQuery<?> query,
            CriteriaBuilder cb
    ) {
        if (node instanceof LogicalPredicateIr logical) {
            return switch (logical.operator()) {
                case NOT -> translateNode(logical.operands().get(0), !negated, root, query, cb);
                case AND -> {
                    List<Predicate> parts = new ArrayList<>(logical.operands().size());
                    for (SearchPredicateIr child : logical.operands()) {
                        parts.add(translateNode(child, negated, root, query, cb));
                    }
                    yield negated
                            ? cb.or(parts.toArray(Predicate[]::new))
                            : cb.and(parts.toArray(Predicate[]::new));
                }
                case OR -> {
                    List<Predicate> parts = new ArrayList<>(logical.operands().size());
                    for (SearchPredicateIr child : logical.operands()) {
                        parts.add(translateNode(child, negated, root, query, cb));
                    }
                    yield negated
                            ? cb.and(parts.toArray(Predicate[]::new))
                            : cb.or(parts.toArray(Predicate[]::new));
                }
                default -> throw new IllegalArgumentException("Unexpected logical operator: " + logical.operator());
            };
        }

        if (node instanceof NullabilityPredicateIr nullPred) {
            QueryAdapterFieldBinding binding = requireBinding(nullPred.fieldPath());
            if (binding.traversalStrategy() == RelationTraversalStrategy.CORRELATED_EXISTS_SUBQUERY) {
                boolean innerIsNull = (nullPred.operator() == SearchPredicateOperator.IS_NULL);
                return buildCorrelatedCollectionSubquery(binding, root, query, cb,
                        targetPath -> innerIsNull ? cb.isNull(targetPath) : cb.isNotNull(targetPath), negated);
            }
            boolean checkIsNull = (nullPred.operator() == SearchPredicateOperator.IS_NULL) ^ negated;
            Path<?> path = resolveScalarPath(root, binding.nativeJpaPath());
            return checkIsNull ? cb.isNull(path) : cb.isNotNull(path);
        }

        if (node instanceof ComparisonPredicateIr comp) {
            return translateComparison(comp, negated, root, query, cb);
        }

        throw new IllegalArgumentException("Unsupported SearchPredicateIr: " + node);
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private <E> Predicate translateComparison(
            ComparisonPredicateIr comp,
            boolean negated,
            Root<E> root,
            jakarta.persistence.criteria.CriteriaQuery<?> query,
            CriteriaBuilder cb
    ) {
        QueryAdapterFieldBinding binding = requireBinding(comp.fieldPath());

        if (binding.traversalStrategy() == RelationTraversalStrategy.CORRELATED_EXISTS_SUBQUERY) {
            return buildCorrelatedCollectionSubquery(binding, root, query, cb,
                    targetPath -> buildScalarComparisonPredicate(comp, false, binding.nullableColumn(), root, targetPath, cb),
                    negated);
        }

        Path<?> rawPath = resolveScalarPath(root, binding.nativeJpaPath());
        return buildScalarComparisonPredicate(comp, negated, binding.nullableColumn(), root, rawPath, cb);
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private Predicate buildScalarComparisonPredicate(
            ComparisonPredicateIr comp,
            boolean negated,
            boolean lhsNullableColumn,
            Root<?> root,
            Path<?> rawPath,
            CriteriaBuilder cb
    ) {
        Expression<String> lhsStringExpr = comp.caseInsensitive()
                ? cb.lower((Expression<String>) rawPath)
                : (Expression<String>) rawPath;

        Path<?> rhsFieldPath = null;
        boolean rhsNullableColumn = false;
        if (comp.rightOperand() instanceof FieldRefOperandIr fieldRef) {
            QueryAdapterFieldBinding rhsBinding = requireBinding(fieldRef.targetFieldPath());
            rhsFieldPath = resolveScalarPath(root, rhsBinding.nativeJpaPath());
            rhsNullableColumn = rhsBinding.nullableColumn();
        }

        Expression<?> effectiveLhs = comp.caseInsensitive() ? lhsStringExpr : rawPath;
        Expression<?> effectiveRhsField = (rhsFieldPath != null && comp.caseInsensitive())
                ? cb.lower((Expression<String>) rhsFieldPath)
                : rhsFieldPath;

        Predicate baseComparison = switch (comp.operator()) {
            case EQ -> {
                if (effectiveRhsField != null) {
                    yield negated ? cb.notEqual(effectiveLhs, effectiveRhsField) : cb.equal(effectiveLhs, effectiveRhsField);
                }
                Object val = normalizeScalarValue(((LiteralOperandIr) comp.rightOperand()).value(), comp.caseInsensitive());
                yield negated ? cb.notEqual(effectiveLhs, val) : cb.equal(effectiveLhs, val);
            }
            case NE -> {
                if (effectiveRhsField != null) {
                    yield negated ? cb.equal(effectiveLhs, effectiveRhsField) : cb.notEqual(effectiveLhs, effectiveRhsField);
                }
                Object val = normalizeScalarValue(((LiteralOperandIr) comp.rightOperand()).value(), comp.caseInsensitive());
                yield negated ? cb.equal(effectiveLhs, val) : cb.notEqual(effectiveLhs, val);
            }
            case IN -> {
                List<Object> vals = ((LiteralListOperandIr) comp.rightOperand()).values().stream()
                        .map(v -> normalizeScalarValue(v, comp.caseInsensitive()))
                        .toList();
                CriteriaBuilder.In<Object> inClause = cb.in((Expression<Object>) effectiveLhs);
                for (Object v : vals) {
                    inClause.value(v);
                }
                yield negated ? cb.not(inClause) : inClause;
            }
            case NIN -> {
                List<Object> vals = ((LiteralListOperandIr) comp.rightOperand()).values().stream()
                        .map(v -> normalizeScalarValue(v, comp.caseInsensitive()))
                        .toList();
                CriteriaBuilder.In<Object> inClause = cb.in((Expression<Object>) effectiveLhs);
                for (Object v : vals) {
                    inClause.value(v);
                }
                yield negated ? inClause : cb.not(inClause);
            }
            case GT -> {
                if (effectiveRhsField != null) {
                    yield negated
                            ? cb.lessThanOrEqualTo((Expression<Comparable>) effectiveLhs, (Expression<Comparable>) effectiveRhsField)
                            : cb.greaterThan((Expression<Comparable>) effectiveLhs, (Expression<Comparable>) effectiveRhsField);
                }
                Comparable val = (Comparable) normalizeScalarValue(
                        ((LiteralOperandIr) comp.rightOperand()).value(),
                        comp.caseInsensitive()
                );
                yield negated
                        ? cb.lessThanOrEqualTo((Expression<Comparable>) effectiveLhs, val)
                        : cb.greaterThan((Expression<Comparable>) effectiveLhs, val);
            }
            case GTE -> {
                if (effectiveRhsField != null) {
                    yield negated
                            ? cb.lessThan((Expression<Comparable>) effectiveLhs, (Expression<Comparable>) effectiveRhsField)
                            : cb.greaterThanOrEqualTo((Expression<Comparable>) effectiveLhs, (Expression<Comparable>) effectiveRhsField);
                }
                Comparable val = (Comparable) normalizeScalarValue(
                        ((LiteralOperandIr) comp.rightOperand()).value(),
                        comp.caseInsensitive()
                );
                yield negated
                        ? cb.lessThan((Expression<Comparable>) effectiveLhs, val)
                        : cb.greaterThanOrEqualTo((Expression<Comparable>) effectiveLhs, val);
            }
            case LT -> {
                if (effectiveRhsField != null) {
                    yield negated
                            ? cb.greaterThanOrEqualTo((Expression<Comparable>) effectiveLhs, (Expression<Comparable>) effectiveRhsField)
                            : cb.lessThan((Expression<Comparable>) effectiveLhs, (Expression<Comparable>) effectiveRhsField);
                }
                Comparable val = (Comparable) normalizeScalarValue(
                        ((LiteralOperandIr) comp.rightOperand()).value(),
                        comp.caseInsensitive()
                );
                yield negated
                        ? cb.greaterThanOrEqualTo((Expression<Comparable>) effectiveLhs, val)
                        : cb.lessThan((Expression<Comparable>) effectiveLhs, val);
            }
            case LTE -> {
                if (effectiveRhsField != null) {
                    yield negated
                            ? cb.greaterThan((Expression<Comparable>) effectiveLhs, (Expression<Comparable>) effectiveRhsField)
                            : cb.lessThanOrEqualTo((Expression<Comparable>) effectiveLhs, (Expression<Comparable>) effectiveRhsField);
                }
                Comparable val = (Comparable) normalizeScalarValue(
                        ((LiteralOperandIr) comp.rightOperand()).value(),
                        comp.caseInsensitive()
                );
                yield negated
                        ? cb.greaterThan((Expression<Comparable>) effectiveLhs, val)
                        : cb.lessThanOrEqualTo((Expression<Comparable>) effectiveLhs, val);
            }
            case STARTS_WITH -> {
                String prefix = escapeLikeWildcards(String.valueOf(
                        normalizeScalarValue(((LiteralOperandIr) comp.rightOperand()).value(), comp.caseInsensitive())));
                yield negated
                        ? cb.notLike(lhsStringExpr, prefix + "%", '\\')
                        : cb.like(lhsStringExpr, prefix + "%", '\\');
            }
            case ENDS_WITH -> {
                String suffix = escapeLikeWildcards(String.valueOf(
                        normalizeScalarValue(((LiteralOperandIr) comp.rightOperand()).value(), comp.caseInsensitive())));
                yield negated
                        ? cb.notLike(lhsStringExpr, "%" + suffix, '\\')
                        : cb.like(lhsStringExpr, "%" + suffix, '\\');
            }
            case TEXT_CONTAINS -> {
                String sub = escapeLikeWildcards(String.valueOf(
                        normalizeScalarValue(((LiteralOperandIr) comp.rightOperand()).value(), comp.caseInsensitive())));
                yield negated
                        ? cb.notLike(lhsStringExpr, "%" + sub + "%", '\\')
                        : cb.like(lhsStringExpr, "%" + sub + "%", '\\');
            }
            default -> throw new IllegalArgumentException("Unsupported comparison operator: " + comp.operator());
        };

        // DSP-SQL-003 (P08): Kleene 3VL guard on nullable LHS and RHS columns so NULL never evaluates to TRUE under negation or OR
        List<Predicate> guards = new ArrayList<>(3);
        if (lhsNullableColumn) {
            guards.add(cb.isNotNull(rawPath));
        }
        if (rhsNullableColumn && rhsFieldPath != null) {
            guards.add(cb.isNotNull(rhsFieldPath));
        }
        if (guards.isEmpty()) {
            return baseComparison;
        }
        guards.add(baseComparison);
        return cb.and(guards.toArray(Predicate[]::new));
    }

    private <E> Predicate buildCorrelatedCollectionSubquery(
            QueryAdapterFieldBinding binding,
            Root<E> root,
            jakarta.persistence.criteria.CriteriaQuery<?> query,
            CriteriaBuilder cb,
            java.util.function.Function<Path<?>, Predicate> innerPredicateBuilder,
            boolean negateExists
    ) {
        Subquery<Integer> subquery = query.subquery(Integer.class);
        Root<E> correlatedRoot = subquery.correlate(root);
        Path<?> targetPath = resolveCollectionPath(correlatedRoot, binding.nativeJpaPath());
        subquery.select(cb.literal(1)).where(innerPredicateBuilder.apply(targetPath));
        Predicate exists = cb.exists(subquery);
        return negateExists ? cb.not(exists) : exists;
    }

    private static Path<?> resolveScalarPath(Path<?> root, String propertyPath) {
        String cleanPath = propertyPath.startsWith("e.") ? propertyPath.substring(2) : propertyPath;
        String[] segments = cleanPath.split("\\.");
        Path<?> current = root;
        for (int i = 0; i < segments.length; i++) {
            if (i < segments.length - 1 && current instanceof From<?, ?> from) {
                current = reuseOrCreateJoin(from, segments[i], JoinType.LEFT);
            } else {
                current = current.get(segments[i]);
            }
        }
        return current;
    }

    private static Join<?, ?> reuseOrCreateJoin(From<?, ?> from, String attributeName, JoinType joinType) {
        for (Join<?, ?> existingJoin : from.getJoins()) {
            if (attributeName.equals(existingJoin.getAttribute().getName())
                    && existingJoin.getJoinType() == joinType) {
                return existingJoin;
            }
        }
        return from.join(attributeName, joinType);
    }

    private static Path<?> resolveCollectionPath(From<?, ?> correlatedRoot, String propertyPath) {
        String cleanPath = propertyPath.startsWith("e.") ? propertyPath.substring(2) : propertyPath;
        String[] segments = cleanPath.split("\\.");
        From<?, ?> currentFrom = correlatedRoot;
        for (int i = 0; i < segments.length - 1; i++) {
            currentFrom = reuseOrCreateJoin(currentFrom, segments[i], JoinType.INNER);
        }
        return currentFrom.get(segments[segments.length - 1]);
    }

    private static String escapeLikeWildcards(String value) {
        return value
                .replace("\\", "\\\\")
                .replace("%", "\\%")
                .replace("_", "\\_");
    }

    private static Object normalizeScalarValue(Object value, boolean caseInsensitive) {
        if (caseInsensitive && value instanceof String s) {
            return s.toLowerCase(Locale.ROOT);
        }
        return value;
    }

    private QueryAdapterFieldBinding requireBinding(String fieldPath) {
        QueryAdapterFieldBinding binding = bindingsByFieldPath.get(fieldPath);
        if (binding == null) {
            throw new IllegalArgumentException(
                    "No QueryAdapterFieldBinding registered for queryable field '" + fieldPath + "'");
        }
        return binding;
    }
}
