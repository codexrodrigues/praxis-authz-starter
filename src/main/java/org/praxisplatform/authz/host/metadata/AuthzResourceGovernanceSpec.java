package org.praxisplatform.authz.host.metadata;

import jakarta.persistence.Column;
import jakarta.persistence.Embedded;
import jakarta.persistence.Id;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.OneToMany;
import jakarta.persistence.OneToOne;
import jakarta.persistence.Transient;
import jakarta.persistence.Version;
import jakarta.persistence.criteria.From;
import jakarta.persistence.criteria.JoinType;
import jakarta.persistence.criteria.Path;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import java.beans.Introspector;
import java.lang.reflect.AnnotatedElement;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.RecordComponent;
import java.lang.reflect.Type;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.time.Instant;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.function.BiPredicate;
import java.util.function.Function;
import org.praxisplatform.authz.catalog.FieldLineageCatalogEntry;
import org.praxisplatform.authz.contracts.context.ContextEvaluationPhase;
import org.praxisplatform.authz.contracts.context.FactCardinality;
import org.praxisplatform.authz.contracts.context.FactContract;
import org.praxisplatform.authz.contracts.context.FactDescriptor;
import org.praxisplatform.authz.contracts.context.FactPresenceModel;
import org.praxisplatform.authz.contracts.context.FactResolutionStage;
import org.praxisplatform.authz.contracts.context.FactSlotNamespace;
import org.praxisplatform.authz.contracts.context.FactValueType;
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
import org.praxisplatform.authz.contracts.decisionpoint.DecisionKind;
import org.praxisplatform.authz.contracts.decisionpoint.DecisionPointDescriptor;
import org.praxisplatform.authz.contracts.decisionpoint.DecisionPointIdentity;
import org.praxisplatform.authz.contracts.decisionpoint.DecisionResultContractKind;
import org.praxisplatform.authz.contracts.decisionpoint.EnforcementCapability;
import org.praxisplatform.authz.contracts.decisionpoint.EvaluationMode;
import org.praxisplatform.authz.contracts.decisionpoint.FactContractRef;
import org.praxisplatform.authz.contracts.decisionpoint.FieldUseCategory;
import org.praxisplatform.authz.contracts.decisionpoint.QueryableProjectionRef;
import org.praxisplatform.authz.contracts.digest.CanonicalDigestCalculator;
import org.praxisplatform.authz.contracts.digest.DigestDomainKind;
import org.praxisplatform.authz.contracts.policy.DualScopeDelegationSpec;
import org.praxisplatform.authz.enforcement.jpa.JpaDataScopeAdapter;
import org.praxisplatform.authz.enforcement.jpa.QueryAdapterFieldBinding;
import org.praxisplatform.authz.enforcement.jpa.RelationTraversalStrategy;
import org.praxisplatform.authz.enforcement.masking.DtoFieldSchemaMetadata;
import org.praxisplatform.uischema.action.ActionScope;
import org.praxisplatform.uischema.annotation.ApiResource;
import org.praxisplatform.uischema.annotation.UiSurface;
import org.praxisplatform.uischema.annotation.WorkflowAction;
import org.praxisplatform.uischema.capability.ResourceStateSnapshot;
import org.praxisplatform.uischema.filter.annotation.Filterable;
import org.praxisplatform.uischema.service.base.ResourceFilterAccessScope;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

/**
 * Declarative single-source-of-truth specification for a governed resource ({@code Fases P10.8..P10.9},
 * {@code P10.8-R03}, {@code CC03}, {@code CC06}, {@code CC07}, {@code R-07}, {@code R-11},
 * {@code P01..P22}).
 *
 * <p>Eliminates structural drift across JPQL and Criteria query adapters, in-memory entity
 * verification, tenant hard-scope declarations, target fact extraction, dual-scope custody
 * evaluation, and contextual operation availability bindings by deriving:</p>
 * <ul>
 *   <li>Both {@link JpaDataScopeAdapter} and {@link JpaCriteriaDataScopeTranslator} from a single
 *       {@link QueryableResourceProjection} and {@link QueryAdapterFieldBinding} list;</li>
 *   <li>Both {@link ResourceFilterAccessScope} (JPA Criteria) and JPQL hard-scope clause/parameters
 *       from a single {@code tenantFieldName} declaration;</li>
 *   <li>Automatic in-memory evaluation of the active OPA {@link DataScopePlan} ({@link SearchPredicateIr}
 *       AST with Kleene 3-valued {@code NULL} safety and {@code 1:N} collection support) during
 *       {@link #verifyEntityAccessAllowed(Object, AuthzCallerContext, DataScopePlan)};</li>
 *   <li>Automatic target fact extraction ({@link #extractEntityTargetFacts(Object)}), entity state
 *       snapshot construction ({@link #toResourceStateSnapshot(Object)}), and dual-scope custody
 *       evaluation ({@link #isCallerCedente(Object, AuthzCallerContext)} /
 *       {@link #isCallerCessionario(Object, AuthzCallerContext)}) ({@code Fase P10.9}).</li>
 * </ul>
 *
 * @param <E> JPA entity type
 */
public final class AuthzResourceGovernanceSpec<E> {

    /** Canonical parameter name used in generated JPQL hard-scope clauses. */
    public static final String HARD_TENANT_PARAM = "__praxis_hard_tenant_id";

    /** Internal snapshot metadata key storing the entity's tenant identifier. */
    public static final String SNAPSHOT_TENANT_META_KEY = "__authz.tenantId";

    /** Internal snapshot metadata key storing the entity's Cedente custody anchor value. */
    public static final String SNAPSHOT_CEDENTE_VALUE_META_KEY = "__authz.cedenteValue";

    /** Internal snapshot metadata key storing the entity's Cessionário custody anchor value. */
    public static final String SNAPSHOT_CESSIONARIO_VALUE_META_KEY = "__authz.cessionarioValue";

    /** Internal snapshot metadata key storing the source entity reference when custom custody predicates are configured ({@code P10.9-R01}). */
    public static final String SNAPSHOT_ENTITY_REF_META_KEY = "__authz.entityRef";

    private final String resourceKey;
    private final FactContract factContract;
    private final DecisionPointDescriptor decisionPoint;
    private final String factContractDigest;
    private final QueryableResourceProjection queryProjection;
    private final List<QueryAdapterFieldBinding> fieldBindings;
    private final Map<String, QueryAdapterFieldBinding> bindingsByFieldPath;
    private final JpaDataScopeAdapter jpaDataScopeAdapter;
    private final JpaCriteriaDataScopeTranslator criteriaTranslator;
    private final DualScopeDelegationSpec dualScopeDelegationSpec;
    private final Set<String> mandatoryScopeAnchorAttributeIds;
    private final Set<String> technicalConcurrencyPointers;
    private final String tenantFieldName;
    private final Class<?> tenantJavaType;
    private final String tenantJpqlExpression;
    private final Function<E, String> entityTenantExtractor;
    private final BiPredicate<E, AuthzCallerContext> entityScopePredicate;
    private final Function<E, Map<String, Object>> targetFactExtractor;
    private final String stateFieldName;
    private final Function<E, String> stateExtractor;
    private final String cedenteEntityFieldPath;
    private final String cedenteSubjectFactKey;
    private final BiPredicate<E, AuthzCallerContext> cedenteCustodyPredicate;
    private final String cessionarioEntityFieldPath;
    private final String cessionarioSubjectFactKey;
    private final BiPredicate<E, AuthzCallerContext> cessionarioCustodyPredicate;
    private final Map<String, Set<String>> operationModifiedAttributes;
    private final Map<String, DecisionPointDescriptor> actionDecisionPoints;
    private final Map<String, DecisionPointDescriptor> surfaceDecisionPoints;

    private AuthzResourceGovernanceSpec(Builder<E> builder) {
        this.resourceKey = Objects.requireNonNull(builder.resourceKey, "resourceKey is required");
        this.factContract = builder.factContract;
        this.decisionPoint = Objects.requireNonNull(builder.decisionPoint, "decisionPoint is required");
        this.factContractDigest = Objects.requireNonNull(builder.factContractDigest, "factContractDigest is required");
        this.queryProjection = Objects.requireNonNull(builder.queryProjection, "queryProjection is required");
        this.fieldBindings = List.copyOf(Objects.requireNonNull(builder.fieldBindings, "fieldBindings is required"));
        Map<String, QueryAdapterFieldBinding> bindingMap = new LinkedHashMap<>();
        for (QueryAdapterFieldBinding b : this.fieldBindings) {
            bindingMap.put(b.fieldPath(), b);
        }
        this.bindingsByFieldPath = Map.copyOf(bindingMap);
        this.jpaDataScopeAdapter = new JpaDataScopeAdapter(this.queryProjection, this.fieldBindings);
        this.criteriaTranslator = new JpaCriteriaDataScopeTranslator(this.queryProjection, this.fieldBindings);
        this.dualScopeDelegationSpec = builder.dualScopeDelegationSpec;
        this.mandatoryScopeAnchorAttributeIds = Set.copyOf(builder.mandatoryScopeAnchorAttributeIds);
        this.technicalConcurrencyPointers = Set.copyOf(builder.technicalConcurrencyPointers);
        this.tenantFieldName = Objects.requireNonNull(builder.tenantFieldName, "tenantFieldName is required");
        this.tenantJavaType = builder.tenantJavaType;
        this.tenantJpqlExpression = builder.tenantJpqlExpression != null
                ? builder.tenantJpqlExpression
                : "e." + this.tenantFieldName;
        this.entityTenantExtractor = builder.entityTenantExtractor;
        this.entityScopePredicate = builder.entityScopePredicate;
        this.targetFactExtractor = builder.targetFactExtractor;
        this.stateFieldName = builder.stateFieldName;
        this.stateExtractor = builder.stateExtractor;
        this.cedenteEntityFieldPath = builder.cedenteEntityFieldPath;
        this.cedenteSubjectFactKey = builder.cedenteSubjectFactKey;
        this.cedenteCustodyPredicate = builder.cedenteCustodyPredicate;
        this.cessionarioEntityFieldPath = builder.cessionarioEntityFieldPath;
        this.cessionarioSubjectFactKey = builder.cessionarioSubjectFactKey;
        this.cessionarioCustodyPredicate = builder.cessionarioCustodyPredicate;
        Map<String, Set<String>> opAttrs = new LinkedHashMap<>();
        for (Map.Entry<String, Set<String>> e : builder.operationModifiedAttributes.entrySet()) {
            opAttrs.put(e.getKey(), Set.copyOf(e.getValue()));
        }
        this.operationModifiedAttributes = Map.copyOf(opAttrs);
        this.actionDecisionPoints = Map.copyOf(builder.actionDecisionPoints);
        this.surfaceDecisionPoints = Map.copyOf(builder.surfaceDecisionPoints);
    }

    /**
     * Creates a new fluent {@link Builder} for the given {@code resourceKey}.
     *
     * @param <E> JPA entity type
     * @param resourceKey canonical resource key (e.g. {@code "human-resources.afastamentos"})
     * @return builder instance
     */
    public static <E> Builder<E> builder(String resourceKey) {
        return new Builder<>(resourceKey);
    }

    /**
     * Zero-blueprint factory ({@code PLAT-EVO-10}) that introspects a Praxis resource's JPA entity,
     * {@code ResponseDTO}, {@code FilterDTO}, and {@code Controller} annotations ({@link ApiResource},
     * {@link WorkflowAction}, {@link UiSurface}, {@link Filterable}, {@code @DomainGovernance},
     * {@code @DomainLineage}) to synthesize a complete {@link AuthzResourceGovernanceSpec} without
     * manual boilerplate.
     *
     * @param <E> JPA entity type
     * @param serviceKey owning microservice/host key (e.g. {@code "praxis-ergon-showcase"})
     * @param tenantFieldName tenant hard-scope field path on {@code entityClass} (e.g. {@code "empCodigo"})
     * @param entityClass JPA entity class
     * @param responseDtoClass resource {@code ResponseDTO} class
     * @param filterDtoClass optional resource {@code FilterDTO} class
     * @param controllerClass controller class annotated with {@link ApiResource}
     * @return complete {@link AuthzResourceGovernanceSpec}
     */
    public static <E> AuthzResourceGovernanceSpec<E> fromAnnotatedResource(
            String serviceKey,
            String tenantFieldName,
            Class<E> entityClass,
            Class<?> responseDtoClass,
            Class<?> filterDtoClass,
            Class<?> controllerClass
    ) {
        Objects.requireNonNull(controllerClass, "controllerClass is required when resourceKey is omitted");
        ApiResource apiResource = AnnotatedElementUtils.findMergedAnnotation(controllerClass, ApiResource.class);
        if (apiResource == null || apiResource.resourceKey() == null || apiResource.resourceKey().isBlank()) {
            throw new IllegalArgumentException(
                    "Controller " + controllerClass.getName() + " must declare @ApiResource(resourceKey = ...)");
        }
        return fromAnnotatedResource(
                serviceKey,
                apiResource.resourceKey().trim(),
                tenantFieldName,
                entityClass,
                responseDtoClass,
                filterDtoClass,
                controllerClass
        );
    }

    /**
     * Zero-blueprint factory ({@code PLAT-EVO-10}) that introspects a Praxis resource's JPA entity,
     * {@code ResponseDTO}, {@code FilterDTO}, and optional {@code Controller} annotations to synthesize
     * a complete {@link AuthzResourceGovernanceSpec} without manual boilerplate.
     *
     * @param <E> JPA entity type
     * @param serviceKey owning microservice/host key
     * @param resourceKey canonical resource key
     * @param tenantFieldName tenant hard-scope field path on {@code entityClass}
     * @param entityClass JPA entity class
     * @param responseDtoClass optional resource {@code ResponseDTO} class
     * @param filterDtoClass optional resource {@code FilterDTO} class
     * @param controllerClass optional controller class
     * @return complete {@link AuthzResourceGovernanceSpec}
     */
    public static <E> AuthzResourceGovernanceSpec<E> fromAnnotatedResource(
            String serviceKey,
            String resourceKey,
            String tenantFieldName,
            Class<E> entityClass,
            Class<?> responseDtoClass,
            Class<?> filterDtoClass,
            Class<?> controllerClass
    ) {
        return AuthzResourceGovernanceSpec.<E>builder(resourceKey)
                .serviceKey(serviceKey)
                .tenantField(tenantFieldName)
                .introspectFromResource(entityClass, responseDtoClass, filterDtoClass, controllerClass)
                .build();
    }

    public String resourceKey() {
        return resourceKey;
    }

    /** Returns the optional {@link FactContract} associated with or derived by this spec ({@code Fase P10.14}). */
    public FactContract factContract() {
        return factContract;
    }

    public DecisionPointDescriptor decisionPoint() {
        return decisionPoint;
    }

    public String factContractDigest() {
        return factContractDigest;
    }

    public QueryableResourceProjection queryProjection() {
        return queryProjection;
    }

    public List<QueryAdapterFieldBinding> fieldBindings() {
        return fieldBindings;
    }

    public JpaDataScopeAdapter jpaDataScopeAdapter() {
        return jpaDataScopeAdapter;
    }

    public JpaCriteriaDataScopeTranslator criteriaTranslator() {
        return criteriaTranslator;
    }

    public DualScopeDelegationSpec dualScopeDelegationSpec() {
        return dualScopeDelegationSpec;
    }

    public Set<String> mandatoryScopeAnchorAttributeIds() {
        return mandatoryScopeAnchorAttributeIds;
    }

    public Set<String> technicalConcurrencyPointers() {
        return technicalConcurrencyPointers;
    }

    public String tenantFieldName() {
        return tenantFieldName;
    }

    public String tenantJpqlExpression() {
        return tenantJpqlExpression;
    }

    public Map<String, Set<String>> operationModifiedAttributes() {
        return operationModifiedAttributes;
    }

    public Map<String, DecisionPointDescriptor> actionDecisionPoints() {
        return actionDecisionPoints;
    }

    public Map<String, DecisionPointDescriptor> surfaceDecisionPoints() {
        return surfaceDecisionPoints;
    }

    /** Returns the optional entity state property path used for {@link ResourceStateSnapshot#state()}. */
    public String stateFieldName() {
        return stateFieldName;
    }

    /** Returns the optional entity property path storing the {@code Cedente} custody anchor value. */
    public String cedenteEntityFieldPath() {
        return cedenteEntityFieldPath;
    }

    /** Returns the optional caller subject fact key compared against {@link #cedenteEntityFieldPath()}. */
    public String cedenteSubjectFactKey() {
        return cedenteSubjectFactKey;
    }

    /** Returns the optional entity property path storing the {@code Cessionário} custody anchor value. */
    public String cessionarioEntityFieldPath() {
        return cessionarioEntityFieldPath;
    }

    /** Returns the optional caller subject fact key compared against {@link #cessionarioEntityFieldPath()}. */
    public String cessionarioSubjectFactKey() {
        return cessionarioSubjectFactKey;
    }

    /** Returns {@code true} when declarative {@code Cedente} custody rules are configured on this spec. */
    public boolean hasDeclarativeCedenteCustody() {
        return cedenteCustodyPredicate != null || (cedenteEntityFieldPath != null && cedenteSubjectFactKey != null);
    }

    /** Returns {@code true} when declarative {@code Cessionário} custody rules are configured on this spec. */
    public boolean hasDeclarativeCessionarioCustody() {
        return cessionarioCustodyPredicate != null || (cessionarioEntityFieldPath != null && cessionarioSubjectFactKey != null);
    }

    /**
     * Builds the JPA Criteria {@link ResourceFilterAccessScope} for the given {@code tenantId},
     * automatically coercing {@code tenantId} to integer/long/UUID types when the entity's tenant
     * attribute is non-String ({@code PLAT-EVO-10}).
     */
    public ResourceFilterAccessScope<E> buildHardScope(String tenantId) {
        Objects.requireNonNull(tenantId, "tenantId is required for hardScope");
        return ResourceFilterAccessScope.restricted(
                (root, query, cb) -> {
                    Path<?> path = resolveCriteriaTenantPath(root, tenantFieldName);
                    Class<?> expectedType = path != null && path.getJavaType() != null
                            ? path.getJavaType()
                            : tenantJavaType;
                    return cb.equal(path, coerceTenantValue(expectedType, tenantId));
                }
        );
    }

    private static Path<?> resolveCriteriaTenantPath(From<?, ?> root, String dotPath) {
        String[] segments = dotPath.split("\\.");
        From<?, ?> current = root;
        for (int i = 0; i < segments.length - 1; i++) {
            current = current.join(segments[i], JoinType.INNER);
        }
        return current.get(segments[segments.length - 1]);
    }

    private static Object coerceTenantValue(Class<?> expectedType, String tenantId) {
        if (expectedType == null || expectedType == String.class || expectedType == Object.class) {
            return tenantId;
        }
        try {
            if (expectedType == Integer.class || expectedType == int.class) {
                return Integer.valueOf(tenantId.trim());
            }
            if (expectedType == Long.class || expectedType == long.class) {
                return Long.valueOf(tenantId.trim());
            }
            if (expectedType == Short.class || expectedType == short.class) {
                return Short.valueOf(tenantId.trim());
            }
            if (expectedType == UUID.class) {
                return UUID.fromString(tenantId.trim());
            }
        } catch (IllegalArgumentException ex) {
            throw new SecurityException(
                    "AUTHZ_HARD_SCOPE_TENANT_MISMATCH: Tenant identifier '" + tenantId
                            + "' is incompatible with entity tenant type " + expectedType.getSimpleName() + " (403)",
                    ex);
        }
        return tenantId;
    }

    /**
     * Returns the canonical JPQL hard-scope predicate expression.
     */
    public String buildHardScopeJpql() {
        return tenantJpqlExpression + " = :" + HARD_TENANT_PARAM;
    }

    /**
     * Returns the canonical JPQL hard-scope parameter map for the given {@code tenantId}.
     */
    public Map<String, Object> buildHardScopeParams(String tenantId) {
        Objects.requireNonNull(tenantId, "tenantId is required for hardScopeParams");
        return Map.of(HARD_TENANT_PARAM, coerceTenantValue(tenantJavaType, tenantId));
    }

    /**
     * Extracts the tenant identifier from {@code entity} using {@code entityTenantExtractor} or
     * reflection on {@link #tenantFieldName()}.
     *
     * @param entity JPA entity instance
     * @return extracted tenant identifier or {@code null}
     */
    public String extractTenantFromEntity(E entity) {
        if (entity == null) {
            return null;
        }
        if (entityTenantExtractor != null) {
            return entityTenantExtractor.apply(entity);
        }
        Object val = readNestedProperty(entity, tenantFieldName);
        return val == null ? null : String.valueOf(val);
    }

    /**
     * Automatically extracts {@code resource.*} target facts from {@code entity} using the
     * configured {@link #fieldBindings()} and any optional {@code targetFactExtractor}
     * ({@code Fase P10.9}).
     *
     * @param entity JPA entity instance
     * @return immutable map of extracted {@code resource.*} facts
     */
    public Map<String, Object> extractEntityTargetFacts(E entity) {
        if (entity == null) {
            return Map.of();
        }
        Map<String, Object> facts = new LinkedHashMap<>();
        for (QueryAdapterFieldBinding binding : fieldBindings) {
            if (binding.traversalStrategy() == RelationTraversalStrategy.CORRELATED_EXISTS_SUBQUERY) {
                List<Object> values = extractCollectionValues(entity, binding.nativeJpaPath());
                facts.put(binding.fieldPath(), values);
            } else {
                Object val = readNestedProperty(entity, binding.nativeJpaPath());
                if (val != null) {
                    facts.put(binding.fieldPath(), val);
                }
            }
        }
        if (dualScopeDelegationSpec != null) {
            if (cedenteEntityFieldPath != null && dualScopeDelegationSpec.cedenteFactPath() != null) {
                Object cedenteVal = readNestedProperty(entity, cedenteEntityFieldPath);
                if (cedenteVal != null) {
                    facts.putIfAbsent(dualScopeDelegationSpec.cedenteFactPath(), cedenteVal);
                }
            }
            if (cessionarioEntityFieldPath != null && dualScopeDelegationSpec.cessionarioFactPath() != null) {
                Object cessionarioVal = readNestedProperty(entity, cessionarioEntityFieldPath);
                if (cessionarioVal != null) {
                    facts.putIfAbsent(dualScopeDelegationSpec.cessionarioFactPath(), cessionarioVal);
                }
            }
        }
        if (targetFactExtractor != null) {
            Map<String, Object> custom = targetFactExtractor.apply(entity);
            if (custom != null && !custom.isEmpty()) {
                facts.putAll(custom);
            }
        }
        return Map.copyOf(facts);
    }

    /**
     * Extracts the workflow/lifecycle state string from {@code entity} when {@code stateField} or
     * {@code stateExtractor} is configured ({@code Fase P10.9}).
     *
     * @param entity JPA entity instance
     * @return extracted state string or {@code null}
     */
    public String extractEntityState(E entity) {
        if (entity == null) {
            return null;
        }
        if (stateExtractor != null) {
            return stateExtractor.apply(entity);
        }
        if (stateFieldName != null && !stateFieldName.isBlank()) {
            Object val = readNestedProperty(entity, stateFieldName);
            return val == null ? null : String.valueOf(val);
        }
        return null;
    }

    /**
     * Builds a canonical {@link ResourceStateSnapshot} from {@code entity} containing its lifecycle
     * state, {@code resource.*} target facts, tenant identifier, and dual-scope custody anchor values
     * ({@code Fase P10.9}).
     *
     * @param entity JPA entity instance
     * @return populated {@link ResourceStateSnapshot}
     */
    public ResourceStateSnapshot toResourceStateSnapshot(E entity) {
        Objects.requireNonNull(entity, "entity is required");
        String state = extractEntityState(entity);
        Map<String, Object> metadata = new LinkedHashMap<>(extractEntityTargetFacts(entity));
        for (QueryAdapterFieldBinding binding : fieldBindings) {
            if (binding.traversalStrategy() != RelationTraversalStrategy.CORRELATED_EXISTS_SUBQUERY) {
                Object val = metadata.get(binding.fieldPath());
                if (val != null) {
                    metadata.putIfAbsent(binding.nativeJpaPath(), val);
                }
            }
        }
        String tenantId = extractTenantFromEntity(entity);
        if (tenantId != null) {
            metadata.put(SNAPSHOT_TENANT_META_KEY, tenantId);
        }
        if (cedenteEntityFieldPath != null) {
            Object cedenteVal = readNestedProperty(entity, cedenteEntityFieldPath);
            if (cedenteVal != null) {
                metadata.put(SNAPSHOT_CEDENTE_VALUE_META_KEY, cedenteVal);
            }
        }
        if (cessionarioEntityFieldPath != null) {
            Object cessionarioVal = readNestedProperty(entity, cessionarioEntityFieldPath);
            if (cessionarioVal != null) {
                metadata.put(SNAPSHOT_CESSIONARIO_VALUE_META_KEY, cessionarioVal);
            }
        }
        if (cedenteCustodyPredicate != null || cessionarioCustodyPredicate != null) {
            metadata.put(SNAPSHOT_ENTITY_REF_META_KEY, entity);
        }
        return ResourceStateSnapshot.of(state, metadata);
    }

    /**
     * Extracts {@code resource.*} target facts from a {@link ResourceStateSnapshot} produced either
     * by {@link #toResourceStateSnapshot(Object)} or by a custom {@code ResourceStateSnapshotProvider}
     * ({@code Fase P10.9}).
     *
     * @param snapshot resource state snapshot
     * @return immutable map of {@code resource.*} target facts
     */
    public Map<String, Object> extractSnapshotTargetFacts(ResourceStateSnapshot snapshot) {
        if (snapshot == null || snapshot.metadata().isEmpty()) {
            return Map.of();
        }
        Map<String, Object> facts = new LinkedHashMap<>();
        Map<String, Object> meta = snapshot.metadata();
        for (QueryAdapterFieldBinding binding : fieldBindings) {
            Object val = meta.get(binding.fieldPath());
            if (val == null) {
                val = meta.get(binding.nativeJpaPath());
            }
            if (val != null) {
                facts.put(binding.fieldPath(), val);
            }
        }
        for (Map.Entry<String, Object> entry : meta.entrySet()) {
            if (entry.getKey().startsWith("resource.") && entry.getValue() != null) {
                facts.putIfAbsent(entry.getKey(), entry.getValue());
            }
        }
        return Map.copyOf(facts);
    }

    /**
     * Evaluates whether the caller represented by {@code callerContext} holds {@code Cedente}
     * (origin) custody over {@code entity} ({@code Fase P10.9}).
     *
     * @param entity JPA entity instance (may be {@code null} for collection-scoped probes)
     * @param callerContext active caller context
     * @return {@code true} when caller holds {@code Cedente} custody
     */
    public boolean isCallerCedente(E entity, AuthzCallerContext callerContext) {
        if (callerContext == null) {
            return dualScopeDelegationSpec == null;
        }
        if (callerContext.callerMatchesCedente() != null) {
            return callerContext.callerMatchesCedente();
        }
        if (cedenteCustodyPredicate != null && entity != null) {
            return cedenteCustodyPredicate.test(entity, callerContext);
        }
        if (cedenteEntityFieldPath != null && cedenteSubjectFactKey != null) {
            Object subjectFact = callerContext.subjectAndEnvironmentFacts().get(cedenteSubjectFactKey);
            if (entity == null) {
                return hasNonEmptyCustodySubjectFact(subjectFact);
            }
            Object entityVal = readNestedProperty(entity, cedenteEntityFieldPath);
            return matchesCustodyValue(entityVal, subjectFact);
        }
        return true;
    }

    /**
     * Evaluates whether the caller represented by {@code callerContext} holds {@code Cessionário}
     * (destination) custody over {@code entity} ({@code Fase P10.9}).
     *
     * @param entity JPA entity instance (may be {@code null} for collection-scoped probes)
     * @param callerContext active caller context
     * @return {@code true} when caller holds {@code Cessionário} custody
     */
    public boolean isCallerCessionario(E entity, AuthzCallerContext callerContext) {
        if (callerContext == null) {
            return dualScopeDelegationSpec == null;
        }
        if (callerContext.callerMatchesCessionario() != null) {
            return callerContext.callerMatchesCessionario();
        }
        if (cessionarioCustodyPredicate != null && entity != null) {
            return cessionarioCustodyPredicate.test(entity, callerContext);
        }
        if (cessionarioEntityFieldPath != null && cessionarioSubjectFactKey != null) {
            Object subjectFact = callerContext.subjectAndEnvironmentFacts().get(cessionarioSubjectFactKey);
            if (entity == null) {
                return hasNonEmptyCustodySubjectFact(subjectFact);
            }
            Object entityVal = readNestedProperty(entity, cessionarioEntityFieldPath);
            return matchesCustodyValue(entityVal, subjectFact);
        }
        return true;
    }

    /**
     * Evaluates whether the caller holds {@code Cedente} custody for an item {@link ResourceStateSnapshot}
     * ({@code Fase P10.9}, {@code P10.9-R01}).
     */
    @SuppressWarnings("unchecked")
    public boolean isCallerCedenteForSnapshot(ResourceStateSnapshot snapshot, AuthzCallerContext callerContext) {
        if (callerContext == null) {
            return dualScopeDelegationSpec == null;
        }
        if (callerContext.callerMatchesCedente() != null) {
            return callerContext.callerMatchesCedente();
        }
        if (snapshot == null) {
            return false;
        }
        if (cedenteCustodyPredicate != null) {
            Object entityRef = snapshot.metadata().get(SNAPSHOT_ENTITY_REF_META_KEY);
            if (entityRef != null) {
                return cedenteCustodyPredicate.test((E) entityRef, callerContext);
            }
            return false;
        }
        if (cedenteEntityFieldPath != null && cedenteSubjectFactKey != null) {
            Object subjectFact = callerContext.subjectAndEnvironmentFacts().get(cedenteSubjectFactKey);
            Object snapshotVal = snapshot.metadata().get(SNAPSHOT_CEDENTE_VALUE_META_KEY);
            if (snapshotVal == null) {
                snapshotVal = snapshot.metadata().get(cedenteEntityFieldPath);
            }
            return matchesCustodyValue(snapshotVal, subjectFact);
        }
        return true;
    }

    /**
     * Evaluates whether the caller holds {@code Cessionário} custody for an item {@link ResourceStateSnapshot}
     * ({@code Fase P10.9}, {@code P10.9-R01}).
     */
    @SuppressWarnings("unchecked")
    public boolean isCallerCessionarioForSnapshot(ResourceStateSnapshot snapshot, AuthzCallerContext callerContext) {
        if (callerContext == null) {
            return dualScopeDelegationSpec == null;
        }
        if (callerContext.callerMatchesCessionario() != null) {
            return callerContext.callerMatchesCessionario();
        }
        if (snapshot == null) {
            return false;
        }
        if (cessionarioCustodyPredicate != null) {
            Object entityRef = snapshot.metadata().get(SNAPSHOT_ENTITY_REF_META_KEY);
            if (entityRef != null) {
                return cessionarioCustodyPredicate.test((E) entityRef, callerContext);
            }
            return false;
        }
        if (cessionarioEntityFieldPath != null && cessionarioSubjectFactKey != null) {
            Object subjectFact = callerContext.subjectAndEnvironmentFacts().get(cessionarioSubjectFactKey);
            Object snapshotVal = snapshot.metadata().get(SNAPSHOT_CESSIONARIO_VALUE_META_KEY);
            if (snapshotVal == null) {
                snapshotVal = snapshot.metadata().get(cessionarioEntityFieldPath);
            }
            return matchesCustodyValue(snapshotVal, subjectFact);
        }
        return true;
    }

    private static boolean hasNonEmptyCustodySubjectFact(Object subjectFact) {
        if (subjectFact == null) {
            return false;
        }
        if (subjectFact instanceof Collection<?> col) {
            return !col.isEmpty();
        }
        return true;
    }

    private static boolean matchesCustodyValue(Object entityValue, Object subjectFact) {
        if (entityValue == null || subjectFact == null) {
            return false;
        }
        if (subjectFact instanceof Collection<?> col) {
            return col.stream().anyMatch(item -> valuesEqual(entityValue, item, false));
        }
        return valuesEqual(entityValue, subjectFact, false);
    }

    /**
     * Verifies row-level access on {@code entity} against the active {@link AuthzCallerContext}.
     */
    public void verifyEntityAccessAllowed(E entity, AuthzCallerContext callerContext) {
        verifyEntityAccessAllowed(entity, callerContext, null);
    }

    /**
     * Verifies row-level access on {@code entity} against the active {@link AuthzCallerContext}
     * and the live OPA {@link DataScopePlan} ({@code P10.8-R03}, {@code P05}, {@code P06}, {@code P07}).
     *
     * <ol>
     *   <li>Enforces tenant hard-scope isolation ({@code AUTHZ_HARD_SCOPE_TENANT_MISMATCH});</li>
     *   <li>When {@code activeDataScopePlan} is present, evaluates its {@link DataScopeOutcome}
     *       and {@link SearchPredicateIr} AST directly against {@code entity} using
     *       {@link #fieldBindings()} with Kleene 3-valued {@code NULL} semantics;</li>
     *   <li>When an optional {@code entityScopePredicate} is configured, enforces it as an
     *       additional host invariant.</li>
     * </ol>
     */
    public void verifyEntityAccessAllowed(
            E entity,
            AuthzCallerContext callerContext,
            DataScopePlan activeDataScopePlan
    ) {
        Objects.requireNonNull(entity, "entity is required");
        Objects.requireNonNull(callerContext, "callerContext is required");
        String entityTenant = extractTenantFromEntity(entity);
        if (!Objects.equals(callerContext.tenantId(), entityTenant)) {
            throw new SecurityException("AUTHZ_HARD_SCOPE_TENANT_MISMATCH: Entity tenant '"
                    + entityTenant + "' does not match caller tenant '" + callerContext.tenantId() + "' (403)");
        }
        if (activeDataScopePlan != null) {
            if (activeDataScopePlan.scopeOutcome() == DataScopeOutcome.NONE) {
                throw new SecurityException(
                        "AUTHZ_ENTITY_DATA_SCOPE_DENIED: Active DataScopePlan outcome is NONE (403)");
            }
            if (activeDataScopePlan.scopeOutcome() == DataScopeOutcome.FILTER) {
                SearchPredicateIr predicateIr = Objects.requireNonNull(
                        activeDataScopePlan.predicateIr(), "FILTER outcome requires non-null predicateIr");
                queryProjection.validatePredicateIr(predicateIr);
                if (!evaluatePredicateIrOnEntity(entity, predicateIr, false)) {
                    throw new SecurityException(
                            "AUTHZ_ENTITY_DATA_SCOPE_DENIED: Entity is outside caller's authorized DataScopePlan (403)");
                }
            }
        }
        if (entityScopePredicate != null && !entityScopePredicate.test(entity, callerContext)) {
            throw new SecurityException(
                    "AUTHZ_ENTITY_DATA_SCOPE_DENIED: Entity is outside caller's authorized DataScopePlan (403)");
        }
    }

    private boolean evaluatePredicateIrOnEntity(E entity, SearchPredicateIr node, boolean negated) {
        if (node instanceof LogicalPredicateIr logical) {
            return switch (logical.operator()) {
                case NOT -> evaluatePredicateIrOnEntity(entity, logical.operands().getFirst(), !negated);
                case AND -> {
                    if (negated) {
                        for (SearchPredicateIr child : logical.operands()) {
                            if (evaluatePredicateIrOnEntity(entity, child, true)) {
                                yield true;
                            }
                        }
                        yield false;
                    }
                    for (SearchPredicateIr child : logical.operands()) {
                        if (!evaluatePredicateIrOnEntity(entity, child, false)) {
                            yield false;
                        }
                    }
                    yield true;
                }
                case OR -> {
                    if (negated) {
                        for (SearchPredicateIr child : logical.operands()) {
                            if (!evaluatePredicateIrOnEntity(entity, child, true)) {
                                yield false;
                            }
                        }
                        yield true;
                    }
                    for (SearchPredicateIr child : logical.operands()) {
                        if (evaluatePredicateIrOnEntity(entity, child, false)) {
                            yield true;
                        }
                    }
                    yield false;
                }
                default -> throw new IllegalArgumentException("Unexpected logical operator: " + logical.operator());
            };
        }

        if (node instanceof NullabilityPredicateIr nullPred) {
            QueryAdapterFieldBinding binding = requireBinding(nullPred.fieldPath());
            boolean checkIsNull = (nullPred.operator() == SearchPredicateOperator.IS_NULL) ^ negated;
            if (binding.traversalStrategy() == RelationTraversalStrategy.CORRELATED_EXISTS_SUBQUERY) {
                List<Object> values = extractCollectionValues(entity, binding.nativeJpaPath());
                return values.stream().anyMatch(v -> checkIsNull == (v == null));
            }
            Object val = readNestedProperty(entity, binding.nativeJpaPath());
            return checkIsNull == (val == null);
        }

        if (node instanceof ComparisonPredicateIr comp) {
            QueryAdapterFieldBinding binding = requireBinding(comp.fieldPath());
            if (binding.traversalStrategy() == RelationTraversalStrategy.CORRELATED_EXISTS_SUBQUERY) {
                List<Object> values = extractCollectionValues(entity, binding.nativeJpaPath());
                boolean anyMatch = values.stream().anyMatch(
                        v -> evaluateScalarComparison(entity, v, binding.nullableColumn(), comp, false));
                return negated != anyMatch;
            }
            Object lhsVal = readNestedProperty(entity, binding.nativeJpaPath());
            return evaluateScalarComparison(entity, lhsVal, binding.nullableColumn(), comp, negated);
        }

        throw new IllegalArgumentException("Unsupported SearchPredicateIr: " + node);
    }

    private boolean evaluateScalarComparison(
            E rootEntity,
            Object lhsRaw,
            boolean lhsNullableColumn,
            ComparisonPredicateIr comp,
            boolean negated
    ) {
        Object rhsRaw;
        boolean rhsNullableColumn = false;
        boolean isFieldRef = false;
        if (comp.rightOperand() instanceof FieldRefOperandIr fieldRef) {
            QueryAdapterFieldBinding rhsBinding = requireBinding(fieldRef.targetFieldPath());
            rhsRaw = readNestedProperty(rootEntity, rhsBinding.nativeJpaPath());
            rhsNullableColumn = rhsBinding.nullableColumn();
            isFieldRef = true;
        } else if (comp.rightOperand() instanceof LiteralOperandIr lit) {
            rhsRaw = lit.value();
        } else if (comp.rightOperand() instanceof LiteralListOperandIr listOp) {
            rhsRaw = listOp.values();
        } else {
            throw new IllegalArgumentException("Unsupported rightOperand: " + comp.rightOperand());
        }

        boolean requiresNotNullGuard = switch (comp.operator()) {
            case NE, NIN -> !negated;
            case EQ, IN, GT, GTE, LT, LTE, TEXT_CONTAINS, STARTS_WITH, ENDS_WITH -> negated;
            default -> false;
        };
        if (lhsRaw == null) {
            return false;
        }
        if (isFieldRef && rhsRaw == null) {
            return false;
        }
        if (requiresNotNullGuard && ((lhsNullableColumn && lhsRaw == null) || (rhsNullableColumn && rhsRaw == null))) {
            return false;
        }

        boolean rawMatch = switch (comp.operator()) {
            case EQ -> valuesEqual(lhsRaw, rhsRaw, comp.caseInsensitive());
            case NE -> !valuesEqual(lhsRaw, rhsRaw, comp.caseInsensitive());
            case IN -> {
                Collection<?> list = (Collection<?>) rhsRaw;
                yield list.stream().anyMatch(item -> valuesEqual(lhsRaw, item, comp.caseInsensitive()));
            }
            case NIN -> {
                Collection<?> list = (Collection<?>) rhsRaw;
                yield list.stream().noneMatch(item -> valuesEqual(lhsRaw, item, comp.caseInsensitive()));
            }
            case GT -> compareValues(lhsRaw, rhsRaw, comp.caseInsensitive()) > 0;
            case GTE -> compareValues(lhsRaw, rhsRaw, comp.caseInsensitive()) >= 0;
            case LT -> compareValues(lhsRaw, rhsRaw, comp.caseInsensitive()) < 0;
            case LTE -> compareValues(lhsRaw, rhsRaw, comp.caseInsensitive()) <= 0;
            case TEXT_CONTAINS -> normalizeString(lhsRaw, comp.caseInsensitive())
                    .contains(normalizeString(rhsRaw, comp.caseInsensitive()));
            case STARTS_WITH -> normalizeString(lhsRaw, comp.caseInsensitive())
                    .startsWith(normalizeString(rhsRaw, comp.caseInsensitive()));
            case ENDS_WITH -> normalizeString(lhsRaw, comp.caseInsensitive())
                    .endsWith(normalizeString(rhsRaw, comp.caseInsensitive()));
            default -> throw new IllegalArgumentException("Unsupported comparison operator: " + comp.operator());
        };
        return negated != rawMatch;
    }

    private static boolean valuesEqual(Object a, Object b, boolean caseInsensitive) {
        if (a == null || b == null) {
            return false;
        }
        if (a instanceof Number na && b instanceof Number nb) {
            return new BigDecimal(na.toString()).compareTo(new BigDecimal(nb.toString())) == 0;
        }
        if (caseInsensitive && a instanceof String sa && b instanceof String sb) {
            return sa.toLowerCase(Locale.ROOT).equals(sb.toLowerCase(Locale.ROOT));
        }
        return Objects.equals(a, b);
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    private static int compareValues(Object a, Object b, boolean caseInsensitive) {
        if (a instanceof Number na && b instanceof Number nb) {
            return new BigDecimal(na.toString()).compareTo(new BigDecimal(nb.toString()));
        }
        if (caseInsensitive && a instanceof String sa && b instanceof String sb) {
            return sa.toLowerCase(Locale.ROOT).compareTo(sb.toLowerCase(Locale.ROOT));
        }
        return ((Comparable) a).compareTo(b);
    }

    private static String normalizeString(Object val, boolean caseInsensitive) {
        String s = String.valueOf(val);
        return caseInsensitive ? s.toLowerCase(Locale.ROOT) : s;
    }

    private QueryAdapterFieldBinding requireBinding(String fieldPath) {
        QueryAdapterFieldBinding binding = bindingsByFieldPath.get(fieldPath);
        if (binding == null) {
            throw new IllegalStateException("No QueryAdapterFieldBinding registered for fieldPath '" + fieldPath + "'");
        }
        return binding;
    }

    private static Object readNestedProperty(Object target, String dotPath) {
        Object current = target;
        for (String segment : dotPath.split("\\.")) {
            if (current == null) {
                return null;
            }
            current = readSingleField(current, segment);
        }
        return current;
    }

    private static List<Object> extractCollectionValues(Object target, String dotPath) {
        String[] segments = dotPath.split("\\.");
        if (segments.length < 2) {
            throw new IllegalArgumentException(
                    "CORRELATED_EXISTS_SUBQUERY path must have at least collection.property: " + dotPath);
        }
        Object current = target;
        for (int i = 0; i < segments.length - 1; i++) {
            if (current == null) {
                return List.of();
            }
            current = readSingleField(current, segments[i]);
        }
        if (!(current instanceof Collection<?> col)) {
            return List.of();
        }
        String leaf = segments[segments.length - 1];
        return col.stream()
                .filter(Objects::nonNull)
                .map(elem -> readSingleField(elem, leaf))
                .toList();
    }

    private static Object readSingleField(Object target, String fieldName) {
        Class<?> current = target.getClass();
        while (current != null && current != Object.class) {
            try {
                Field f = current.getDeclaredField(fieldName);
                f.setAccessible(true);
                return f.get(target);
            } catch (NoSuchFieldException ignored) {
                current = current.getSuperclass();
            } catch (IllegalAccessException ex) {
                throw new IllegalStateException("Failed to read field '" + fieldName + "' on " + target.getClass().getName(), ex);
            }
        }
        throw new IllegalStateException("Field '" + fieldName + "' not found on class " + target.getClass().getName());
    }

    /**
     * Fluent builder for {@link AuthzResourceGovernanceSpec}.
     *
     * @param <E> JPA entity type
     */
    public static final class Builder<E> {
        private final String resourceKey;
        private String serviceKey;
        private String operationKey = "filter";
        private String httpMethod = "POST";
        private String httpPath;
        private String legalBasis = "STATUTORY_LEGAL_OBLIGATION";
        private String regulatoryReference = "LGPD:ART_7_III";
        private FactContract factContract;
        private DecisionPointDescriptor decisionPoint;
        private String factContractDigest;
        private QueryableResourceProjection queryProjection;
        private List<QueryAdapterFieldBinding> fieldBindings = List.of();
        private final List<QueryAdapterFieldBinding> declarativeFieldBindings = new ArrayList<>();
        private final Map<String, QueryableFieldDescriptor> declarativeQueryableFields = new LinkedHashMap<>();
        private final Map<String, FactDescriptor> declarativeFacts = new LinkedHashMap<>();
        private DualScopeDelegationSpec dualScopeDelegationSpec;
        private final Set<String> mandatoryScopeAnchorAttributeIds = new LinkedHashSet<>();
        private final Set<String> technicalConcurrencyPointers = new LinkedHashSet<>(Set.of("/version"));
        private String tenantFieldName = "tenantId";
        private Class<?> tenantJavaType;
        private String tenantJpqlExpression;
        private Function<E, String> entityTenantExtractor;
        private BiPredicate<E, AuthzCallerContext> entityScopePredicate;
        private Function<E, Map<String, Object>> targetFactExtractor;
        private String stateFieldName;
        private Function<E, String> stateExtractor;
        private String cedenteEntityFieldPath;
        private String cedenteSubjectFactKey;
        private BiPredicate<E, AuthzCallerContext> cedenteCustodyPredicate;
        private String cessionarioEntityFieldPath;
        private String cessionarioSubjectFactKey;
        private BiPredicate<E, AuthzCallerContext> cessionarioCustodyPredicate;
        private final Map<String, Set<String>> operationModifiedAttributes = new LinkedHashMap<>();
        private final Map<String, DecisionPointDescriptor> actionDecisionPoints = new LinkedHashMap<>();
        private final Map<String, DecisionPointDescriptor> surfaceDecisionPoints = new LinkedHashMap<>();
        private final Map<String, DeclarativeActionEndpoint> declarativeWorkflowActions = new LinkedHashMap<>();
        private final Map<String, DeclarativeSurfaceEndpoint> declarativeUiSurfaces = new LinkedHashMap<>();

        private record DeclarativeActionEndpoint(
                String actionKey,
                String httpMethod,
                String canonicalPath,
                boolean bulkCollectionScope
        ) {}
        private record DeclarativeSurfaceEndpoint(String surfaceKey, String httpMethod, String canonicalPath) {}

        private Builder(String resourceKey) {
            this.resourceKey = Objects.requireNonNull(resourceKey, "resourceKey is required");
        }

        /**
         * Configures the owning microservice/host {@code serviceKey} (e.g. {@code "praxis-ergon-showcase"}),
         * enabling automatic derivation of {@link FactContract}, {@link QueryableResourceProjection},
         * and {@link DecisionPointDescriptor} when not explicitly supplied ({@code Fase P10.14}).
         */
        public Builder<E> serviceKey(String serviceKey) {
            this.serviceKey = Objects.requireNonNull(serviceKey, "serviceKey is required").trim();
            return this;
        }

        /** Configures the primary operation key for the auto-derived decision point (defaults to {@code "filter"}). */
        public Builder<E> operationKey(String operationKey) {
            this.operationKey = Objects.requireNonNull(operationKey, "operationKey is required").trim();
            return this;
        }

        /** Configures the HTTP method and path for the auto-derived decision point. */
        public Builder<E> httpEndpoint(String httpMethod, String httpPath) {
            this.httpMethod = Objects.requireNonNull(httpMethod, "httpMethod is required").trim();
            this.httpPath = Objects.requireNonNull(httpPath, "httpPath is required").trim();
            return this;
        }

        /** Configures an explicit {@link FactContract} on this spec ({@code Fase P10.14}). */
        public Builder<E> factContract(FactContract factContract) {
            this.factContract = Objects.requireNonNull(factContract, "factContract is required");
            if (this.factContractDigest == null) {
                this.factContractDigest = factContract.factContractDigest();
            }
            return this;
        }

        /**
         * Declaratively registers a scalar queryable field binding (defaulting to {@link FactValueType#INT64},
         * {@code EQ}/{@code IN} operators, {@link RelationTraversalStrategy#INNER_JOIN_SCALAR}, and
         * {@code nullableColumn = true}) and automatically populates both {@link QueryableResourceProjection}
         * and {@link FactContract} when auto-derived ({@code Fase P10.14}).
         */
        public Builder<E> scalarFieldBinding(
                String factPath,
                String attributeId,
                String nativeJpaPath
        ) {
            return scalarFieldBinding(
                    factPath,
                    attributeId,
                    nativeJpaPath,
                    FactValueType.INT64,
                    Set.of(SearchPredicateOperator.EQ, SearchPredicateOperator.IN),
                    true
            );
        }

        /**
         * Declaratively registers a typed scalar queryable field binding and automatically populates
         * both {@link QueryableResourceProjection} and {@link FactContract} when auto-derived
         * ({@code Fase P10.14}).
         */
        public Builder<E> scalarFieldBinding(
                String factPath,
                String attributeId,
                String nativeJpaPath,
                FactValueType valueType,
                Set<SearchPredicateOperator> operators,
                boolean nullableColumn
        ) {
            Objects.requireNonNull(factPath, "factPath is required");
            Objects.requireNonNull(attributeId, "attributeId is required");
            Objects.requireNonNull(nativeJpaPath, "nativeJpaPath is required");
            Objects.requireNonNull(valueType, "valueType is required");
            this.declarativeFieldBindings.add(new QueryAdapterFieldBinding(
                    resourceKey,
                    factPath,
                    attributeId,
                    nativeJpaPath,
                    RelationTraversalStrategy.INNER_JOIN_SCALAR,
                    nullableColumn
            ));
            this.declarativeQueryableFields.put(
                    factPath,
                    new QueryableFieldDescriptor(
                            factPath,
                            attributeId,
                            valueType,
                            operators == null || operators.isEmpty()
                                    ? Set.of(SearchPredicateOperator.EQ, SearchPredicateOperator.IN)
                                    : Set.copyOf(operators),
                            true
                    )
            );
            this.declarativeFacts.putIfAbsent(
                    factPath,
                    new FactDescriptor(
                            factPath,
                            FactSlotNamespace.RESOURCE,
                            valueType,
                            FactCardinality.SCALAR,
                            nullableColumn ? FactPresenceModel.MAY_BE_ABSENT : FactPresenceModel.ALWAYS_PRESENT,
                            attributeId,
                            null,
                            FactResolutionStage.EXTRACT,
                            Set.of(ContextEvaluationPhase.TARGET),
                            true,
                            "INTERNAL",
                            "OPERATIONAL",
                            Set.of(),
                            legalBasis,
                            null
                    )
            );
            return this;
        }

        /**
         * Declaratively registers a {@code 1:N} collection queryable field binding using
         * {@link RelationTraversalStrategy#CORRELATED_EXISTS_SUBQUERY} ({@code Fase P10.14}).
         */
        public Builder<E> collectionFieldBinding(
                String factPath,
                String attributeId,
                String nativeJpaPath,
                FactValueType valueType,
                Set<SearchPredicateOperator> operators,
                boolean nullableColumn
        ) {
            Objects.requireNonNull(factPath, "factPath is required");
            Objects.requireNonNull(attributeId, "attributeId is required");
            Objects.requireNonNull(nativeJpaPath, "nativeJpaPath is required");
            Objects.requireNonNull(valueType, "valueType is required");
            this.declarativeFieldBindings.add(new QueryAdapterFieldBinding(
                    resourceKey,
                    factPath,
                    attributeId,
                    nativeJpaPath,
                    RelationTraversalStrategy.CORRELATED_EXISTS_SUBQUERY,
                    nullableColumn
            ));
            this.declarativeQueryableFields.put(
                    factPath,
                    new QueryableFieldDescriptor(
                            factPath,
                            attributeId,
                            valueType,
                            operators == null || operators.isEmpty()
                                    ? Set.of(SearchPredicateOperator.EQ, SearchPredicateOperator.IN)
                                    : Set.copyOf(operators),
                            true
                    )
            );
            this.declarativeFacts.putIfAbsent(
                    factPath,
                    new FactDescriptor(
                            factPath,
                            FactSlotNamespace.RESOURCE,
                            valueType,
                            FactCardinality.SET,
                            FactPresenceModel.MAY_BE_ABSENT,
                            attributeId,
                            null,
                            FactResolutionStage.EXTRACT,
                            Set.of(ContextEvaluationPhase.TARGET),
                            true,
                            "INTERNAL",
                            "OPERATIONAL",
                            Set.of(),
                            legalBasis,
                            null
                    )
            );
            return this;
        }

        /**
         * Registers a custom {@link FactDescriptor} for the auto-derived {@link FactContract}
         * ({@code Fase P10.14}).
         */
        public Builder<E> factDescriptor(FactDescriptor descriptor) {
            Objects.requireNonNull(descriptor, "descriptor is required");
            this.declarativeFacts.put(descriptor.factPath(), descriptor);
            return this;
        }

        /**
         * Registers a sensitive {@code resource.*} fact descriptor (e.g. {@code LGPD_SENSITIVE_DATA}
         * health/PII attribute) for the auto-derived {@link FactContract} ({@code Fase P10.14}).
         */
        public Builder<E> resourceSensitiveFact(
                String factPath,
                String attributeId,
                FactValueType valueType,
                String complianceTag,
                String specificLegalBasis
        ) {
            Objects.requireNonNull(factPath, "factPath is required");
            Objects.requireNonNull(attributeId, "attributeId is required");
            Objects.requireNonNull(valueType, "valueType is required");
            this.declarativeFacts.put(
                    factPath,
                    new FactDescriptor(
                            factPath,
                            FactSlotNamespace.RESOURCE,
                            valueType,
                            FactCardinality.SCALAR,
                            FactPresenceModel.MAY_BE_ABSENT,
                            attributeId,
                            null,
                            FactResolutionStage.EXTRACT,
                            Set.of(ContextEvaluationPhase.TARGET),
                            true,
                            "RESTRICTED",
                            "SENSITIVE_PERSONAL",
                            complianceTag != null && !complianceTag.isBlank() ? Set.of(complianceTag) : Set.of("LGPD_SENSITIVE"),
                            specificLegalBasis != null && !specificLegalBasis.isBlank() ? specificLegalBasis : legalBasis,
                            null
                    )
            );
            return this;
        }

        public Builder<E> decisionPoint(DecisionPointDescriptor decisionPoint) {
            this.decisionPoint = Objects.requireNonNull(decisionPoint, "decisionPoint is required");
            return this;
        }

        public Builder<E> factContractDigest(String factContractDigest) {
            this.factContractDigest = Objects.requireNonNull(factContractDigest, "factContractDigest is required");
            return this;
        }

        public Builder<E> queryAdapter(
                QueryableResourceProjection queryProjection,
                List<QueryAdapterFieldBinding> fieldBindings
        ) {
            this.queryProjection = Objects.requireNonNull(queryProjection, "queryProjection is required");
            this.fieldBindings = List.copyOf(Objects.requireNonNull(fieldBindings, "fieldBindings is required"));
            return this;
        }

        public Builder<E> dualScopeDelegationSpec(DualScopeDelegationSpec dualScopeDelegationSpec) {
            this.dualScopeDelegationSpec = dualScopeDelegationSpec;
            return this;
        }

        public Builder<E> mandatoryScopeAnchorAttributeIds(Set<String> anchorAttributeIds) {
            this.mandatoryScopeAnchorAttributeIds.clear();
            if (anchorAttributeIds != null) {
                this.mandatoryScopeAnchorAttributeIds.addAll(anchorAttributeIds);
            }
            return this;
        }

        public Builder<E> technicalConcurrencyPointers(Set<String> pointers) {
            this.technicalConcurrencyPointers.clear();
            if (pointers != null) {
                this.technicalConcurrencyPointers.addAll(pointers);
            }
            return this;
        }

        /**
         * Configures the tenant hard-scope field name; single-item entity verification will
         * automatically evaluate both tenant equality and the active OPA {@link DataScopePlan}
         * ({@code P10.8-R03}).
         */
        public Builder<E> tenantField(String tenantFieldName) {
            return tenantField(tenantFieldName, null, null);
        }

        /**
         * Configures the tenant hard-scope field name and explicit extractor; single-item entity
         * verification will automatically evaluate both tenant equality and the active OPA
         * {@link DataScopePlan} ({@code P10.8-R03}).
         */
        public Builder<E> tenantField(
                String tenantFieldName,
                Function<E, String> entityTenantExtractor
        ) {
            return tenantField(tenantFieldName, entityTenantExtractor, null);
        }

        /**
         * Configures the tenant hard-scope field name, optional extractor, and optional additional
         * host scope predicate.
         */
        public Builder<E> tenantField(
                String tenantFieldName,
                Function<E, String> entityTenantExtractor,
                BiPredicate<E, AuthzCallerContext> entityScopePredicate
        ) {
            this.tenantFieldName = Objects.requireNonNull(tenantFieldName, "tenantFieldName is required");
            this.entityTenantExtractor = entityTenantExtractor;
            this.entityScopePredicate = entityScopePredicate;
            return this;
        }

        public Builder<E> tenantJpqlExpression(String tenantJpqlExpression) {
            this.tenantJpqlExpression = Objects.requireNonNull(tenantJpqlExpression, "tenantJpqlExpression is required");
            return this;
        }

        /**
         * Configures an optional additional extractor for {@code resource.*} target facts beyond
         * those automatically derived from {@code fieldBindings} ({@code Fase P10.9}).
         */
        public Builder<E> targetFactExtractor(Function<E, Map<String, Object>> targetFactExtractor) {
            this.targetFactExtractor = targetFactExtractor;
            return this;
        }

        /**
         * Configures the entity field path holding the resource's lifecycle/workflow state (e.g.
         * {@code "statusAfastamento"}) used to populate {@link ResourceStateSnapshot#state()}
         * ({@code Fase P10.9}).
         */
        public Builder<E> stateField(String stateFieldName) {
            this.stateFieldName = Objects.requireNonNull(stateFieldName, "stateFieldName is required");
            return this;
        }

        /**
         * Configures a custom extractor for the resource's lifecycle/workflow state used to
         * populate {@link ResourceStateSnapshot#state()} ({@code Fase P10.9}).
         */
        public Builder<E> stateExtractor(Function<E, String> stateExtractor) {
            this.stateExtractor = Objects.requireNonNull(stateExtractor, "stateExtractor is required");
            return this;
        }

        /**
         * Declaratively binds {@code Cedente} custody evaluation to an entity field (e.g.
         * {@code "cedenteOrgaoId"}) matched against a caller subject fact (e.g.
         * {@code "subject.cedenteOrgaoIds"}) ({@code Fase P10.9}).
         */
        public Builder<E> cedenteCustody(String entityFieldPath, String subjectFactKey) {
            this.cedenteEntityFieldPath = Objects.requireNonNull(entityFieldPath, "entityFieldPath is required");
            this.cedenteSubjectFactKey = Objects.requireNonNull(subjectFactKey, "subjectFactKey is required");
            return this;
        }

        /**
         * Configures a custom predicate for evaluating {@code Cedente} custody on an entity.
         */
        public Builder<E> cedenteCustodyPredicate(BiPredicate<E, AuthzCallerContext> cedenteCustodyPredicate) {
            this.cedenteCustodyPredicate = Objects.requireNonNull(cedenteCustodyPredicate, "cedenteCustodyPredicate is required");
            return this;
        }

        /**
         * Declaratively binds {@code Cessionário} custody evaluation to an entity field (e.g.
         * {@code "cessionarioOrgaoId"}) matched against a caller subject fact (e.g.
         * {@code "subject.cessionarioOrgaoIds"}) ({@code Fase P10.9}).
         */
        public Builder<E> cessionarioCustody(String entityFieldPath, String subjectFactKey) {
            this.cessionarioEntityFieldPath = Objects.requireNonNull(entityFieldPath, "entityFieldPath is required");
            this.cessionarioSubjectFactKey = Objects.requireNonNull(subjectFactKey, "subjectFactKey is required");
            return this;
        }

        /**
         * Configures a custom predicate for evaluating {@code Cessionário} custody on an entity.
         */
        public Builder<E> cessionarioCustodyPredicate(BiPredicate<E, AuthzCallerContext> cessionarioCustodyPredicate) {
            this.cessionarioCustodyPredicate = Objects.requireNonNull(cessionarioCustodyPredicate, "cessionarioCustodyPredicate is required");
            return this;
        }

        /**
         * Registers the canonical {@code attributeId}s modified by an operation/workflow action
         * for contextual availability discovery and command pre-checks ({@code Fase P10.9}).
         */
        public Builder<E> operationModifiedAttributes(String operationId, Set<String> modifiedAttributeIds) {
            this.operationModifiedAttributes.put(
                    Objects.requireNonNull(operationId, "operationId is required"),
                    Set.copyOf(Objects.requireNonNull(modifiedAttributeIds, "modifiedAttributeIds is required"))
            );
            return this;
        }

        /**
         * Registers a map of operation/workflow action IDs to their modified canonical
         * {@code attributeId}s ({@code Fase P10.9}).
         */
        public Builder<E> operationModifiedAttributes(Map<String, Set<String>> operationModifiedAttributes) {
            this.operationModifiedAttributes.clear();
            if (operationModifiedAttributes != null) {
                for (Map.Entry<String, Set<String>> e : operationModifiedAttributes.entrySet()) {
                    this.operationModifiedAttributes.put(e.getKey(), Set.copyOf(e.getValue()));
                }
            }
            return this;
        }

        public Builder<E> actionDecisionPoint(String actionId, DecisionPointDescriptor decisionPoint) {
            this.actionDecisionPoints.put(
                    Objects.requireNonNull(actionId, "actionId is required"),
                    Objects.requireNonNull(decisionPoint, "decisionPoint is required")
            );
            return this;
        }

        public Builder<E> surfaceDecisionPoint(String surfaceId, DecisionPointDescriptor decisionPoint) {
            this.surfaceDecisionPoints.put(
                    Objects.requireNonNull(surfaceId, "surfaceId is required"),
                    Objects.requireNonNull(decisionPoint, "decisionPoint is required")
            );
            return this;
        }

        /**
         * Declaratively registers a governed {@code @WorkflowAction} and its modified target
         * {@code attributeId}s, automatically synthesizing a canonical {@link DecisionPointDescriptor}
         * (with {@code ACCESS} + {@code FIELD_WRITE} capabilities) and registering
         * {@link #operationModifiedAttributes(String, Set)} during {@link #build()} ({@code Fase P10.15-R03}).
         */
        public Builder<E> workflowAction(String actionKey, Set<String> modifiedAttributeIds) {
            return workflowAction(actionKey, "POST", null, modifiedAttributeIds);
        }

        /**
         * Declaratively registers a governed {@code @WorkflowAction} with an explicit HTTP method/path
         * and modified target {@code attributeId}s, automatically synthesizing its
         * {@link DecisionPointDescriptor} during {@link #build()} ({@code Fase P10.15-R03}).
         */
        public Builder<E> workflowAction(
                String actionKey,
                String httpMethod,
                String canonicalPath,
                Set<String> modifiedAttributeIds
        ) {
            String key = Objects.requireNonNull(actionKey, "actionKey is required").trim();
            String method = (httpMethod == null || httpMethod.isBlank()) ? "POST" : httpMethod.trim();
            String path = (canonicalPath == null || canonicalPath.isBlank()) ? null : canonicalPath.trim();
            this.declarativeWorkflowActions.put(key, new DeclarativeActionEndpoint(key, method, path, false));
            if (modifiedAttributeIds != null && !modifiedAttributeIds.isEmpty()) {
                this.operationModifiedAttributes.put(key, Set.copyOf(modifiedAttributeIds));
            }
            return this;
        }

        /**
         * Declaratively registers a governed collection-scoped bulk {@code @WorkflowAction(scope = ActionScope.COLLECTION)}
         * ({@code BulkMode.DOMAIN_COMMAND}) and its modified target {@code attributeId}s, automatically
         * synthesizing a canonical {@link DecisionPointDescriptor} with {@code SEARCH} + {@code TARGET}
         * evaluation modes and {@code ACCESS} + {@code DATA_SCOPE} + {@code FIELD_WRITE} capabilities
         * during {@link #build()} ({@code Fase P10.16-A}).
         */
        public Builder<E> bulkWorkflowAction(String actionKey, Set<String> modifiedAttributeIds) {
            return bulkWorkflowAction(actionKey, "POST", null, modifiedAttributeIds);
        }

        /**
         * Declaratively registers a governed collection-scoped bulk {@code @WorkflowAction(scope = ActionScope.COLLECTION)}
         * ({@code BulkMode.DOMAIN_COMMAND}) with an explicit HTTP method/path and modified target
         * {@code attributeId}s ({@code Fase P10.16-A}).
         */
        public Builder<E> bulkWorkflowAction(
                String actionKey,
                String httpMethod,
                String canonicalPath,
                Set<String> modifiedAttributeIds
        ) {
            String key = Objects.requireNonNull(actionKey, "actionKey is required").trim();
            String method = (httpMethod == null || httpMethod.isBlank()) ? "POST" : httpMethod.trim();
            String path = (canonicalPath == null || canonicalPath.isBlank()) ? null : canonicalPath.trim();
            this.declarativeWorkflowActions.put(key, new DeclarativeActionEndpoint(key, method, path, true));
            if (modifiedAttributeIds != null && !modifiedAttributeIds.isEmpty()) {
                this.operationModifiedAttributes.put(key, Set.copyOf(modifiedAttributeIds));
            }
            return this;
        }

        /**
         * Declaratively registers a governed {@code @UiSurface} (read projection or 360° drawer),
         * automatically synthesizing a canonical {@link DecisionPointDescriptor} (with {@code ACCESS},
         * {@code MASK}, and {@code FIELD_USE} capabilities) during {@link #build()} ({@code Fase P10.15-R03}).
         */
        public Builder<E> uiSurface(String surfaceKey) {
            return uiSurface(surfaceKey, "GET", null);
        }

        /**
         * Declaratively registers a governed {@code @UiSurface} with an explicit HTTP method/path,
         * automatically synthesizing its {@link DecisionPointDescriptor} during {@link #build()}
         * ({@code Fase P10.15-R03}).
         */
        public Builder<E> uiSurface(String surfaceKey, String httpMethod, String canonicalPath) {
            String key = Objects.requireNonNull(surfaceKey, "surfaceKey is required").trim();
            String method = (httpMethod == null || httpMethod.isBlank()) ? "GET" : httpMethod.trim();
            String path = (canonicalPath == null || canonicalPath.isBlank()) ? null : canonicalPath.trim();
            this.declarativeUiSurfaces.put(key, new DeclarativeSurfaceEndpoint(key, method, path));
            return this;
        }

        /**
         * Introspects a Praxis resource's JPA entity, {@code ResponseDTO}, {@code FilterDTO}, and
         * {@code Controller} classes ({@code PLAT-EVO-10}) to automatically register:
         * <ul>
         *   <li>Base HTTP endpoint path from {@link ApiResource} / {@link RequestMapping};</li>
         *   <li>Item and collection {@link WorkflowAction} decision points ({@link ActionScope#ITEM} and {@link ActionScope#COLLECTION});</li>
         *   <li>Class-level and method-level {@link UiSurface} decision points;</li>
         *   <li>Scalar and {@code 1:N} queryable entity field bindings ({@link Filterable} relations + JPA scalar columns);</li>
         *   <li>Sensitive {@code resource.*} facts from {@code @DomainGovernance} on {@code responseDtoClass};</li>
         *   <li>Optimistic concurrency {@code @Version} pointer and typed tenant hard-scope metadata.</li>
         * </ul>
         *
         * @param entityClass JPA entity class
         * @param responseDtoClass optional {@code ResponseDTO} class
         * @param filterDtoClass optional {@code FilterDTO} class
         * @param controllerClass optional {@code Controller} class
         * @return this builder
         */
        public Builder<E> introspectFromResource(
                Class<E> entityClass,
                Class<?> responseDtoClass,
                Class<?> filterDtoClass,
                Class<?> controllerClass
        ) {
            Objects.requireNonNull(entityClass, "entityClass is required");
            if (controllerClass != null) {
                introspectControllerEndpoints(controllerClass);
            }

            MetadataDtoGovernanceIntrospector introspector = new MetadataDtoGovernanceIntrospector();
            MetadataDtoGovernanceIntrospector.IntrospectedDtoGovernanceContract dtoContract = null;
            Map<String, DtoFieldSchemaMetadata> dtoSchemasByField = new LinkedHashMap<>();
            List<FieldLineageCatalogEntry> responseLineage = List.of();
            if (responseDtoClass != null && responseDtoClass != Object.class && !Map.class.isAssignableFrom(responseDtoClass)) {
                dtoContract = introspector.introspect(responseDtoClass, this.resourceKey);
                for (DtoFieldSchemaMetadata schemaMeta : dtoContract.fieldSchemas()) {
                    dtoSchemasByField.put(schemaMeta.wireFieldName(), schemaMeta);
                }
                responseLineage = introspector.deriveDtoFieldLineageCatalogEntries(
                        this.resourceKey, responseDtoClass, "READ_PROJECTION", null);
            }

            Set<String> filterPaths = collectFilterPaths(filterDtoClass);
            introspectEntityFields(entityClass, dtoContract, filterPaths);
            registerSensitiveDtoFacts(responseLineage, dtoSchemasByField);
            return this;
        }

        private void introspectControllerEndpoints(Class<?> controllerClass) {
            String basePath = resolveControllerBasePath(controllerClass);
            if (this.httpPath == null && basePath != null) {
                this.httpPath = joinHttpPaths(basePath, this.operationKey);
            }

            for (UiSurface classSurface : AnnotatedElementUtils.findAllMergedAnnotations(controllerClass, UiSurface.class)) {
                if (classSurface.id() != null && !classSurface.id().isBlank()) {
                    String surfId = classSurface.id().trim();
                    if (!this.declarativeUiSurfaces.containsKey(surfId)) {
                        String fallbackPath = basePath != null ? joinHttpPaths(basePath, "{id}/surfaces/" + surfId) : null;
                        uiSurface(surfId, "GET", fallbackPath);
                    }
                }
            }

            List<Method> methods = collectSortedHierarchyMethods(controllerClass);
            for (Method method : methods) {
                RequestMapping rm = AnnotatedElementUtils.findMergedAnnotation(method, RequestMapping.class);
                WorkflowAction wf = AnnotatedElementUtils.findMergedAnnotation(method, WorkflowAction.class);
                if (wf != null && wf.id() != null && !wf.id().isBlank()) {
                    String actionId = wf.id().trim();
                    if (!this.declarativeWorkflowActions.containsKey(actionId)) {
                        String actMethod = extractHttpMethod(rm, "POST");
                        String actSubPath = extractFirstPath(rm);
                        String actFullPath = rm != null ? joinHttpPaths(basePath, actSubPath) : null;
                        Set<String> modified = this.operationModifiedAttributes.getOrDefault(actionId, Set.of());
                        if (wf.scope() == ActionScope.COLLECTION) {
                            bulkWorkflowAction(actionId, actMethod, actFullPath, modified);
                        } else {
                            workflowAction(actionId, actMethod, actFullPath, modified);
                        }
                    }
                }

                for (UiSurface methodSurface : AnnotatedElementUtils.findAllMergedAnnotations(method, UiSurface.class)) {
                    if (methodSurface.id() != null && !methodSurface.id().isBlank()) {
                        String surfId = methodSurface.id().trim();
                        if (!this.declarativeUiSurfaces.containsKey(surfId)) {
                            String surfMethod = extractHttpMethod(rm, "GET");
                            String surfSubPath = extractFirstPath(rm);
                            String surfFullPath = rm != null ? joinHttpPaths(basePath, surfSubPath) : null;
                            uiSurface(surfId, surfMethod, surfFullPath);
                        }
                    }
                }
            }
        }

        private void introspectEntityFields(
                Class<E> entityClass,
                MetadataDtoGovernanceIntrospector.IntrospectedDtoGovernanceContract dtoContract,
                Set<String> filterPaths
        ) {
            Field tenantField = resolveNestedScalarField(entityClass, this.tenantFieldName);
            if (tenantField != null) {
                this.tenantJavaType = tenantField.getType();
            }

            Set<String> registeredFactPaths = new LinkedHashSet<>();
            for (QueryAdapterFieldBinding existing : this.declarativeFieldBindings) {
                registeredFactPaths.add(existing.fieldPath());
            }

            for (Field field : collectEntityHierarchyFields(entityClass)) {
                if (field.isAnnotationPresent(Transient.class)) {
                    continue;
                }
                if (field.isAnnotationPresent(Version.class)) {
                    this.technicalConcurrencyPointers.add("/" + field.getName());
                    continue;
                }
                if (isEntityAssociationField(field)) {
                    continue;
                }
                FactValueType valueType = resolveEntityScalarValueType(field.getType());
                if (valueType == null) {
                    continue;
                }
                String fieldName = field.getName();
                String factPath = "resource." + fieldName;
                if (registeredFactPaths.add(factPath)) {
                    String attributeId = resolveAttributeIdForPath(fieldName, dtoContract);
                    boolean nullable = isNullableEntityField(field);
                    scalarFieldBinding(
                            factPath,
                            attributeId,
                            fieldName,
                            valueType,
                            defaultOperatorsForValueType(valueType),
                            nullable
                    );
                    if (fieldName.equals(this.tenantFieldName)) {
                        this.mandatoryScopeAnchorAttributeIds.add(attributeId);
                    }
                }
            }

            for (String candidatePath : filterPaths) {
                if (candidatePath == null || candidatePath.isBlank() || !candidatePath.contains(".")) {
                    continue;
                }
                ResolvedEntityPath resolved = resolveEntityDotPath(entityClass, candidatePath.trim());
                if (resolved == null) {
                    continue;
                }
                String factPath = "resource." + candidatePath.trim().replace('.', '_');
                if (!registeredFactPaths.add(factPath)) {
                    continue;
                }
                String attributeId = resolveAttributeIdForPath(candidatePath.trim(), dtoContract);
                Set<SearchPredicateOperator> operators = defaultOperatorsForValueType(resolved.valueType());
                if (resolved.collectionTraversal()) {
                    collectionFieldBinding(factPath, attributeId, candidatePath.trim(), resolved.valueType(), operators, true);
                } else {
                    scalarFieldBinding(factPath, attributeId, candidatePath.trim(), resolved.valueType(), operators, resolved.nullable());
                    if (candidatePath.trim().equals(this.tenantFieldName)) {
                        this.mandatoryScopeAnchorAttributeIds.add(attributeId);
                    }
                }
            }
        }

        private void registerSensitiveDtoFacts(
                List<FieldLineageCatalogEntry> responseLineage,
                Map<String, DtoFieldSchemaMetadata> dtoSchemasByField
        ) {
            for (FieldLineageCatalogEntry entry : responseLineage) {
                String classification = entry.sensitivityClassification();
                if ("SENSITIVE_PERSONAL".equals(classification)
                        || "SECRET".equals(classification)
                        || "PII_RESTRICTED".equals(classification)
                        || "FINANCIAL_RESTRICTED".equals(classification)
                        || "RESTRICTED".equals(classification)) {
                    DtoFieldSchemaMetadata schemaMeta = dtoSchemasByField.get(entry.wirePath());
                    FactValueType valueType = schemaMeta != null ? schemaMeta.valueType() : FactValueType.STRING;
                    resourceSensitiveFact(
                            "resource." + entry.wirePath(),
                            entry.attributeId(),
                            valueType,
                            classification,
                            this.legalBasis
                    );
                }
            }
        }

        private String resolveAttributeIdForPath(
                String path,
                MetadataDtoGovernanceIntrospector.IntrospectedDtoGovernanceContract dtoContract
        ) {
            if (dtoContract != null) {
                String direct = dtoContract.wirePointerToAttributeIdMap().get("/" + path);
                if (direct != null) {
                    return direct;
                }
            }
            String normalizedResource = this.resourceKey.replace('-', '_');
            return normalizedResource + "." + camelToSnakeIdentifier(path.replace('.', '_'));
        }

        private record ResolvedEntityPath(FactValueType valueType, boolean collectionTraversal, boolean nullable) {}

        private static ResolvedEntityPath resolveEntityDotPath(Class<?> rootClass, String dotPath) {
            String[] segments = dotPath.split("\\.");
            Class<?> currentType = rootClass;
            boolean collectionTraversal = false;
            boolean nullable = false;
            for (int i = 0; i < segments.length; i++) {
                Field field = findFieldInHierarchy(currentType, segments[i]);
                if (field == null || field.isAnnotationPresent(Transient.class)) {
                    return null;
                }
                nullable = nullable || isNullableEntityField(field);
                boolean isLast = (i == segments.length - 1);
                if (isLast) {
                    FactValueType vt = resolveEntityScalarValueType(field.getType());
                    return vt != null ? new ResolvedEntityPath(vt, collectionTraversal, nullable) : null;
                }
                if (Collection.class.isAssignableFrom(field.getType())) {
                    if (collectionTraversal || i != segments.length - 2) {
                        return null;
                    }
                    Class<?> elemType = resolveCollectionElementType(field);
                    if (elemType == null) {
                        return null;
                    }
                    collectionTraversal = true;
                    currentType = elemType;
                } else if (Map.class.isAssignableFrom(field.getType()) || field.getType().isArray()) {
                    return null;
                } else {
                    currentType = field.getType();
                }
            }
            return null;
        }

        private static Field resolveNestedScalarField(Class<?> rootClass, String dotPath) {
            if (dotPath == null || dotPath.isBlank()) {
                return null;
            }
            String[] segments = dotPath.trim().split("\\.");
            Class<?> currentType = rootClass;
            Field field = null;
            for (int i = 0; i < segments.length; i++) {
                field = findFieldInHierarchy(currentType, segments[i]);
                if (field == null) {
                    return null;
                }
                if (i < segments.length - 1) {
                    currentType = field.getType();
                }
            }
            return field;
        }

        private static Class<?> resolveCollectionElementType(Field field) {
            Type genericType = field.getGenericType();
            if (genericType instanceof ParameterizedType pt && pt.getActualTypeArguments().length == 1) {
                Type arg = pt.getActualTypeArguments()[0];
                if (arg instanceof Class<?> clazz) {
                    return clazz;
                }
            }
            return null;
        }

        private static List<Field> collectEntityHierarchyFields(Class<?> entityClass) {
            List<Class<?>> hierarchy = new ArrayList<>();
            for (Class<?> curr = entityClass; curr != null && curr != Object.class; curr = curr.getSuperclass()) {
                hierarchy.add(curr);
            }
            Collections.reverse(hierarchy);
            Map<String, Field> byName = new LinkedHashMap<>();
            for (Class<?> curr : hierarchy) {
                for (Field f : curr.getDeclaredFields()) {
                    if (!Modifier.isStatic(f.getModifiers()) && !f.isSynthetic()) {
                        byName.put(f.getName(), f);
                    }
                }
            }
            return List.copyOf(byName.values());
        }

        private static Field findFieldInHierarchy(Class<?> type, String fieldName) {
            for (Class<?> curr = type; curr != null && curr != Object.class; curr = curr.getSuperclass()) {
                try {
                    Field f = curr.getDeclaredField(fieldName);
                    if (!Modifier.isStatic(f.getModifiers()) && !f.isSynthetic()) {
                        return f;
                    }
                } catch (NoSuchFieldException ignored) {
                    // inspect superclass
                }
            }
            return null;
        }

        private static boolean isEntityAssociationField(Field field) {
            return field.isAnnotationPresent(ManyToOne.class)
                    || field.isAnnotationPresent(OneToOne.class)
                    || field.isAnnotationPresent(OneToMany.class)
                    || field.isAnnotationPresent(ManyToMany.class)
                    || field.isAnnotationPresent(Embedded.class);
        }

        private static boolean isNullableEntityField(Field field) {
            if (field.getType().isPrimitive()
                    || field.isAnnotationPresent(Id.class)
                    || field.isAnnotationPresent(NotNull.class)
                    || field.isAnnotationPresent(NotBlank.class)
                    || field.isAnnotationPresent(NotEmpty.class)) {
                return false;
            }
            ManyToOne manyToOne = field.getAnnotation(ManyToOne.class);
            if (manyToOne != null && !manyToOne.optional()) {
                return false;
            }
            OneToOne oneToOne = field.getAnnotation(OneToOne.class);
            if (oneToOne != null && !oneToOne.optional()) {
                return false;
            }
            jakarta.persistence.JoinColumn joinColumn = field.getAnnotation(jakarta.persistence.JoinColumn.class);
            if (joinColumn != null && !joinColumn.nullable()) {
                return false;
            }
            Column column = field.getAnnotation(Column.class);
            return column == null || column.nullable();
        }

        private static FactValueType resolveEntityScalarValueType(Class<?> javaType) {
            if (javaType == boolean.class || javaType == Boolean.class) {
                return FactValueType.BOOLEAN;
            }
            if (javaType == int.class || javaType == Integer.class
                    || javaType == long.class || javaType == Long.class
                    || javaType == short.class || javaType == Short.class
                    || javaType == byte.class || javaType == Byte.class
                    || javaType == BigInteger.class) {
                return FactValueType.INT64;
            }
            if (javaType == double.class || javaType == Double.class
                    || javaType == float.class || javaType == Float.class
                    || javaType == BigDecimal.class) {
                return FactValueType.DECIMAL;
            }
            if (javaType == LocalDate.class) {
                return FactValueType.LOCAL_DATE;
            }
            if (javaType == Instant.class || javaType == LocalDateTime.class
                    || javaType == OffsetDateTime.class || javaType == ZonedDateTime.class) {
                return FactValueType.INSTANT;
            }
            if (javaType.isEnum()) {
                return FactValueType.ENUM;
            }
            if (javaType == String.class || javaType == UUID.class) {
                return FactValueType.STRING;
            }
            return null;
        }

        private static Set<SearchPredicateOperator> defaultOperatorsForValueType(FactValueType valueType) {
            return switch (valueType) {
                case BOOLEAN -> Set.of(
                        SearchPredicateOperator.EQ,
                        SearchPredicateOperator.NE,
                        SearchPredicateOperator.IS_NULL,
                        SearchPredicateOperator.IS_NOT_NULL
                );
                case INT64, DECIMAL, LOCAL_DATE, INSTANT -> Set.of(
                        SearchPredicateOperator.EQ,
                        SearchPredicateOperator.NE,
                        SearchPredicateOperator.IN,
                        SearchPredicateOperator.NIN,
                        SearchPredicateOperator.GT,
                        SearchPredicateOperator.GTE,
                        SearchPredicateOperator.LT,
                        SearchPredicateOperator.LTE,
                        SearchPredicateOperator.IS_NULL,
                        SearchPredicateOperator.IS_NOT_NULL
                );
                case ENUM -> Set.of(
                        SearchPredicateOperator.EQ,
                        SearchPredicateOperator.NE,
                        SearchPredicateOperator.IN,
                        SearchPredicateOperator.NIN,
                        SearchPredicateOperator.IS_NULL,
                        SearchPredicateOperator.IS_NOT_NULL
                );
                case STRING -> Set.of(
                        SearchPredicateOperator.EQ,
                        SearchPredicateOperator.NE,
                        SearchPredicateOperator.IN,
                        SearchPredicateOperator.NIN,
                        SearchPredicateOperator.TEXT_CONTAINS,
                        SearchPredicateOperator.STARTS_WITH,
                        SearchPredicateOperator.ENDS_WITH,
                        SearchPredicateOperator.IS_NULL,
                        SearchPredicateOperator.IS_NOT_NULL
                );
                default -> Set.of(SearchPredicateOperator.EQ, SearchPredicateOperator.IN);
            };
        }

        private static Set<String> collectFilterPaths(Class<?> filterDtoClass) {
            if (filterDtoClass == null || filterDtoClass == Object.class) {
                return Set.of();
            }
            Set<String> paths = new LinkedHashSet<>();
            if (filterDtoClass.isRecord()) {
                for (RecordComponent rc : filterDtoClass.getRecordComponents()) {
                    extractFilterablePathsFromElement(rc, rc.getName(), paths);
                    if (rc.getAccessor() != null) {
                        extractFilterablePathsFromElement(rc.getAccessor(), rc.getName(), paths);
                    }
                }
            }
            for (Class<?> curr = filterDtoClass; curr != null && curr != Object.class; curr = curr.getSuperclass()) {
                for (Field f : curr.getDeclaredFields()) {
                    if (!Modifier.isStatic(f.getModifiers()) && !f.isSynthetic()) {
                        extractFilterablePathsFromElement(f, f.getName(), paths);
                    }
                }
                for (Method m : curr.getDeclaredMethods()) {
                    if (m.getParameterCount() == 0 && !Modifier.isStatic(m.getModifiers()) && m.getReturnType() != void.class) {
                        String prop = extractGetterProperty(m);
                        if (prop != null) {
                            extractFilterablePathsFromElement(m, prop, paths);
                        }
                    }
                }
            }
            return Set.copyOf(paths);
        }

        private static void extractFilterablePathsFromElement(
                AnnotatedElement element,
                String defaultPropName,
                Set<String> target
        ) {
            Filterable filterable = AnnotatedElementUtils.findMergedAnnotation(element, Filterable.class);
            if (filterable == null) {
                return;
            }
            boolean explicit = false;
            if (filterable.relations() != null && filterable.relations().length > 0) {
                for (String rel : filterable.relations()) {
                    if (rel != null && !rel.isBlank()) {
                        target.add(rel.trim());
                        explicit = true;
                    }
                }
            }
            if (filterable.relation() != null && !filterable.relation().isBlank()) {
                target.add(filterable.relation().trim());
                explicit = true;
            }
            if (!explicit && defaultPropName != null && !defaultPropName.isBlank()) {
                target.add(defaultPropName.trim());
            }
        }

        private static String extractGetterProperty(Method m) {
            String name = m.getName();
            if ("getClass".equals(name)) {
                return null;
            }
            if (name.startsWith("get") && name.length() > 3 && Character.isUpperCase(name.charAt(3))) {
                return Introspector.decapitalize(name.substring(3));
            }
            if (name.startsWith("is") && name.length() > 2 && Character.isUpperCase(name.charAt(2))) {
                return Introspector.decapitalize(name.substring(2));
            }
            return null;
        }

        private static String resolveControllerBasePath(Class<?> controllerClass) {
            ApiResource apiResource = AnnotatedElementUtils.findMergedAnnotation(controllerClass, ApiResource.class);
            if (apiResource != null) {
                String p = firstNonBlank(apiResource.path());
                if (p == null) {
                    p = firstNonBlank(apiResource.value());
                }
                if (p != null) {
                    return normalizeHttpBasePath(p);
                }
            }
            RequestMapping rm = AnnotatedElementUtils.findMergedAnnotation(controllerClass, RequestMapping.class);
            String p = extractFirstPath(rm);
            return p != null ? normalizeHttpBasePath(p) : null;
        }

        private static String extractHttpMethod(RequestMapping rm, String fallback) {
            if (rm != null && rm.method() != null && rm.method().length > 0) {
                RequestMethod first = rm.method()[0];
                if (first != null) {
                    return first.name();
                }
            }
            return fallback;
        }

        private static String extractFirstPath(RequestMapping rm) {
            if (rm == null) {
                return null;
            }
            String p = firstNonBlank(rm.path());
            return p != null ? p : firstNonBlank(rm.value());
        }

        private static String firstNonBlank(String[] values) {
            if (values == null) {
                return null;
            }
            for (String v : values) {
                if (v != null && !v.isBlank()) {
                    return v.trim();
                }
            }
            return null;
        }

        private static String normalizeHttpBasePath(String path) {
            String clean = path.trim();
            if (!clean.startsWith("/")) {
                clean = "/" + clean;
            }
            while (clean.length() > 1 && clean.endsWith("/")) {
                clean = clean.substring(0, clean.length() - 1);
            }
            return clean;
        }

        private static String joinHttpPaths(String basePath, String subPath) {
            if (basePath == null || basePath.isBlank()) {
                return subPath != null ? normalizeHttpBasePath(subPath) : null;
            }
            if (subPath == null || subPath.isBlank()) {
                return normalizeHttpBasePath(basePath);
            }
            String base = normalizeHttpBasePath(basePath);
            String sub = subPath.trim();
            if (sub.startsWith("/")) {
                sub = sub.substring(1);
            }
            return sub.isEmpty() ? base : base + "/" + sub;
        }

        private static List<Method> collectSortedHierarchyMethods(Class<?> type) {
            List<Method> methods = new ArrayList<>();
            for (Class<?> curr = type; curr != null && curr != Object.class; curr = curr.getSuperclass()) {
                for (Method m : curr.getDeclaredMethods()) {
                    if (!Modifier.isStatic(m.getModifiers()) && !m.isSynthetic() && !m.isBridge()) {
                        methods.add(m);
                    }
                }
            }
            methods.sort(Comparator.comparing((Method m) -> m.getName() + Arrays.toString(m.getParameterTypes())));
            return methods;
        }

        private static String camelToSnakeIdentifier(String input) {
            StringBuilder sb = new StringBuilder(input.length() + 4);
            for (int i = 0; i < input.length(); i++) {
                char c = input.charAt(i);
                if (Character.isUpperCase(c)) {
                    if (i > 0 && input.charAt(i - 1) != '_') {
                        sb.append('_');
                    }
                    sb.append(Character.toLowerCase(c));
                } else {
                    sb.append(c);
                }
            }
            return sb.toString().toLowerCase(Locale.ROOT);
        }

        public AuthzResourceGovernanceSpec<E> build() {
            if (this.fieldBindings.isEmpty() && !this.declarativeFieldBindings.isEmpty()) {
                this.fieldBindings = List.copyOf(this.declarativeFieldBindings);
            }
            if (this.queryProjection == null && !this.declarativeQueryableFields.isEmpty()) {
                String qpId = "qp-" + resourceKey.replace('.', '-');
                String qpDigest = CanonicalDigestCalculator.computeDigest(
                        DigestDomainKind.DEPENDENCY_MANIFEST_DIGEST,
                        qpId + "|" + this.declarativeQueryableFields.keySet() + "|v1"
                );
                this.queryProjection = new QueryableResourceProjection(
                        QueryableResourceProjection.SCHEMA_VERSION_V1,
                        qpId,
                        resourceKey,
                        qpDigest,
                        Map.copyOf(this.declarativeQueryableFields)
                );
            }
            if (this.factContract == null && this.serviceKey != null && !this.serviceKey.isBlank()) {
                Map<String, FactDescriptor> facts = new LinkedHashMap<>();
                facts.put(
                        "subject.principalId",
                        new FactDescriptor(
                                "subject.principalId",
                                FactSlotNamespace.SUBJECT,
                                FactValueType.STRING,
                                FactCardinality.SCALAR,
                                FactPresenceModel.ALWAYS_PRESENT,
                                null,
                                null,
                                FactResolutionStage.EXTRACT,
                                Set.of(ContextEvaluationPhase.ADMISSION, ContextEvaluationPhase.TARGET),
                                false,
                                "INTERNAL",
                                "OPERATIONAL",
                                Set.of(),
                                legalBasis,
                                null
                        )
                );
                facts.put(
                        "subject.organizationUnitIds",
                        new FactDescriptor(
                                "subject.organizationUnitIds",
                                FactSlotNamespace.SUBJECT,
                                FactValueType.INT64,
                                FactCardinality.SET,
                                FactPresenceModel.ALWAYS_PRESENT,
                                null,
                                null,
                                FactResolutionStage.ENRICH,
                                Set.of(ContextEvaluationPhase.ADMISSION, ContextEvaluationPhase.TARGET),
                                false,
                                "INTERNAL",
                                "OPERATIONAL",
                                Set.of(),
                                legalBasis,
                                null
                        )
                );
                facts.putAll(this.declarativeFacts);
                if (this.cedenteSubjectFactKey != null && this.cedenteSubjectFactKey.startsWith("subject.")) {
                    facts.putIfAbsent(
                            this.cedenteSubjectFactKey,
                            new FactDescriptor(
                                    this.cedenteSubjectFactKey,
                                    FactSlotNamespace.SUBJECT,
                                    FactValueType.INT64,
                                    FactCardinality.SET,
                                    FactPresenceModel.MAY_BE_ABSENT,
                                    null,
                                    null,
                                    FactResolutionStage.ENRICH,
                                    Set.of(ContextEvaluationPhase.ADMISSION, ContextEvaluationPhase.TARGET),
                                    false,
                                    "INTERNAL",
                                    "OPERATIONAL",
                                    Set.of(),
                                    legalBasis,
                                    null
                            )
                    );
                }
                if (this.cessionarioSubjectFactKey != null && this.cessionarioSubjectFactKey.startsWith("subject.")) {
                    facts.putIfAbsent(
                            this.cessionarioSubjectFactKey,
                            new FactDescriptor(
                                    this.cessionarioSubjectFactKey,
                                    FactSlotNamespace.SUBJECT,
                                    FactValueType.INT64,
                                    FactCardinality.SET,
                                    FactPresenceModel.MAY_BE_ABSENT,
                                    null,
                                    null,
                                    FactResolutionStage.ENRICH,
                                    Set.of(ContextEvaluationPhase.ADMISSION, ContextEvaluationPhase.TARGET),
                                    false,
                                    "INTERNAL",
                                    "OPERATIONAL",
                                    Set.of(),
                                    legalBasis,
                                    null
                            )
                    );
                }
                if (this.dualScopeDelegationSpec != null) {
                    String cedFact = this.dualScopeDelegationSpec.cedenteFactPath();
                    if (cedFact != null && cedFact.startsWith("resource.")) {
                        facts.putIfAbsent(
                                cedFact,
                                new FactDescriptor(
                                        cedFact,
                                        FactSlotNamespace.RESOURCE,
                                        FactValueType.INT64,
                                        FactCardinality.SCALAR,
                                        FactPresenceModel.MAY_BE_ABSENT,
                                        null,
                                        null,
                                        FactResolutionStage.EXTRACT,
                                        Set.of(ContextEvaluationPhase.TARGET),
                                        true,
                                        "INTERNAL",
                                        "OPERATIONAL",
                                        Set.of(),
                                        legalBasis,
                                        null
                                )
                        );
                    }
                    String cesFact = this.dualScopeDelegationSpec.cessionarioFactPath();
                    if (cesFact != null && cesFact.startsWith("resource.")) {
                        facts.putIfAbsent(
                                cesFact,
                                new FactDescriptor(
                                        cesFact,
                                        FactSlotNamespace.RESOURCE,
                                        FactValueType.INT64,
                                        FactCardinality.SCALAR,
                                        FactPresenceModel.MAY_BE_ABSENT,
                                        null,
                                        null,
                                        FactResolutionStage.EXTRACT,
                                        Set.of(ContextEvaluationPhase.TARGET),
                                        true,
                                        "INTERNAL",
                                        "OPERATIONAL",
                                        Set.of(),
                                        legalBasis,
                                        null
                                )
                        );
                    }
                }
                Set<String> existingAttrIds = new LinkedHashSet<>();
                for (FactDescriptor fd : facts.values()) {
                    if (fd.attributeId() != null) {
                        existingAttrIds.add(fd.attributeId());
                    }
                }
                Set<String> declaredWriteOrAnchorAttrs = new LinkedHashSet<>(this.mandatoryScopeAnchorAttributeIds);
                for (Set<String> opAttrs : this.operationModifiedAttributes.values()) {
                    if (opAttrs != null) {
                        declaredWriteOrAnchorAttrs.addAll(opAttrs);
                    }
                }
                if (this.dualScopeDelegationSpec != null) {
                    if (this.dualScopeDelegationSpec.cedenteExclusiveWriteAttributes() != null) {
                        declaredWriteOrAnchorAttrs.addAll(this.dualScopeDelegationSpec.cedenteExclusiveWriteAttributes());
                    }
                    if (this.dualScopeDelegationSpec.cessionarioAllowedWriteAttributes() != null) {
                        declaredWriteOrAnchorAttrs.addAll(this.dualScopeDelegationSpec.cessionarioAllowedWriteAttributes());
                    }
                }
                for (String attrId : declaredWriteOrAnchorAttrs) {
                    if (attrId != null && !attrId.isBlank() && existingAttrIds.add(attrId)) {
                        String leaf = attrId.contains(".") ? attrId.substring(attrId.lastIndexOf('.') + 1) : attrId;
                        String syntheticFactPath = "resource.attr_" + leaf;
                        facts.putIfAbsent(
                                syntheticFactPath,
                                new FactDescriptor(
                                        syntheticFactPath,
                                        FactSlotNamespace.RESOURCE,
                                        FactValueType.STRING,
                                        FactCardinality.SCALAR,
                                        FactPresenceModel.MAY_BE_ABSENT,
                                        attrId,
                                        null,
                                        FactResolutionStage.EXTRACT,
                                        Set.of(ContextEvaluationPhase.TARGET),
                                        true,
                                        "INTERNAL",
                                        "OPERATIONAL",
                                        Set.of(),
                                        legalBasis,
                                        null
                                )
                        );
                    }
                }
                String fcId = "fc-" + resourceKey.replace('.', '-');
                String fcDigest = CanonicalDigestCalculator.computeDigest(
                        DigestDomainKind.DEPENDENCY_MANIFEST_DIGEST,
                        fcId + "|" + facts.keySet() + "|v1"
                );
                this.factContract = new FactContract(
                        FactContract.SCHEMA_VERSION_V1,
                        fcId,
                        "1.0.0",
                        fcDigest,
                        resourceKey,
                        Map.copyOf(facts)
                );
            }
            if (this.decisionPoint == null
                    && this.serviceKey != null
                    && !this.serviceKey.isBlank()
                    && this.factContract != null) {
                DecisionPointIdentity dpId = DecisionPointIdentity.resourceOperation(
                        this.serviceKey,
                        this.resourceKey,
                        this.operationKey
                );
                String effectiveHttpPath = this.httpPath != null
                        ? this.httpPath
                        : "/api/" + resourceKey.replace('.', '/') + "/" + this.operationKey;
                String dpDigest = CanonicalDigestCalculator.computeDigest(
                        DigestDomainKind.DEPENDENCY_MANIFEST_DIGEST,
                        this.serviceKey + "|" + this.resourceKey + "|" + this.operationKey + "|v1"
                );
                this.decisionPoint = new DecisionPointDescriptor(
                        DecisionPointDescriptor.SCHEMA_VERSION_V1,
                        dpId,
                        DecisionKind.AUTHORIZATION,
                        DecisionResultContractKind.GATE,
                        null,
                        "SEARCH",
                        this.httpMethod,
                        effectiveHttpPath,
                        Set.of(EvaluationMode.SEARCH, EvaluationMode.TARGET),
                        Set.of(
                                EnforcementCapability.ACCESS,
                                EnforcementCapability.DATA_SCOPE,
                                EnforcementCapability.FIELD_USE,
                                EnforcementCapability.FIELD_WRITE,
                                EnforcementCapability.MASK
                        ),
                        Set.of(
                                FieldUseCategory.VALUE,
                                FieldUseCategory.FILTER,
                                FieldUseCategory.SORT,
                                FieldUseCategory.GROUP,
                                FieldUseCategory.AGGREGATE,
                                FieldUseCategory.JOIN
                        ),
                        null,
                        new FactContractRef(this.factContract.factContractId(), this.factContract.factContractDigest()),
                        this.queryProjection != null
                                ? new QueryableProjectionRef(this.queryProjection.projectionId(), this.queryProjection.projectionDigest())
                                : null,
                        null,
                        null,
                        this.legalBasis,
                        this.regulatoryReference,
                        null,
                        dpDigest
                );
            }
            if (this.factContractDigest == null) {
                if (this.factContract != null) {
                    this.factContractDigest = this.factContract.factContractDigest();
                } else if (this.decisionPoint != null && this.decisionPoint.factContractRef() != null) {
                    this.factContractDigest = this.decisionPoint.factContractRef().factContractDigest();
                }
            }
            String effectiveServiceKey = (this.serviceKey != null && !this.serviceKey.isBlank())
                    ? this.serviceKey
                    : (this.decisionPoint != null ? this.decisionPoint.identity().serviceKey() : null);
            FactContractRef effectiveFactRef = this.factContract != null
                    ? new FactContractRef(this.factContract.factContractId(), this.factContract.factContractDigest())
                    : (this.decisionPoint != null ? this.decisionPoint.factContractRef() : null);
            if (effectiveServiceKey != null && effectiveFactRef != null) {
                QueryableProjectionRef effectiveQpRef = this.queryProjection != null
                        ? new QueryableProjectionRef(this.queryProjection.projectionId(), this.queryProjection.projectionDigest())
                        : (this.decisionPoint != null ? this.decisionPoint.queryProjectionRef() : null);
                for (DeclarativeActionEndpoint act : this.declarativeWorkflowActions.values()) {
                    this.actionDecisionPoints.computeIfAbsent(act.actionKey(), k -> {
                        DecisionPointIdentity actId = DecisionPointIdentity.workflowAction(
                                effectiveServiceKey,
                                this.resourceKey,
                                act.actionKey()
                        );
                        String actPath = act.canonicalPath() != null
                                ? act.canonicalPath()
                                : (act.bulkCollectionScope()
                                        ? "/api/" + this.resourceKey.replace('.', '/') + "/actions/" + act.actionKey()
                                        : "/api/" + this.resourceKey.replace('.', '/') + "/{id}/actions/" + act.actionKey());
                        String actDigest = CanonicalDigestCalculator.computeDigest(
                                DigestDomainKind.DEFINITION_FINGERPRINT,
                                effectiveServiceKey + "|" + this.resourceKey + "|action:" + act.actionKey()
                                        + (act.bulkCollectionScope() ? "|bulk|v1" : "|v1")
                        );
                        Set<EvaluationMode> actModes = act.bulkCollectionScope()
                                ? Set.of(EvaluationMode.SEARCH, EvaluationMode.TARGET)
                                : Set.of(EvaluationMode.TARGET);
                        Set<EnforcementCapability> actCapabilities = act.bulkCollectionScope()
                                ? Set.of(
                                        EnforcementCapability.ACCESS,
                                        EnforcementCapability.DATA_SCOPE,
                                        EnforcementCapability.FIELD_WRITE
                                )
                                : Set.of(
                                        EnforcementCapability.ACCESS,
                                        EnforcementCapability.FIELD_WRITE
                                );
                        return new DecisionPointDescriptor(
                                DecisionPointDescriptor.SCHEMA_VERSION_V1,
                                actId,
                                DecisionKind.AUTHORIZATION,
                                DecisionResultContractKind.GATE,
                                null,
                                act.bulkCollectionScope() ? "EXECUTE_BULK_ACTION" : "EXECUTE_ACTION",
                                act.httpMethod(),
                                actPath,
                                actModes,
                                actCapabilities,
                                Set.of(),
                                this.decisionPoint != null ? this.decisionPoint.obligationSupport() : null,
                                effectiveFactRef,
                                act.bulkCollectionScope() ? effectiveQpRef : null,
                                null,
                                null,
                                this.decisionPoint != null ? this.decisionPoint.legalPurpose() : this.legalBasis,
                                this.decisionPoint != null ? this.decisionPoint.legalBasisRef() : this.regulatoryReference,
                                this.decisionPoint != null ? this.decisionPoint.provenance() : null,
                                actDigest
                        );
                    });
                }
                for (DeclarativeSurfaceEndpoint surf : this.declarativeUiSurfaces.values()) {
                    this.surfaceDecisionPoints.computeIfAbsent(surf.surfaceKey(), k -> {
                        DecisionPointIdentity surfId = DecisionPointIdentity.resourceOperation(
                                effectiveServiceKey,
                                this.resourceKey,
                                "surface-" + surf.surfaceKey()
                        );
                        String surfPath = surf.canonicalPath() != null
                                ? surf.canonicalPath()
                                : "/api/" + this.resourceKey.replace('.', '/') + "/{id}/surfaces/" + surf.surfaceKey();
                        String surfDigest = CanonicalDigestCalculator.computeDigest(
                                DigestDomainKind.DEFINITION_FINGERPRINT,
                                effectiveServiceKey + "|" + this.resourceKey + "|surface:" + surf.surfaceKey() + "|v1"
                        );
                        return new DecisionPointDescriptor(
                                DecisionPointDescriptor.SCHEMA_VERSION_V1,
                                surfId,
                                DecisionKind.AUTHORIZATION,
                                DecisionResultContractKind.GATE,
                                null,
                                "READ_PROJECTION",
                                surf.httpMethod(),
                                surfPath,
                                Set.of(EvaluationMode.TARGET),
                                Set.of(
                                        EnforcementCapability.ACCESS,
                                        EnforcementCapability.MASK
                                ),
                                Set.of(),
                                this.decisionPoint != null ? this.decisionPoint.obligationSupport() : null,
                                effectiveFactRef,
                                null,
                                null,
                                null,
                                this.decisionPoint != null ? this.decisionPoint.legalPurpose() : this.legalBasis,
                                this.decisionPoint != null ? this.decisionPoint.legalBasisRef() : this.regulatoryReference,
                                this.decisionPoint != null ? this.decisionPoint.provenance() : null,
                                surfDigest
                        );
                    });
                }
            }
            return new AuthzResourceGovernanceSpec<>(this);
        }
    }
}
