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
import org.praxisplatform.authz.contracts.annotation.AuthzActionRule;
import org.praxisplatform.authz.contracts.annotation.AuthzCustodyPartition;
import org.praxisplatform.authz.contracts.annotation.AuthzCustodyRole;
import org.praxisplatform.authz.contracts.annotation.AuthzDelegationSplitMode;
import org.praxisplatform.authz.contracts.annotation.AuthzMask;
import org.praxisplatform.authz.contracts.annotation.AuthzScopeAnchor;
import org.praxisplatform.authz.contracts.annotation.AuthzTenantScope;
import org.praxisplatform.authz.contracts.annotation.AuthzTenantScopeMode;
import org.praxisplatform.authz.contracts.context.ContextEvaluationPhase;
import org.praxisplatform.authz.contracts.context.FactCardinality;
import org.praxisplatform.authz.contracts.context.FactContract;
import org.praxisplatform.authz.contracts.context.FactDescriptor;
import org.praxisplatform.authz.contracts.context.FactPresenceModel;
import org.praxisplatform.authz.contracts.context.FactResolutionStage;
import org.praxisplatform.authz.contracts.context.FactResolutionStatus;
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
import org.praxisplatform.authz.contracts.policy.MaskContributionSpec;
import org.praxisplatform.authz.enforcement.jpa.JpaDataScopeAdapter;
import org.praxisplatform.authz.enforcement.jpa.QueryAdapterFieldBinding;
import org.praxisplatform.authz.enforcement.jpa.RelationTraversalStrategy;
import org.praxisplatform.authz.enforcement.masking.DtoFieldSchemaMetadata;
import org.praxisplatform.authz.host.metadata.MetadataDtoGovernanceIntrospector.DeclaredMaskSpec;
import org.praxisplatform.uischema.action.ActionScope;
import org.praxisplatform.uischema.annotation.ApiResource;
import org.praxisplatform.uischema.annotation.DomainLineage;
import org.praxisplatform.uischema.annotation.UiSurface;
import org.praxisplatform.uischema.annotation.WorkflowAction;
import org.praxisplatform.uischema.capability.ResourceStateSnapshot;
import org.praxisplatform.uischema.filter.annotation.Filterable;
import org.praxisplatform.uischema.service.base.ResourceFilterAccessScope;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.web.bind.annotation.RequestBody;
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
 *       evaluation ({@link #isCallerOrigin(Object, AuthzCallerContext)} /
 *       {@link #isCallerDestination(Object, AuthzCallerContext)}) ({@code Fase P10.9}).</li>
 * </ul>
 *
 * @param <E> JPA entity type
 */
public final class AuthzResourceGovernanceSpec<E> {

    /** Canonical parameter name used in generated JPQL hard-scope clauses. */
    public static final String HARD_TENANT_PARAM = "__praxis_hard_tenant_id";

    /** Canonical parameter name used in generated JPQL multi-organization hard-scope clauses. */
    public static final String HARD_TENANT_IDS_PARAM = MultiOrganizationHardScopeResolver.HARD_TENANT_IDS_PARAM;

    /** Internal snapshot metadata key storing the entity's tenant identifier. */
    public static final String SNAPSHOT_TENANT_META_KEY = "__authz.tenantId";

    /** Internal snapshot metadata key storing the entity's origin custody anchor value. */
    public static final String SNAPSHOT_ORIGIN_VALUE_META_KEY = "__authz.originValue";

    /** Internal snapshot metadata key storing the entity's destination custody anchor value. */
    public static final String SNAPSHOT_DESTINATION_VALUE_META_KEY = "__authz.destinationValue";

    /**
     * Backward-compatible constant alias for {@link #SNAPSHOT_ORIGIN_VALUE_META_KEY}.
     *
     * @deprecated Use {@link #SNAPSHOT_ORIGIN_VALUE_META_KEY}.
     */
    @Deprecated(since = "0.1.0-beta.2")
    public static final String SNAPSHOT_CEDENTE_VALUE_META_KEY = SNAPSHOT_ORIGIN_VALUE_META_KEY;

    /**
     * Backward-compatible constant alias for {@link #SNAPSHOT_DESTINATION_VALUE_META_KEY}.
     *
     * @deprecated Use {@link #SNAPSHOT_DESTINATION_VALUE_META_KEY}.
     */
    @Deprecated(since = "0.1.0-beta.2")
    public static final String SNAPSHOT_CESSIONARIO_VALUE_META_KEY = SNAPSHOT_DESTINATION_VALUE_META_KEY;

    /** Internal snapshot metadata key storing the source entity reference when custom custody predicates are configured ({@code P10.9-R01}). */
    public static final String SNAPSHOT_ENTITY_REF_META_KEY = "__authz.entityRef";

    /** Internal snapshot metadata key marking snapshots enriched with host/OPA governance facts ({@code Wave 3}). */
    public static final String SNAPSHOT_ENRICHED_META_KEY = "__authz.snapshotEnriched";

    /** Internal snapshot metadata key listing {@code resource.*} paths whose entity value evaluated to {@code null} ({@code Wave 3}). */
    public static final String SNAPSHOT_NULL_FACTS_META_KEY = "__authz.nullFactPaths";

    /** Tenant and organizational isolation metadata resolved from {@link AuthzTenantScope}. */
    public record TenantScopeSpec(
            AuthzTenantScopeMode mode,
            String tenantField,
            String resourceFactPath,
            String subjectFactPath,
            String policyId,
            String ruleId,
            boolean allowBulkWithoutScope,
            String sharedBulkNonNullFactPath
    ) {
        public TenantScopeSpec {
            mode = mode == null ? AuthzTenantScopeMode.ORGANIZATIONAL_UNIT : mode;
            tenantField = (tenantField == null || tenantField.isBlank()) ? "tenantId" : tenantField.trim();
            resourceFactPath = (resourceFactPath == null || resourceFactPath.isBlank())
                    ? "resource." + tenantField
                    : resourceFactPath.trim();
            subjectFactPath = (subjectFactPath == null || subjectFactPath.isBlank())
                    ? (mode == AuthzTenantScopeMode.TENANT_ONLY ? "subject.tenantId" : "subject.organizationUnitIds")
                    : subjectFactPath.trim();
            policyId = policyId == null ? "" : policyId.trim();
            ruleId = ruleId == null ? "" : ruleId.trim();
            sharedBulkNonNullFactPath = sharedBulkNonNullFactPath == null ? "" : sharedBulkNonNullFactPath.trim();
        }
    }

    /** Mandatory scope anchor constraint resolved from {@link AuthzScopeAnchor}. */
    public record ScopeAnchorSpec(
            String attributeId,
            String factPath,
            boolean requiredOnCreate,
            boolean forbidClearOnUpdate,
            boolean immutableAfterCreate,
            String reason
    ) {
        public ScopeAnchorSpec {
            Objects.requireNonNull(attributeId, "attributeId is required");
            factPath = factPath == null ? "" : factPath.trim();
            reason = reason == null ? "" : reason.trim();
        }
    }

    /** Declarative rule specification resolved from {@link AuthzActionRule}. */
    public record ActionRuleSpec(
            String actionKey,
            String surfaceKey,
            String ruleId,
            String policyId,
            Set<EvaluationMode> evaluationModes,
            boolean requireAuthenticatedPrincipal,
            Set<String> requiredRoles,
            String conditionFactPath,
            List<String> conditionAllowedValues,
            String conditionJsonLogic,
            Set<String> allowedWriteAttributes,
            String reasonCode,
            boolean auditRequired,
            String auditCategory,
            String legalPurpose,
            String legalBasisRef,
            String description
    ) {
        public ActionRuleSpec {
            actionKey = actionKey == null ? "" : actionKey.trim();
            surfaceKey = surfaceKey == null ? "" : surfaceKey.trim();
            ruleId = ruleId == null ? "" : ruleId.trim();
            policyId = policyId == null ? "" : policyId.trim();
            evaluationModes = evaluationModes == null ? Set.of() : Set.copyOf(evaluationModes);
            requiredRoles = requiredRoles == null ? Set.of() : Set.copyOf(requiredRoles);
            conditionFactPath = conditionFactPath == null ? "" : conditionFactPath.trim();
            conditionAllowedValues = conditionAllowedValues == null ? List.of() : List.copyOf(conditionAllowedValues);
            conditionJsonLogic = conditionJsonLogic == null ? "" : conditionJsonLogic.trim();
            allowedWriteAttributes = allowedWriteAttributes == null ? Set.of() : Set.copyOf(allowedWriteAttributes);
            reasonCode = reasonCode == null ? "" : reasonCode.trim();
            auditCategory = auditCategory == null ? "" : auditCategory.trim();
            legalPurpose = legalPurpose == null ? "" : legalPurpose.trim();
            legalBasisRef = legalBasisRef == null ? "" : legalBasisRef.trim();
            description = description == null ? "" : description.trim();
        }

        public boolean targetsSurface() {
            return !surfaceKey.isEmpty();
        }
    }

    private final String resourceKey;
    private final String serviceKey;
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
    private final List<ScopeAnchorSpec> scopeAnchorSpecs;
    private final Set<String> technicalConcurrencyPointers;
    private final String tenantFieldName;
    private final Class<?> tenantJavaType;
    private final String tenantJpqlExpression;
    private final AuthzTenantScopeMode tenantScopeMode;
    private final TenantScopeSpec tenantScopeSpec;
    private final String hardScopeSubjectFactKey;
    private final boolean allowGlobalNullScope;
    private final boolean immutableTenantAnchor;
    private final HardScopeResolver hardScopeResolver;
    private final Function<E, String> entityTenantExtractor;
    private final BiPredicate<E, AuthzCallerContext> entityScopePredicate;
    private final Function<E, Map<String, Object>> targetFactExtractor;
    private final String stateFieldName;
    private final Function<E, String> stateExtractor;
    private final String originEntityFieldPath;
    private final String originSubjectFactKey;
    private final BiPredicate<E, AuthzCallerContext> originCustodyPredicate;
    private final String destinationEntityFieldPath;
    private final String destinationSubjectFactKey;
    private final BiPredicate<E, AuthzCallerContext> destinationCustodyPredicate;
    private final Map<String, Set<String>> operationModifiedAttributes;
    private final Map<String, DecisionPointDescriptor> actionDecisionPoints;
    private final Map<String, DecisionPointDescriptor> surfaceDecisionPoints;
    private final List<DeclaredMaskSpec> maskSpecs;
    private final Map<String, ActionRuleSpec> actionRuleSpecs;
    private final Map<String, ActionRuleSpec> surfaceRuleSpecs;

    private AuthzResourceGovernanceSpec(Builder<E> builder) {
        this.resourceKey = Objects.requireNonNull(builder.resourceKey, "resourceKey is required");
        this.serviceKey = builder.serviceKey;
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
        this.scopeAnchorSpecs = List.copyOf(builder.scopeAnchorSpecs);
        this.technicalConcurrencyPointers = Set.copyOf(builder.technicalConcurrencyPointers);
        this.tenantFieldName = Objects.requireNonNull(builder.tenantFieldName, "tenantFieldName is required");
        this.tenantJavaType = builder.tenantJavaType;
        this.tenantJpqlExpression = builder.tenantJpqlExpression != null
                ? builder.tenantJpqlExpression
                : "e." + this.tenantFieldName;
        this.tenantScopeMode = builder.tenantScopeMode != null
                ? builder.tenantScopeMode
                : AuthzTenantScopeMode.ORGANIZATIONAL_UNIT;
        this.tenantScopeSpec = builder.tenantScopeSpec;
        this.hardScopeSubjectFactKey = builder.hardScopeSubjectFactKey;
        this.allowGlobalNullScope = builder.allowGlobalNullScope;
        this.immutableTenantAnchor = builder.immutableTenantAnchor;
        this.hardScopeResolver = builder.hardScopeResolver != null
                ? builder.hardScopeResolver
                : new MultiOrganizationHardScopeResolver();
        this.entityTenantExtractor = builder.entityTenantExtractor;
        this.entityScopePredicate = builder.entityScopePredicate;
        this.targetFactExtractor = builder.targetFactExtractor;
        this.stateFieldName = builder.stateFieldName;
        this.stateExtractor = builder.stateExtractor;
        this.originEntityFieldPath = builder.originEntityFieldPath;
        this.originSubjectFactKey = builder.originSubjectFactKey;
        this.originCustodyPredicate = builder.originCustodyPredicate;
        this.destinationEntityFieldPath = builder.destinationEntityFieldPath;
        this.destinationSubjectFactKey = builder.destinationSubjectFactKey;
        this.destinationCustodyPredicate = builder.destinationCustodyPredicate;
        Map<String, Set<String>> opAttrs = new LinkedHashMap<>();
        for (Map.Entry<String, Set<String>> e : builder.operationModifiedAttributes.entrySet()) {
            opAttrs.put(e.getKey(), Set.copyOf(e.getValue()));
        }
        this.operationModifiedAttributes = Map.copyOf(opAttrs);
        this.actionDecisionPoints = Map.copyOf(builder.actionDecisionPoints);
        this.surfaceDecisionPoints = Map.copyOf(builder.surfaceDecisionPoints);
        this.maskSpecs = List.copyOf(builder.maskSpecs);
        this.actionRuleSpecs = Map.copyOf(builder.actionRuleSpecs);
        this.surfaceRuleSpecs = Map.copyOf(builder.surfaceRuleSpecs);
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
     * @param serviceKey owning microservice/host key (e.g. {@code "praxis-workforce-showcase"})
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
    /**
     * Zero-blueprint factory ({@code PLAT-EVO-10}) relying on {@link AuthzTenantScope} (or default
     * {@code "tenantId"}), {@link AuthzScopeAnchor}, {@link AuthzCustodyPartition},
     * {@link AuthzMask}, and {@link AuthzActionRule} annotations without specifying
     * {@code tenantFieldName} manually.
     */
    public static <E> AuthzResourceGovernanceSpec<E> fromAnnotatedResource(
            String serviceKey,
            Class<E> entityClass,
            Class<?> responseDtoClass,
            Class<?> filterDtoClass,
            Class<?> controllerClass
    ) {
        return fromAnnotatedResource(
                serviceKey,
                (String) null,
                entityClass,
                responseDtoClass,
                filterDtoClass,
                controllerClass
        );
    }

    /**
     * Zero-blueprint factory ({@code PLAT-EVO-10}) accepting explicit write DTOs and service class
     * for full {@code @Authz*} annotation discovery.
     */
    public static <E> AuthzResourceGovernanceSpec<E> fromAnnotatedResource(
            String serviceKey,
            String resourceKey,
            String tenantFieldName,
            Class<E> entityClass,
            Class<?> responseDtoClass,
            Class<?> filterDtoClass,
            Class<?> createDtoClass,
            Class<?> updateDtoClass,
            Class<?> controllerClass,
            Class<?> serviceClass
    ) {
        Builder<E> builder = AuthzResourceGovernanceSpec.<E>builder(resourceKey)
                .serviceKey(serviceKey);
        if (tenantFieldName != null && !tenantFieldName.isBlank()) {
            builder.tenantField(tenantFieldName);
        }
        return builder.introspectFromResource(
                        entityClass,
                        responseDtoClass,
                        filterDtoClass,
                        createDtoClass,
                        updateDtoClass,
                        controllerClass,
                        serviceClass
                )
                .build();
    }

    public static <E> AuthzResourceGovernanceSpec<E> fromAnnotatedResource(
            String serviceKey,
            String resourceKey,
            String tenantFieldName,
            Class<E> entityClass,
            Class<?> responseDtoClass,
            Class<?> filterDtoClass,
            Class<?> controllerClass
    ) {
        return fromAnnotatedResource(
                serviceKey,
                resourceKey,
                tenantFieldName,
                entityClass,
                responseDtoClass,
                filterDtoClass,
                null,
                null,
                controllerClass,
                null
        );
    }

    public String resourceKey() {
        return resourceKey;
    }

    /** Returns the optional owning microservice/host key configured on the spec. */
    public String serviceKey() {
        if (serviceKey != null && !serviceKey.isBlank()) {
            return serviceKey;
        }
        return decisionPoint.identity().serviceKey();
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

    /** Returns declarative {@link ScopeAnchorSpec} contracts extracted from {@link AuthzScopeAnchor}. */
    public List<ScopeAnchorSpec> scopeAnchorSpecs() {
        return scopeAnchorSpecs;
    }

    public Set<String> technicalConcurrencyPointers() {
        return technicalConcurrencyPointers;
    }

    public String tenantFieldName() {
        return tenantFieldName;
    }

    public Class<?> tenantJavaType() {
        return tenantJavaType;
    }

    public String tenantJpqlExpression() {
        return tenantJpqlExpression;
    }

    /** Returns the resolved {@link AuthzTenantScopeMode} for this resource. */
    public AuthzTenantScopeMode tenantScopeMode() {
        return tenantScopeMode;
    }

    /** Returns the optional declarative {@link TenantScopeSpec} extracted from {@link AuthzTenantScope}. */
    public TenantScopeSpec tenantScopeSpec() {
        return tenantScopeSpec;
    }

    /** Returns the optional explicit subject fact key driving multi-organization hard scope. */
    public String hardScopeSubjectFactKey() {
        return hardScopeSubjectFactKey;
    }

    /** Returns whether {@code null} scope values represent globally visible rows. */
    public boolean allowGlobalNullScope() {
        return allowGlobalNullScope;
    }

    /** Returns whether the tenant/organization scope anchor is marked immutable after creation. */
    public boolean hasImmutableTenantAnchor() {
        return immutableTenantAnchor;
    }

    /** Returns the {@link HardScopeResolver} configured for this spec. */
    public HardScopeResolver hardScopeResolver() {
        return hardScopeResolver;
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

    /** Returns all declared {@link AuthzMask} and derived {@code @DomainGovernance} mask bindings. */
    public List<DeclaredMaskSpec> maskSpecs() {
        return maskSpecs;
    }

    /** Returns the effective {@link MaskContributionSpec} list for bootstrap policy synthesis. */
    public List<MaskContributionSpec> effectiveMaskDirectives() {
        if (maskSpecs.isEmpty()) {
            return List.of();
        }
        return maskSpecs.stream().map(DeclaredMaskSpec::contribution).toList();
    }

    /** Returns declarative action rules mapped by canonical action key. */
    public Map<String, ActionRuleSpec> actionRuleSpecs() {
        return actionRuleSpecs;
    }

    /** Returns declarative surface rules mapped by canonical surface key. */
    public Map<String, ActionRuleSpec> surfaceRuleSpecs() {
        return surfaceRuleSpecs;
    }

    /** Returns the optional entity state property path used for {@link ResourceStateSnapshot#state()}. */
    public String stateFieldName() {
        return stateFieldName;
    }

    /** Returns the optional entity property path storing the authoritative origin custody anchor value. */
    public String originEntityFieldPath() {
        return originEntityFieldPath;
    }

    /** Returns the optional caller subject fact key compared against {@link #originEntityFieldPath()}. */
    public String originSubjectFactKey() {
        return originSubjectFactKey;
    }

    /** Returns the optional entity property path storing the delegated destination custody anchor value. */
    public String destinationEntityFieldPath() {
        return destinationEntityFieldPath;
    }

    /** Returns the optional caller subject fact key compared against {@link #destinationEntityFieldPath()}. */
    public String destinationSubjectFactKey() {
        return destinationSubjectFactKey;
    }

    /** Returns {@code true} when declarative origin custody rules are configured on this spec. */
    public boolean hasDeclarativeOriginCustody() {
        return originCustodyPredicate != null || (originEntityFieldPath != null && originSubjectFactKey != null);
    }

    /** Returns {@code true} when declarative destination custody rules are configured on this spec. */
    public boolean hasDeclarativeDestinationCustody() {
        return destinationCustodyPredicate != null
                || (destinationEntityFieldPath != null && destinationSubjectFactKey != null);
    }

    /**
     * Backward-compatible delegate for {@link #originEntityFieldPath()}.
     *
     * @deprecated Use {@link #originEntityFieldPath()}.
     */
    @Deprecated(since = "0.1.0-beta.2")
    public String cedenteEntityFieldPath() {
        return originEntityFieldPath();
    }

    /**
     * Backward-compatible delegate for {@link #originSubjectFactKey()}.
     *
     * @deprecated Use {@link #originSubjectFactKey()}.
     */
    @Deprecated(since = "0.1.0-beta.2")
    public String cedenteSubjectFactKey() {
        return originSubjectFactKey();
    }

    /**
     * Backward-compatible delegate for {@link #destinationEntityFieldPath()}.
     *
     * @deprecated Use {@link #destinationEntityFieldPath()}.
     */
    @Deprecated(since = "0.1.0-beta.2")
    public String cessionarioEntityFieldPath() {
        return destinationEntityFieldPath();
    }

    /**
     * Backward-compatible delegate for {@link #destinationSubjectFactKey()}.
     *
     * @deprecated Use {@link #destinationSubjectFactKey()}.
     */
    @Deprecated(since = "0.1.0-beta.2")
    public String cessionarioSubjectFactKey() {
        return destinationSubjectFactKey();
    }

    /**
     * Backward-compatible delegate for {@link #hasDeclarativeOriginCustody()}.
     *
     * @deprecated Use {@link #hasDeclarativeOriginCustody()}.
     */
    @Deprecated(since = "0.1.0-beta.2")
    public boolean hasDeclarativeCedenteCustody() {
        return hasDeclarativeOriginCustody();
    }

    /**
     * Backward-compatible delegate for {@link #hasDeclarativeDestinationCustody()}.
     *
     * @deprecated Use {@link #hasDeclarativeDestinationCustody()}.
     */
    @Deprecated(since = "0.1.0-beta.2")
    public boolean hasDeclarativeCessionarioCustody() {
        return hasDeclarativeDestinationCustody();
    }

    /**
     * Builds the JPA Criteria {@link ResourceFilterAccessScope} for the given {@link AuthzCallerContext},
     * supporting single-tenant, multi-organization ({@code IN}), and shared scopes via {@link HardScopeResolver}.
     */
    public ResourceFilterAccessScope<E> buildHardScope(AuthzCallerContext callerContext) {
        return hardScopeResolver.buildCriteriaScope(this, callerContext);
    }

    /**
     * Builds the JPA Criteria {@link ResourceFilterAccessScope} for the given {@code tenantId},
     * automatically coercing {@code tenantId} to integer/long/UUID types when the entity's tenant
     * attribute is non-String ({@code PLAT-EVO-10}).
     */
    public ResourceFilterAccessScope<E> buildHardScope(String tenantId) {
        Objects.requireNonNull(tenantId, "tenantId is required for hardScope");
        if (tenantScopeMode == AuthzTenantScopeMode.AUTHENTICATED_SHARED) {
            return ResourceFilterAccessScope.unrestricted();
        }
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

    static Object coerceScopeValue(Class<?> expectedType, String value) {
        return coerceTenantValue(expectedType, value);
    }

    static boolean scopeValuesEqual(Object a, Object b) {
        return valuesEqual(a, b, false);
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
     * Returns the canonical JPQL hard-scope predicate expression for a caller context (single or multi-org).
     */
    public String buildHardScopeJpql(AuthzCallerContext callerContext) {
        return hardScopeResolver.buildJpqlPredicate(this, callerContext);
    }

    /**
     * Returns the canonical JPQL hard-scope predicate expression.
     */
    public String buildHardScopeJpql() {
        if (tenantScopeMode == AuthzTenantScopeMode.AUTHENTICATED_SHARED) {
            return "1 = 1";
        }
        return tenantJpqlExpression + " = :" + HARD_TENANT_PARAM;
    }

    /**
     * Returns the canonical JPQL hard-scope parameter map for the given {@link AuthzCallerContext}.
     */
    public Map<String, Object> buildHardScopeParams(AuthzCallerContext callerContext) {
        return hardScopeResolver.buildJpqlParams(this, callerContext);
    }

    /**
     * Returns the canonical JPQL hard-scope parameter map for the given {@code tenantId}.
     */
    public Map<String, Object> buildHardScopeParams(String tenantId) {
        Objects.requireNonNull(tenantId, "tenantId is required for hardScopeParams");
        if (tenantScopeMode == AuthzTenantScopeMode.AUTHENTICATED_SHARED) {
            return Map.of();
        }
        return Map.of(HARD_TENANT_PARAM, coerceTenantValue(tenantJavaType, tenantId));
    }

    /**
     * Extracts the raw organizational/tenant scope field value from {@code entity}.
     */
    public Object extractRawScopeValueFromEntity(E entity) {
        E unwrapped = AuthzEntityUnproxySupport.unproxy(entity);
        if (unwrapped == null) {
            return null;
        }
        if (entityTenantExtractor != null) {
            return entityTenantExtractor.apply(unwrapped);
        }
        return readNestedProperty(unwrapped, tenantFieldName);
    }

    /**
     * Resolves the effective hard-scope selection ({@code SINGLE_VALUE}, {@code MULTI_ORGANIZATION},
     * {@code SHARED_UNRESTRICTED}, or {@code DENIED}) via the configured {@link HardScopeResolver}.
     */
    public HardScopeResolver.HardScopeSelection resolveHardScopeSelection(AuthzCallerContext callerContext) {
        return hardScopeResolver.resolveSelection(this, callerContext);
    }

    /**
     * Verifies write-target organizational invariants against {@link HardScopeResolver}.
     */
    public void verifyWritableTarget(E candidate, E previous, AuthzCallerContext callerContext) {
        hardScopeResolver.verifyWritableTarget(
                this,
                AuthzEntityUnproxySupport.unproxy(candidate),
                AuthzEntityUnproxySupport.unproxy(previous),
                callerContext
        );
    }

    /**
     * Extracts the tenant identifier from {@code entity} using {@code entityTenantExtractor} or
     * reflection on {@link #tenantFieldName()}.
     *
     * @param entity JPA entity instance
     * @return extracted tenant identifier or {@code null}
     */
    public String extractTenantFromEntity(E entity) {
        E unwrapped = AuthzEntityUnproxySupport.unproxy(entity);
        if (unwrapped == null) {
            return null;
        }
        if (entityTenantExtractor != null) {
            return entityTenantExtractor.apply(unwrapped);
        }
        Object val = readNestedProperty(unwrapped, tenantFieldName);
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
        E unwrapped = AuthzEntityUnproxySupport.unproxy(entity);
        if (unwrapped == null) {
            return Map.of();
        }
        Map<String, Object> facts = new LinkedHashMap<>();
        for (QueryAdapterFieldBinding binding : fieldBindings) {
            if (binding.traversalStrategy() == RelationTraversalStrategy.CORRELATED_EXISTS_SUBQUERY) {
                List<Object> values = extractCollectionValues(unwrapped, binding.nativeJpaPath());
                facts.put(binding.fieldPath(), values);
            } else {
                Object val = readNestedProperty(unwrapped, binding.nativeJpaPath());
                if (val != null) {
                    facts.put(binding.fieldPath(), val);
                }
            }
        }
        if (dualScopeDelegationSpec != null) {
            if (originEntityFieldPath != null && dualScopeDelegationSpec.originFactPath() != null) {
                Object originVal = readNestedProperty(unwrapped, originEntityFieldPath);
                if (originVal != null) {
                    facts.putIfAbsent(dualScopeDelegationSpec.originFactPath(), originVal);
                }
            }
            if (destinationEntityFieldPath != null && dualScopeDelegationSpec.destinationFactPath() != null) {
                Object destinationVal = readNestedProperty(unwrapped, destinationEntityFieldPath);
                if (destinationVal != null) {
                    facts.putIfAbsent(dualScopeDelegationSpec.destinationFactPath(), destinationVal);
                }
            }
        }
        if (targetFactExtractor != null) {
            Map<String, Object> custom = targetFactExtractor.apply(unwrapped);
            if (custom != null && !custom.isEmpty()) {
                facts.putAll(custom);
            }
        }
        return Map.copyOf(facts);
    }

    /**
     * Extracts {@link FactResolutionStatus#NULL} entries for scalar {@link #fieldBindings()} whose
     * property evaluates to {@code null} on {@code entity}, enabling {@code is_null} predicates
     * (such as {@code allowGlobalNullScope}) in {@code TARGET} evaluations without placing {@code null}
     * values in immutable fact maps.
     *
     * @param entity JPA entity instance
     * @return immutable map of {@code resource.*} paths with {@link FactResolutionStatus#NULL}
     */
    public Map<String, FactResolutionStatus> extractEntityTargetFactStatuses(E entity) {
        E unwrapped = AuthzEntityUnproxySupport.unproxy(entity);
        if (unwrapped == null) {
            return Map.of();
        }
        Map<String, FactResolutionStatus> statuses = new LinkedHashMap<>();
        for (QueryAdapterFieldBinding binding : fieldBindings) {
            if (binding.traversalStrategy() != RelationTraversalStrategy.CORRELATED_EXISTS_SUBQUERY) {
                Object val = readNestedProperty(unwrapped, binding.nativeJpaPath());
                if (val == null) {
                    statuses.put(binding.fieldPath(), FactResolutionStatus.NULL);
                }
            }
        }
        return statuses.isEmpty() ? Map.of() : Map.copyOf(statuses);
    }

    /**
     * Builds canonical {@link FactResolutionStatus} entries from caller statuses, non-null facts
     * (defaulted to {@link FactResolutionStatus#PRESENT}), and nullable scalar bindings on
     * {@code entity} whose value is {@code null} ({@link FactResolutionStatus#NULL}).
     */
    public static <E> Map<String, FactResolutionStatus> resolveFactStatuses(
            Map<String, FactResolutionStatus> baseStatuses,
            Map<String, Object> facts,
            AuthzResourceGovernanceSpec<E> spec,
            E entity
    ) {
        Map<String, FactResolutionStatus> statuses = new LinkedHashMap<>();
        if (baseStatuses != null && !baseStatuses.isEmpty()) {
            statuses.putAll(baseStatuses);
        }
        if (facts != null) {
            for (String key : facts.keySet()) {
                statuses.putIfAbsent(key, FactResolutionStatus.PRESENT);
            }
        }
        if (spec != null && entity != null) {
            for (Map.Entry<String, FactResolutionStatus> entry :
                    spec.extractEntityTargetFactStatuses(entity).entrySet()) {
                if (facts == null || !facts.containsKey(entry.getKey())) {
                    statuses.putIfAbsent(entry.getKey(), entry.getValue());
                }
            }
        }
        return statuses.isEmpty() ? Map.of() : Map.copyOf(statuses);
    }

    /**
     * Extracts the workflow/lifecycle state string from {@code entity} when {@code stateField} or
     * {@code stateExtractor} is configured ({@code Fase P10.9}).
     *
     * @param entity JPA entity instance
     * @return extracted state string or {@code null}
     */
    public String extractEntityState(E entity) {
        E unwrapped = AuthzEntityUnproxySupport.unproxy(entity);
        if (unwrapped == null) {
            return null;
        }
        if (stateExtractor != null) {
            return stateExtractor.apply(unwrapped);
        }
        if (stateFieldName != null && !stateFieldName.isBlank()) {
            Object val = readNestedProperty(unwrapped, stateFieldName);
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
        E unwrapped = AuthzEntityUnproxySupport.unproxy(Objects.requireNonNull(entity, "entity is required"));
        String state = extractEntityState(unwrapped);
        Map<String, Object> metadata = new LinkedHashMap<>(extractEntityTargetFacts(unwrapped));
        for (QueryAdapterFieldBinding binding : fieldBindings) {
            if (binding.traversalStrategy() != RelationTraversalStrategy.CORRELATED_EXISTS_SUBQUERY) {
                Object val = metadata.get(binding.fieldPath());
                if (val != null) {
                    metadata.putIfAbsent(binding.nativeJpaPath(), val);
                }
            }
        }
        if (tenantScopeMode != AuthzTenantScopeMode.AUTHENTICATED_SHARED) {
            String tenantId = extractTenantFromEntity(unwrapped);
            if (tenantId != null) {
                metadata.put(SNAPSHOT_TENANT_META_KEY, tenantId);
            }
        }
        if (originEntityFieldPath != null) {
            Object originVal = readNestedProperty(unwrapped, originEntityFieldPath);
            if (originVal != null) {
                metadata.put(SNAPSHOT_ORIGIN_VALUE_META_KEY, originVal);
            }
        }
        if (destinationEntityFieldPath != null) {
            Object destinationVal = readNestedProperty(unwrapped, destinationEntityFieldPath);
            if (destinationVal != null) {
                metadata.put(SNAPSHOT_DESTINATION_VALUE_META_KEY, destinationVal);
            }
        }
        if (originCustodyPredicate != null || destinationCustodyPredicate != null) {
            metadata.put(SNAPSHOT_ENTITY_REF_META_KEY, unwrapped);
        }
        Map<String, FactResolutionStatus> nullStatuses = extractEntityTargetFactStatuses(unwrapped);
        if (!nullStatuses.isEmpty()) {
            metadata.put(SNAPSHOT_NULL_FACTS_META_KEY, List.copyOf(nullStatuses.keySet()));
        }
        metadata.put(SNAPSHOT_ENRICHED_META_KEY, Boolean.TRUE);
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
        Map<String, FactDescriptor> contractDescriptors =
                factContract != null && factContract.descriptorsByPath() != null
                        ? factContract.descriptorsByPath()
                        : null;
        for (Map.Entry<String, Object> entry : meta.entrySet()) {
            String key = entry.getKey();
            if (key != null
                    && key.startsWith("resource.")
                    && entry.getValue() != null
                    && (contractDescriptors == null || contractDescriptors.containsKey(key))) {
                facts.putIfAbsent(key, entry.getValue());
            }
        }
        return Map.copyOf(facts);
    }

    /**
     * Extracts canonical {@link FactResolutionStatus} entries for {@code resource.*} target facts
     * resolved from a {@link ResourceStateSnapshot}, preserving {@link FactResolutionStatus#NULL}
     * markers recorded by {@link #toResourceStateSnapshot(Object)} ({@code Wave 3}).
     *
     * @param snapshot resource state snapshot
     * @return immutable map of {@code resource.*} fact resolution statuses
     */
    public Map<String, FactResolutionStatus> extractSnapshotTargetFactStatuses(ResourceStateSnapshot snapshot) {
        if (snapshot == null) {
            return Map.of();
        }
        Map<String, FactResolutionStatus> statuses = new LinkedHashMap<>();
        for (String key : extractSnapshotTargetFacts(snapshot).keySet()) {
            statuses.put(key, FactResolutionStatus.PRESENT);
        }
        Object rawNullPaths = snapshot.metadata().get(SNAPSHOT_NULL_FACTS_META_KEY);
        if (rawNullPaths instanceof Collection<?> nullPaths) {
            for (Object item : nullPaths) {
                if (item instanceof String path && !path.isBlank()) {
                    statuses.putIfAbsent(path, FactResolutionStatus.NULL);
                }
            }
        }
        return statuses.isEmpty() ? Map.of() : Map.copyOf(statuses);
    }

    /**
     * Evaluates whether the caller represented by {@code callerContext} holds authoritative origin
     * custody over {@code entity} ({@code Fase P10.9}).
     *
     * @param entity JPA entity instance (may be {@code null} for collection-scoped probes)
     * @param callerContext active caller context
     * @return {@code true} when caller holds origin custody
     */
    public boolean isCallerOrigin(E entity, AuthzCallerContext callerContext) {
        if (callerContext == null) {
            return dualScopeDelegationSpec == null;
        }
        if (callerContext.callerMatchesOrigin() != null) {
            return callerContext.callerMatchesOrigin();
        }
        E unwrapped = AuthzEntityUnproxySupport.unproxy(entity);
        if (originCustodyPredicate != null && unwrapped != null) {
            return originCustodyPredicate.test(unwrapped, callerContext);
        }
        if (originEntityFieldPath != null && originSubjectFactKey != null) {
            Object subjectFact = callerContext.subjectAndEnvironmentFacts().get(originSubjectFactKey);
            if (unwrapped == null) {
                return hasNonEmptyCustodySubjectFact(subjectFact);
            }
            Object entityVal = readNestedProperty(unwrapped, originEntityFieldPath);
            return matchesCustodyValue(entityVal, subjectFact);
        }
        return true;
    }

    /**
     * Evaluates whether the caller represented by {@code callerContext} holds delegated destination
     * custody over {@code entity} ({@code Fase P10.9}).
     *
     * @param entity JPA entity instance (may be {@code null} for collection-scoped probes)
     * @param callerContext active caller context
     * @return {@code true} when caller holds destination custody
     */
    public boolean isCallerDestination(E entity, AuthzCallerContext callerContext) {
        if (callerContext == null) {
            return dualScopeDelegationSpec == null;
        }
        if (callerContext.callerMatchesDestination() != null) {
            return callerContext.callerMatchesDestination();
        }
        E unwrapped = AuthzEntityUnproxySupport.unproxy(entity);
        if (destinationCustodyPredicate != null && unwrapped != null) {
            return destinationCustodyPredicate.test(unwrapped, callerContext);
        }
        if (destinationEntityFieldPath != null && destinationSubjectFactKey != null) {
            Object subjectFact = callerContext.subjectAndEnvironmentFacts().get(destinationSubjectFactKey);
            if (unwrapped == null) {
                return hasNonEmptyCustodySubjectFact(subjectFact);
            }
            Object entityVal = readNestedProperty(unwrapped, destinationEntityFieldPath);
            return matchesCustodyValue(entityVal, subjectFact);
        }
        return true;
    }

    /**
     * Evaluates whether the caller holds origin custody for an item {@link ResourceStateSnapshot}
     * ({@code Fase P10.9}, {@code P10.9-R01}).
     */
    @SuppressWarnings("unchecked")
    public boolean isCallerOriginForSnapshot(ResourceStateSnapshot snapshot, AuthzCallerContext callerContext) {
        if (callerContext == null) {
            return dualScopeDelegationSpec == null;
        }
        if (callerContext.callerMatchesOrigin() != null) {
            return callerContext.callerMatchesOrigin();
        }
        if (snapshot == null) {
            return false;
        }
        if (originCustodyPredicate != null) {
            Object entityRef = snapshot.metadata().get(SNAPSHOT_ENTITY_REF_META_KEY);
            if (entityRef != null) {
                return originCustodyPredicate.test((E) entityRef, callerContext);
            }
            return false;
        }
        if (originEntityFieldPath != null && originSubjectFactKey != null) {
            Object subjectFact = callerContext.subjectAndEnvironmentFacts().get(originSubjectFactKey);
            Object snapshotVal = snapshot.metadata().get(SNAPSHOT_ORIGIN_VALUE_META_KEY);
            if (snapshotVal == null) {
                snapshotVal = snapshot.metadata().get(originEntityFieldPath);
            }
            return matchesCustodyValue(snapshotVal, subjectFact);
        }
        return true;
    }

    /**
     * Evaluates whether the caller holds destination custody for an item {@link ResourceStateSnapshot}
     * ({@code Fase P10.9}, {@code P10.9-R01}).
     */
    @SuppressWarnings("unchecked")
    public boolean isCallerDestinationForSnapshot(ResourceStateSnapshot snapshot, AuthzCallerContext callerContext) {
        if (callerContext == null) {
            return dualScopeDelegationSpec == null;
        }
        if (callerContext.callerMatchesDestination() != null) {
            return callerContext.callerMatchesDestination();
        }
        if (snapshot == null) {
            return false;
        }
        if (destinationCustodyPredicate != null) {
            Object entityRef = snapshot.metadata().get(SNAPSHOT_ENTITY_REF_META_KEY);
            if (entityRef != null) {
                return destinationCustodyPredicate.test((E) entityRef, callerContext);
            }
            return false;
        }
        if (destinationEntityFieldPath != null && destinationSubjectFactKey != null) {
            Object subjectFact = callerContext.subjectAndEnvironmentFacts().get(destinationSubjectFactKey);
            Object snapshotVal = snapshot.metadata().get(SNAPSHOT_DESTINATION_VALUE_META_KEY);
            if (snapshotVal == null) {
                snapshotVal = snapshot.metadata().get(destinationEntityFieldPath);
            }
            return matchesCustodyValue(snapshotVal, subjectFact);
        }
        return true;
    }

    /** @deprecated Use {@link #isCallerOrigin(Object, AuthzCallerContext)}. */
    @Deprecated(since = "0.1.0-beta.2")
    public boolean isCallerCedente(E entity, AuthzCallerContext callerContext) {
        return isCallerOrigin(entity, callerContext);
    }

    /** @deprecated Use {@link #isCallerDestination(Object, AuthzCallerContext)}. */
    @Deprecated(since = "0.1.0-beta.2")
    public boolean isCallerCessionario(E entity, AuthzCallerContext callerContext) {
        return isCallerDestination(entity, callerContext);
    }

    /** @deprecated Use {@link #isCallerOriginForSnapshot(ResourceStateSnapshot, AuthzCallerContext)}. */
    @Deprecated(since = "0.1.0-beta.2")
    public boolean isCallerCedenteForSnapshot(ResourceStateSnapshot snapshot, AuthzCallerContext callerContext) {
        return isCallerOriginForSnapshot(snapshot, callerContext);
    }

    /** @deprecated Use {@link #isCallerDestinationForSnapshot(ResourceStateSnapshot, AuthzCallerContext)}. */
    @Deprecated(since = "0.1.0-beta.2")
    public boolean isCallerCessionarioForSnapshot(ResourceStateSnapshot snapshot, AuthzCallerContext callerContext) {
        return isCallerDestinationForSnapshot(snapshot, callerContext);
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
        E unwrapped = AuthzEntityUnproxySupport.unproxy(Objects.requireNonNull(entity, "entity is required"));
        Objects.requireNonNull(callerContext, "callerContext is required");
        hardScopeResolver.verifyEntityAccess(this, unwrapped, callerContext);
        if (activeDataScopePlan != null) {
            if (activeDataScopePlan.scopeOutcome() == DataScopeOutcome.NONE) {
                throw new SecurityException(
                        "AUTHZ_ENTITY_DATA_SCOPE_DENIED: Active DataScopePlan outcome is NONE (403)");
            }
            if (activeDataScopePlan.scopeOutcome() == DataScopeOutcome.FILTER) {
                SearchPredicateIr predicateIr = Objects.requireNonNull(
                        activeDataScopePlan.predicateIr(), "FILTER outcome requires non-null predicateIr");
                queryProjection.validatePredicateIr(predicateIr);
                if (!evaluatePredicateIrOnEntity(unwrapped, predicateIr, false)) {
                    throw new SecurityException(
                            "AUTHZ_ENTITY_DATA_SCOPE_DENIED: Entity is outside caller's authorized DataScopePlan (403)");
                }
            }
        }
        if (entityScopePredicate != null && !entityScopePredicate.test(unwrapped, callerContext)) {
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
        Object unwrapped = AuthzEntityUnproxySupport.unproxy(target);
        if (unwrapped == null) {
            return null;
        }
        Class<?> current = unwrapped.getClass();
        while (current != null && current != Object.class) {
            try {
                Field f = current.getDeclaredField(fieldName);
                f.setAccessible(true);
                return f.get(unwrapped);
            } catch (NoSuchFieldException ignored) {
                current = current.getSuperclass();
            } catch (IllegalAccessException ex) {
                throw new IllegalStateException("Failed to read field '" + fieldName + "' on " + unwrapped.getClass().getName(), ex);
            }
        }
        throw new IllegalStateException("Field '" + fieldName + "' not found on class " + unwrapped.getClass().getName());
    }

    /**
     * Fluent builder for {@link AuthzResourceGovernanceSpec}.
     *
     * @param <E> JPA entity type
     */
    public static final class Builder<E> {
        private final String resourceKey;
        private String serviceKey;
        private boolean includeActionVerbFact = false;
        private boolean includeSubjectRolesFact = false;
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
        private final List<ScopeAnchorSpec> scopeAnchorSpecs = new ArrayList<>();
        private final Set<String> technicalConcurrencyPointers = new LinkedHashSet<>(Set.of("/version"));
        private String tenantFieldName = "tenantId";
        private boolean tenantFieldExplicitlySet = false;
        private Class<?> tenantJavaType;
        private String tenantJpqlExpression;
        private AuthzTenantScopeMode tenantScopeMode = AuthzTenantScopeMode.ORGANIZATIONAL_UNIT;
        private TenantScopeSpec tenantScopeSpec;
        private String hardScopeSubjectFactKey;
        private boolean allowGlobalNullScope = false;
        private boolean immutableTenantAnchor = false;
        private HardScopeResolver hardScopeResolver;
        private Function<E, String> entityTenantExtractor;
        private BiPredicate<E, AuthzCallerContext> entityScopePredicate;
        private Function<E, Map<String, Object>> targetFactExtractor;
        private String stateFieldName;
        private Function<E, String> stateExtractor;
        private String originEntityFieldPath;
        private String originSubjectFactKey;
        private BiPredicate<E, AuthzCallerContext> originCustodyPredicate;
        private String destinationEntityFieldPath;
        private String destinationSubjectFactKey;
        private BiPredicate<E, AuthzCallerContext> destinationCustodyPredicate;
        private final Map<String, Set<String>> operationModifiedAttributes = new LinkedHashMap<>();
        private final Map<String, DecisionPointDescriptor> actionDecisionPoints = new LinkedHashMap<>();
        private final Map<String, DecisionPointDescriptor> surfaceDecisionPoints = new LinkedHashMap<>();
        private final Map<String, DeclarativeActionEndpoint> declarativeWorkflowActions = new LinkedHashMap<>();
        private final Map<String, DeclarativeSurfaceEndpoint> declarativeUiSurfaces = new LinkedHashMap<>();
        private final List<DeclaredMaskSpec> maskSpecs = new ArrayList<>();
        private final Map<String, ActionRuleSpec> actionRuleSpecs = new LinkedHashMap<>();
        private final Map<String, ActionRuleSpec> surfaceRuleSpecs = new LinkedHashMap<>();

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
         * Configures the owning microservice/host {@code serviceKey} (e.g. {@code "praxis-workforce-showcase"}),
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
         * Enables opt-in emission and {@link FactContract} registration of the canonical
         * {@code action.verb} fact ({@code GET}, {@code POST}, {@code PATCH}, {@code PUT},
         * {@code DELETE}) during {@code TARGET} policy evaluations.
         */
        public Builder<E> withActionVerbFact() {
            this.includeActionVerbFact = true;
            return this;
        }

        /**
         * Ensures {@code subject.roles} is registered in the auto-derived {@link FactContract}
         * even when primary/scope rules inspect caller roles outside declarative action annotations.
         */
        public Builder<E> withSubjectRolesFact() {
            this.includeSubjectRolesFact = true;
            return this;
        }

        /**
         * Registers a subject fact descriptor in the auto-derived {@link FactContract}.
         */
        public Builder<E> subjectFact(
                String factPath,
                FactValueType valueType,
                FactCardinality cardinality,
                FactPresenceModel presenceModel
        ) {
            Objects.requireNonNull(factPath, "factPath is required");
            Objects.requireNonNull(valueType, "valueType is required");
            Objects.requireNonNull(cardinality, "cardinality is required");
            Objects.requireNonNull(presenceModel, "presenceModel is required");
            this.declarativeFacts.put(
                    factPath,
                    new FactDescriptor(
                            factPath,
                            FactSlotNamespace.SUBJECT,
                            valueType,
                            cardinality,
                            presenceModel,
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
            this.tenantFieldExplicitlySet = true;
            this.entityTenantExtractor = entityTenantExtractor;
            this.entityScopePredicate = entityScopePredicate;
            return this;
        }

        /**
         * Configures explicit multi-organization hard-scope isolation ({@code field IN values})
         * bound to {@code subjectFactKey} (e.g. {@code "subject.organizationUnitIds"}).
         */
        public Builder<E> multiOrganizationScope(String tenantFieldName, String subjectFactKey) {
            tenantField(tenantFieldName);
            this.tenantScopeMode = AuthzTenantScopeMode.ORGANIZATIONAL_UNIT;
            this.hardScopeSubjectFactKey = Objects.requireNonNull(subjectFactKey, "subjectFactKey is required").trim();
            return this;
        }

        /** Configures declarative tenant scope metadata resolved from {@link AuthzTenantScope}. */
        public Builder<E> tenantScope(TenantScopeSpec spec) {
            Objects.requireNonNull(spec, "tenantScopeSpec is required");
            this.tenantScopeSpec = spec;
            this.tenantScopeMode = spec.mode();
            if (!this.tenantFieldExplicitlySet && !spec.tenantField().isBlank()) {
                this.tenantFieldName = spec.tenantField();
            }
            if (spec.mode() == AuthzTenantScopeMode.ORGANIZATIONAL_UNIT) {
                this.hardScopeSubjectFactKey = spec.subjectFactPath();
            } else {
                this.hardScopeSubjectFactKey = null;
            }
            return this;
        }

        public Builder<E> allowGlobalNullScope(boolean allowGlobalNullScope) {
            this.allowGlobalNullScope = allowGlobalNullScope;
            return this;
        }

        public Builder<E> immutableTenantAnchor(boolean immutableTenantAnchor) {
            this.immutableTenantAnchor = immutableTenantAnchor;
            return this;
        }

        public Builder<E> hardScopeResolver(HardScopeResolver hardScopeResolver) {
            this.hardScopeResolver = Objects.requireNonNull(hardScopeResolver, "hardScopeResolver is required");
            return this;
        }

        public Builder<E> scopeAnchor(ScopeAnchorSpec anchorSpec) {
            Objects.requireNonNull(anchorSpec, "anchorSpec is required");
            this.scopeAnchorSpecs.add(anchorSpec);
            if (anchorSpec.requiredOnCreate() || anchorSpec.forbidClearOnUpdate()) {
                this.mandatoryScopeAnchorAttributeIds.add(anchorSpec.attributeId());
            }
            return this;
        }

        public Builder<E> maskDirective(DeclaredMaskSpec maskSpec) {
            this.maskSpecs.add(Objects.requireNonNull(maskSpec, "maskSpec is required"));
            return this;
        }

        public Builder<E> actionRule(ActionRuleSpec ruleSpec) {
            Objects.requireNonNull(ruleSpec, "ruleSpec is required");
            if (ruleSpec.targetsSurface()) {
                this.surfaceRuleSpecs.put(ruleSpec.surfaceKey(), ruleSpec);
            } else if (!ruleSpec.actionKey().isEmpty()) {
                this.actionRuleSpecs.put(ruleSpec.actionKey(), ruleSpec);
                if (!ruleSpec.allowedWriteAttributes().isEmpty()) {
                    Set<String> merged = new LinkedHashSet<>(
                            this.operationModifiedAttributes.getOrDefault(ruleSpec.actionKey(), Set.of()));
                    merged.addAll(ruleSpec.allowedWriteAttributes());
                    this.operationModifiedAttributes.put(ruleSpec.actionKey(), Set.copyOf(merged));
                }
            }
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
         * Declaratively binds authoritative origin custody evaluation to an entity field (e.g.
         * {@code "originOrgId"}) matched against a caller subject fact (e.g.
         * {@code "subject.originOrgIds"}) ({@code Fase P10.9}).
         */
        public Builder<E> originCustody(String entityFieldPath, String subjectFactKey) {
            this.originEntityFieldPath = Objects.requireNonNull(entityFieldPath, "entityFieldPath is required");
            this.originSubjectFactKey = Objects.requireNonNull(subjectFactKey, "subjectFactKey is required");
            return this;
        }

        /**
         * Configures a custom predicate for evaluating origin custody on an entity.
         */
        public Builder<E> originCustodyPredicate(BiPredicate<E, AuthzCallerContext> originCustodyPredicate) {
            this.originCustodyPredicate = Objects.requireNonNull(originCustodyPredicate, "originCustodyPredicate is required");
            return this;
        }

        /**
         * Declaratively binds delegated destination custody evaluation to an entity field (e.g.
         * {@code "destinationOrgId"}) matched against a caller subject fact (e.g.
         * {@code "subject.destinationOrgIds"}) ({@code Fase P10.9}).
         */
        public Builder<E> destinationCustody(String entityFieldPath, String subjectFactKey) {
            this.destinationEntityFieldPath = Objects.requireNonNull(entityFieldPath, "entityFieldPath is required");
            this.destinationSubjectFactKey = Objects.requireNonNull(subjectFactKey, "subjectFactKey is required");
            return this;
        }

        /**
         * Configures a custom predicate for evaluating destination custody on an entity.
         */
        public Builder<E> destinationCustodyPredicate(BiPredicate<E, AuthzCallerContext> destinationCustodyPredicate) {
            this.destinationCustodyPredicate = Objects.requireNonNull(destinationCustodyPredicate, "destinationCustodyPredicate is required");
            return this;
        }

        /** @deprecated Use {@link #originCustody(String, String)}. */
        @Deprecated(since = "0.1.0-beta.2")
        public Builder<E> cedenteCustody(String entityFieldPath, String subjectFactKey) {
            return originCustody(entityFieldPath, subjectFactKey);
        }

        /** @deprecated Use {@link #originCustodyPredicate(BiPredicate)}. */
        @Deprecated(since = "0.1.0-beta.2")
        public Builder<E> cedenteCustodyPredicate(BiPredicate<E, AuthzCallerContext> custodyPredicate) {
            return originCustodyPredicate(custodyPredicate);
        }

        /** @deprecated Use {@link #destinationCustody(String, String)}. */
        @Deprecated(since = "0.1.0-beta.2")
        public Builder<E> cessionarioCustody(String entityFieldPath, String subjectFactKey) {
            return destinationCustody(entityFieldPath, subjectFactKey);
        }

        /** @deprecated Use {@link #destinationCustodyPredicate(BiPredicate)}. */
        @Deprecated(since = "0.1.0-beta.2")
        public Builder<E> cessionarioCustodyPredicate(BiPredicate<E, AuthzCallerContext> custodyPredicate) {
            return destinationCustodyPredicate(custodyPredicate);
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
            return introspectFromResource(
                    entityClass,
                    responseDtoClass,
                    filterDtoClass,
                    null,
                    null,
                    controllerClass,
                    null
            );
        }

        /**
         * Introspects a Praxis resource's JPA entity, {@code ResponseDTO}, {@code FilterDTO},
         * optional write DTOs ({@code CreateDTO}/{@code UpdateDTO}), {@code Controller}, and optional
         * {@code Service} class to automatically resolve {@code @ApiResource}, {@code @WorkflowAction},
         * {@code @UiSurface}, {@code @Filterable}, {@code @DomainGovernance}, {@code @DomainLineage},
         * {@link AuthzTenantScope}, {@link AuthzScopeAnchor}, {@link AuthzCustodyPartition},
         * {@link AuthzMask}, and {@link AuthzActionRule}.
         */
        public Builder<E> introspectFromResource(
                Class<E> entityClass,
                Class<?> responseDtoClass,
                Class<?> filterDtoClass,
                Class<?> createDtoClass,
                Class<?> updateDtoClass,
                Class<?> controllerClass,
                Class<?> serviceClass
        ) {
            Objects.requireNonNull(entityClass, "entityClass is required");

            MetadataDtoGovernanceIntrospector introspector = new MetadataDtoGovernanceIntrospector();
            MetadataDtoGovernanceIntrospector.IntrospectedDtoGovernanceContract dtoContract = null;
            Map<String, DtoFieldSchemaMetadata> dtoSchemasByField = new LinkedHashMap<>();
            List<FieldLineageCatalogEntry> responseLineage = List.of();
            if (isDtoClass(responseDtoClass)) {
                dtoContract = introspector.introspect(responseDtoClass, this.resourceKey);
                for (DtoFieldSchemaMetadata schemaMeta : dtoContract.fieldSchemas()) {
                    dtoSchemasByField.put(schemaMeta.wireFieldName(), schemaMeta);
                }
                responseLineage = introspector.deriveDtoFieldLineageCatalogEntries(
                        this.resourceKey, responseDtoClass, "READ_PROJECTION", null);
            }

            MetadataDtoGovernanceIntrospector.IntrospectedDtoGovernanceContract createContract =
                    isDtoClass(createDtoClass)
                            ? introspector.introspectWriteDto(createDtoClass, responseDtoClass, this.resourceKey)
                            : null;
            MetadataDtoGovernanceIntrospector.IntrospectedDtoGovernanceContract updateContract =
                    isDtoClass(updateDtoClass)
                            ? introspector.introspectWriteDto(updateDtoClass, responseDtoClass, this.resourceKey)
                            : null;

            introspectTenantScopeAnnotations(entityClass, controllerClass, serviceClass);

            if (controllerClass != null) {
                introspectControllerEndpoints(controllerClass, dtoContract, responseDtoClass, introspector);
            }
            if (serviceClass != null) {
                introspectActionRulesOnTypeAndMethods(serviceClass);
            }
            introspectActionRulesOnTypeAndMethods(entityClass);

            Set<String> filterPaths = collectFilterPaths(filterDtoClass);
            introspectEntityFields(entityClass, dtoContract, filterPaths);
            registerSensitiveDtoFacts(responseLineage, dtoSchemasByField);

            introspectScopeAnchorAnnotations(
                    entityClass, responseDtoClass, createDtoClass, updateDtoClass,
                    controllerClass, serviceClass,
                    dtoContract, createContract, updateContract
            );
            introspectCustodyPartitionAnnotations(
                    entityClass, responseDtoClass, createDtoClass, updateDtoClass,
                    controllerClass, serviceClass,
                    dtoContract, createContract, updateContract
            );
            introspectMaskAnnotations(dtoContract, entityClass, controllerClass, serviceClass);
            return this;
        }

        private static boolean isDtoClass(Class<?> candidate) {
            return candidate != null
                    && candidate != Object.class
                    && !Map.class.isAssignableFrom(candidate);
        }

        private void introspectTenantScopeAnnotations(
                Class<E> entityClass,
                Class<?> controllerClass,
                Class<?> serviceClass
        ) {
            AuthzTenantScope found = null;
            String memberFieldOverride = null;

            if (serviceClass != null) {
                found = AnnotatedElementUtils.findMergedAnnotation(serviceClass, AuthzTenantScope.class);
            }
            if (found == null && controllerClass != null) {
                found = AnnotatedElementUtils.findMergedAnnotation(controllerClass, AuthzTenantScope.class);
            }
            if (found == null) {
                found = AnnotatedElementUtils.findMergedAnnotation(entityClass, AuthzTenantScope.class);
            }
            if (found == null) {
                for (Field field : collectEntityHierarchyFields(entityClass)) {
                    AuthzTenantScope fieldAnn = AnnotatedElementUtils.findMergedAnnotation(field, AuthzTenantScope.class);
                    if (fieldAnn != null) {
                        found = fieldAnn;
                        memberFieldOverride = field.getName();
                        break;
                    }
                }
            }
            if (found == null) {
                for (Method method : collectSortedHierarchyMethods(entityClass)) {
                    if (method.getParameterCount() == 0 && method.getReturnType() != void.class) {
                        AuthzTenantScope methodAnn = AnnotatedElementUtils.findMergedAnnotation(method, AuthzTenantScope.class);
                        if (methodAnn != null) {
                            found = methodAnn;
                            memberFieldOverride = extractGetterProperty(method);
                            break;
                        }
                    }
                }
            }

            if (found != null) {
                String resolvedField = found.tenantField();
                if ((resolvedField == null || resolvedField.isBlank() || "tenantId".equals(resolvedField))
                        && memberFieldOverride != null && !memberFieldOverride.isBlank()) {
                    resolvedField = memberFieldOverride;
                }
                if ((resolvedField == null || resolvedField.isBlank() || "tenantId".equals(resolvedField))
                        && this.tenantFieldExplicitlySet) {
                    resolvedField = this.tenantFieldName;
                }
                String resolvedSubjectFactPath = found.subjectFactPath();
                if (found.mode() == AuthzTenantScopeMode.TENANT_ONLY
                        && "subject.organizationUnitIds".equals(resolvedSubjectFactPath)) {
                    resolvedSubjectFactPath = "";
                }
                tenantScope(new TenantScopeSpec(
                        found.mode(),
                        resolvedField,
                        found.resourceFactPath(),
                        resolvedSubjectFactPath,
                        found.policyId(),
                        found.ruleId(),
                        found.allowBulkWithoutScope(),
                        found.sharedBulkNonNullFactPath()
                ));
            }
        }

        private void introspectControllerEndpoints(
                Class<?> controllerClass,
                MetadataDtoGovernanceIntrospector.IntrospectedDtoGovernanceContract dtoContract,
                Class<?> responseDtoClass,
                MetadataDtoGovernanceIntrospector introspector
        ) {
            String basePath = resolveControllerBasePath(controllerClass);
            if (this.httpPath == null && basePath != null) {
                this.httpPath = joinHttpPaths(basePath, this.operationKey);
            }

            introspectActionRulesOnTypeAndMethods(controllerClass);

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
                    collectMethodAuthzActionRules(method, actionId, "");
                    if (!this.operationModifiedAttributes.containsKey(actionId)
                            || this.operationModifiedAttributes.get(actionId).isEmpty()) {
                        Set<String> dtoAttrs = extractRequestBodyWriteAttributes(
                                method, dtoContract, responseDtoClass, introspector);
                        if (!dtoAttrs.isEmpty()) {
                            this.operationModifiedAttributes.put(actionId, dtoAttrs);
                        }
                    }
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
                        collectMethodAuthzActionRules(method, "", surfId);
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

        private void introspectActionRulesOnTypeAndMethods(Class<?> targetClass) {
            if (targetClass == null || targetClass == Object.class) {
                return;
            }
            for (AuthzActionRule rule : AnnotatedElementUtils.findMergedRepeatableAnnotations(targetClass, AuthzActionRule.class)) {
                actionRule(toActionRuleSpec(rule, rule.actionKey(), rule.surfaceKey()));
            }
            for (Method method : collectSortedHierarchyMethods(targetClass)) {
                WorkflowAction wf = AnnotatedElementUtils.findMergedAnnotation(method, WorkflowAction.class);
                UiSurface surf = AnnotatedElementUtils.findMergedAnnotation(method, UiSurface.class);
                String defaultActionKey = (wf != null && wf.id() != null) ? wf.id().trim() : "";
                String defaultSurfaceKey = (surf != null && surf.id() != null) ? surf.id().trim() : "";
                collectMethodAuthzActionRules(method, defaultActionKey, defaultSurfaceKey);
            }
        }

        private void collectMethodAuthzActionRules(
                Method method,
                String defaultActionKey,
                String defaultSurfaceKey
        ) {
            for (AuthzActionRule rule : AnnotatedElementUtils.findMergedRepeatableAnnotations(method, AuthzActionRule.class)) {
                String ak = (rule.actionKey() != null && !rule.actionKey().isBlank())
                        ? rule.actionKey().trim()
                        : defaultActionKey;
                String sk = (rule.surfaceKey() != null && !rule.surfaceKey().isBlank())
                        ? rule.surfaceKey().trim()
                        : defaultSurfaceKey;
                if (!ak.isEmpty() || !sk.isEmpty()) {
                    actionRule(toActionRuleSpec(rule, ak, sk));
                }
            }
        }

        private static ActionRuleSpec toActionRuleSpec(
                AuthzActionRule rule,
                String resolvedActionKey,
                String resolvedSurfaceKey
        ) {
            Set<EvaluationMode> modes = (rule.evaluationModes() == null || rule.evaluationModes().length == 0)
                    ? Set.of()
                    : Set.of(rule.evaluationModes());
            Set<String> roles = new LinkedHashSet<>();
            if (rule.requiredRoles() != null) {
                for (String r : rule.requiredRoles()) {
                    if (r != null && !r.isBlank()) {
                        roles.add(r.trim());
                    }
                }
            }
            List<String> allowedVals = new ArrayList<>();
            if (rule.conditionAllowedValues() != null) {
                for (String v : rule.conditionAllowedValues()) {
                    if (v != null && !v.isBlank()) {
                        allowedVals.add(v.trim());
                    }
                }
            }
            Set<String> writes = new LinkedHashSet<>();
            if (rule.allowedWriteAttributes() != null) {
                for (String w : rule.allowedWriteAttributes()) {
                    if (w != null && !w.isBlank()) {
                        writes.add(w.trim());
                    }
                }
            }
            return new ActionRuleSpec(
                    resolvedActionKey,
                    resolvedSurfaceKey,
                    rule.ruleId(),
                    rule.policyId(),
                    modes,
                    rule.requireAuthenticatedPrincipal(),
                    roles,
                    rule.conditionFactPath(),
                    allowedVals,
                    rule.conditionJsonLogic(),
                    writes,
                    rule.reasonCode(),
                    rule.auditRequired(),
                    rule.auditCategory(),
                    rule.legalPurpose(),
                    rule.legalBasisRef(),
                    rule.description()
            );
        }

        private Set<String> extractRequestBodyWriteAttributes(
                Method method,
                MetadataDtoGovernanceIntrospector.IntrospectedDtoGovernanceContract responseContract,
                Class<?> responseDtoClass,
                MetadataDtoGovernanceIntrospector introspector
        ) {
            Set<String> attrs = new LinkedHashSet<>();
            for (java.lang.reflect.Parameter param : method.getParameters()) {
                if (AnnotatedElementUtils.hasAnnotation(param, RequestBody.class)) {
                    Class<?> bodyType = param.getType();
                    if (isDtoClass(bodyType)
                            && !bodyType.isPrimitive()
                            && !CharSequence.class.isAssignableFrom(bodyType)
                            && !Number.class.isAssignableFrom(bodyType)
                            && !Collection.class.isAssignableFrom(bodyType)) {
                        var cmdContract = introspector.introspectWriteDto(bodyType, responseDtoClass, this.resourceKey);
                        for (DtoFieldSchemaMetadata schema : cmdContract.fieldSchemas()) {
                            attrs.add(schema.attributeId());
                        }
                    }
                }
            }
            return attrs;
        }

        private void introspectScopeAnchorAnnotations(
                Class<E> entityClass,
                Class<?> responseDtoClass,
                Class<?> createDtoClass,
                Class<?> updateDtoClass,
                Class<?> controllerClass,
                Class<?> serviceClass,
                MetadataDtoGovernanceIntrospector.IntrospectedDtoGovernanceContract responseContract,
                MetadataDtoGovernanceIntrospector.IntrospectedDtoGovernanceContract createContract,
                MetadataDtoGovernanceIntrospector.IntrospectedDtoGovernanceContract updateContract
        ) {
            for (Class<?> ownerType : List.of(
                    nonNullOrVoid(serviceClass),
                    nonNullOrVoid(controllerClass),
                    nonNullOrVoid(entityClass),
                    nonNullOrVoid(responseDtoClass),
                    nonNullOrVoid(createDtoClass),
                    nonNullOrVoid(updateDtoClass))) {
                if (ownerType == Void.class) {
                    continue;
                }
                for (AuthzScopeAnchor anchor : AnnotatedElementUtils.findMergedRepeatableAnnotations(ownerType, AuthzScopeAnchor.class)) {
                    if (anchor.attributeId() != null && !anchor.attributeId().isBlank()) {
                        String attrId = anchor.attributeId().trim();
                        scopeAnchor(new ScopeAnchorSpec(
                                attrId,
                                anchor.factPath(),
                                anchor.requiredOnCreate(),
                                anchor.forbidClearOnUpdate(),
                                anchor.immutableAfterCreate(),
                                anchor.reason()
                        ));
                        if (anchor.immutableAfterCreate() && isTenantFieldAttribute(attrId, responseContract)) {
                            this.immutableTenantAnchor = true;
                        }
                    }
                }
            }

            scanMemberScopeAnchors(entityClass, responseContract, createContract, updateContract);
            scanMemberScopeAnchors(responseDtoClass, responseContract, createContract, updateContract);
            scanMemberScopeAnchors(createDtoClass, responseContract, createContract, updateContract);
            scanMemberScopeAnchors(updateDtoClass, responseContract, createContract, updateContract);
        }

        private void scanMemberScopeAnchors(
                Class<?> type,
                MetadataDtoGovernanceIntrospector.IntrospectedDtoGovernanceContract responseContract,
                MetadataDtoGovernanceIntrospector.IntrospectedDtoGovernanceContract createContract,
                MetadataDtoGovernanceIntrospector.IntrospectedDtoGovernanceContract updateContract
        ) {
            if (!isDtoClass(type)) {
                return;
            }
            if (type.isRecord()) {
                for (RecordComponent rc : type.getRecordComponents()) {
                    processMemberScopeAnchors(rc, rc.getName(), responseContract, createContract, updateContract);
                    if (rc.getAccessor() != null) {
                        processMemberScopeAnchors(rc.getAccessor(), rc.getName(), responseContract, createContract, updateContract);
                    }
                }
            }
            for (Field f : collectEntityHierarchyFields(type)) {
                processMemberScopeAnchors(f, f.getName(), responseContract, createContract, updateContract);
            }
            for (Method m : collectSortedHierarchyMethods(type)) {
                if (m.getParameterCount() == 0 && m.getReturnType() != void.class) {
                    String prop = extractGetterProperty(m);
                    if (prop != null) {
                        processMemberScopeAnchors(m, prop, responseContract, createContract, updateContract);
                    }
                }
            }
        }

        private void processMemberScopeAnchors(
                AnnotatedElement el,
                String propertyName,
                MetadataDtoGovernanceIntrospector.IntrospectedDtoGovernanceContract responseContract,
                MetadataDtoGovernanceIntrospector.IntrospectedDtoGovernanceContract createContract,
                MetadataDtoGovernanceIntrospector.IntrospectedDtoGovernanceContract updateContract
        ) {
            for (AuthzScopeAnchor anchor : AnnotatedElementUtils.findMergedRepeatableAnnotations(el, AuthzScopeAnchor.class)) {
                String attrId = resolveMemberAttributeId(
                        anchor.attributeId(), el, propertyName, responseContract, createContract, updateContract);
                String factPath = (anchor.factPath() != null && !anchor.factPath().isBlank())
                        ? anchor.factPath().trim()
                        : "resource." + propertyName;
                scopeAnchor(new ScopeAnchorSpec(
                        attrId,
                        factPath,
                        anchor.requiredOnCreate(),
                        anchor.forbidClearOnUpdate(),
                        anchor.immutableAfterCreate(),
                        anchor.reason()
                ));
                if (anchor.immutableAfterCreate() && propertyName.equals(this.tenantFieldName)) {
                    this.immutableTenantAnchor = true;
                }
            }
        }

        private boolean isTenantFieldAttribute(
                String attributeId,
                MetadataDtoGovernanceIntrospector.IntrospectedDtoGovernanceContract responseContract
        ) {
            if (this.tenantFieldName == null) {
                return false;
            }
            String expected = resolveAttributeIdForPath(this.tenantFieldName, responseContract);
            return attributeId.equals(expected);
        }

        private void introspectCustodyPartitionAnnotations(
                Class<E> entityClass,
                Class<?> responseDtoClass,
                Class<?> createDtoClass,
                Class<?> updateDtoClass,
                Class<?> controllerClass,
                Class<?> serviceClass,
                MetadataDtoGovernanceIntrospector.IntrospectedDtoGovernanceContract responseContract,
                MetadataDtoGovernanceIntrospector.IntrospectedDtoGovernanceContract createContract,
                MetadataDtoGovernanceIntrospector.IntrospectedDtoGovernanceContract updateContract
        ) {
            AuthzDelegationSplitMode mode = AuthzDelegationSplitMode.ORIGIN_DESTINATION_SPLIT;
            boolean hasPartition = false;
            String originField = this.originEntityFieldPath;
            String originFact = null;
            String originSubj = this.originSubjectFactKey;
            String destField = this.destinationEntityFieldPath;
            String destFact = null;
            String destSubj = this.destinationSubjectFactKey;
            Set<String> originWrites = new LinkedHashSet<>();
            Set<String> destWrites = new LinkedHashSet<>();

            if (this.dualScopeDelegationSpec != null) {
                hasPartition = true;
                originFact = this.dualScopeDelegationSpec.originFactPath();
                destFact = this.dualScopeDelegationSpec.destinationFactPath();
                originWrites.addAll(this.dualScopeDelegationSpec.originExclusiveWriteAttributes());
                destWrites.addAll(this.dualScopeDelegationSpec.destinationAllowedWriteAttributes());
            }

            for (Class<?> ownerType : List.of(
                    nonNullOrVoid(serviceClass),
                    nonNullOrVoid(controllerClass),
                    nonNullOrVoid(entityClass),
                    nonNullOrVoid(responseDtoClass),
                    nonNullOrVoid(createDtoClass),
                    nonNullOrVoid(updateDtoClass))) {
                if (ownerType == Void.class) {
                    continue;
                }
                AuthzCustodyPartition typeAnn = AnnotatedElementUtils.findMergedAnnotation(ownerType, AuthzCustodyPartition.class);
                if (typeAnn != null) {
                    hasPartition = true;
                    mode = typeAnn.mode();
                    if (!typeAnn.originEntityField().isBlank() && originField == null) {
                        originField = typeAnn.originEntityField().trim();
                    }
                    if (!typeAnn.originFactPath().isBlank() && originFact == null) {
                        originFact = typeAnn.originFactPath().trim();
                    }
                    if (!typeAnn.originSubjectFactKey().isBlank() && originSubj == null) {
                        originSubj = typeAnn.originSubjectFactKey().trim();
                    }
                    if (!typeAnn.destinationEntityField().isBlank() && destField == null) {
                        destField = typeAnn.destinationEntityField().trim();
                    }
                    if (!typeAnn.destinationFactPath().isBlank() && destFact == null) {
                        destFact = typeAnn.destinationFactPath().trim();
                    }
                    if (!typeAnn.destinationSubjectFactKey().isBlank() && destSubj == null) {
                        destSubj = typeAnn.destinationSubjectFactKey().trim();
                    }
                    for (String a : typeAnn.originExclusiveWriteAttributes()) {
                        if (a != null && !a.isBlank()) {
                            originWrites.add(a.trim());
                        }
                    }
                    for (String a : typeAnn.destinationAllowedWriteAttributes()) {
                        if (a != null && !a.isBlank()) {
                            destWrites.add(a.trim());
                        }
                    }
                }
            }

            List<MemberCustodyInfo> memberInfos = new ArrayList<>();
            collectMemberCustodyInfo(entityClass, responseContract, createContract, updateContract, memberInfos);
            collectMemberCustodyInfo(responseDtoClass, responseContract, createContract, updateContract, memberInfos);
            collectMemberCustodyInfo(createDtoClass, responseContract, createContract, updateContract, memberInfos);
            collectMemberCustodyInfo(updateDtoClass, responseContract, createContract, updateContract, memberInfos);

            for (MemberCustodyInfo info : memberInfos) {
                hasPartition = true;
                AuthzCustodyPartition ann = info.ann();
                if (ann.custodyAnchor()) {
                    if (ann.role() == AuthzCustodyRole.ORIGIN) {
                        if (originField == null) {
                            originField = info.propertyName();
                        }
                        if (originFact == null) {
                            originFact = !ann.originFactPath().isBlank()
                                    ? ann.originFactPath().trim()
                                    : "resource." + info.propertyName();
                        }
                        if (originSubj == null && !ann.subjectFactPath().isBlank()) {
                            originSubj = ann.subjectFactPath().trim();
                        }
                    } else if (ann.role() == AuthzCustodyRole.DESTINATION) {
                        if (destField == null) {
                            destField = info.propertyName();
                        }
                        if (destFact == null) {
                            destFact = !ann.destinationFactPath().isBlank()
                                    ? ann.destinationFactPath().trim()
                                    : "resource." + info.propertyName();
                        }
                        if (destSubj == null && !ann.subjectFactPath().isBlank()) {
                            destSubj = ann.subjectFactPath().trim();
                        }
                    }
                } else {
                    if (ann.role() == AuthzCustodyRole.ORIGIN) {
                        originWrites.add(info.attributeId());
                    } else if (ann.role() == AuthzCustodyRole.DESTINATION) {
                        destWrites.add(info.attributeId());
                    }
                }
            }

            if (!hasPartition) {
                return;
            }
            if (originFact == null && originField != null) {
                originFact = "resource." + originField;
            }
            if (destFact == null && destField != null) {
                destFact = "resource." + destField;
            }
            if (originField != null && originSubj == null) {
                originSubj = (this.tenantScopeSpec != null
                        && originField.equals(this.tenantFieldName)
                        && !this.tenantScopeSpec.subjectFactPath().isBlank())
                        ? this.tenantScopeSpec.subjectFactPath()
                        : "subject.originUnitIds";
            }
            if (destField != null && destSubj == null) {
                destSubj = "subject.destinationUnitIds";
            }
            if (originField != null && originSubj != null && this.originEntityFieldPath == null) {
                originCustody(originField, originSubj);
            }
            if (destField != null && destSubj != null && this.destinationEntityFieldPath == null) {
                destinationCustody(destField, destSubj);
            }
            if (originFact != null && destFact != null && this.dualScopeDelegationSpec == null) {
                dualScopeDelegationSpec(DualScopeDelegationSpec.ofOriginAndDestination(
                        mode.name(),
                        originFact,
                        destFact,
                        originWrites,
                        destWrites
                ));
            }
        }

        private record MemberCustodyInfo(String propertyName, String attributeId, AuthzCustodyPartition ann) {}

        private void collectMemberCustodyInfo(
                Class<?> type,
                MetadataDtoGovernanceIntrospector.IntrospectedDtoGovernanceContract responseContract,
                MetadataDtoGovernanceIntrospector.IntrospectedDtoGovernanceContract createContract,
                MetadataDtoGovernanceIntrospector.IntrospectedDtoGovernanceContract updateContract,
                List<MemberCustodyInfo> target
        ) {
            if (!isDtoClass(type)) {
                return;
            }
            if (type.isRecord()) {
                for (RecordComponent rc : type.getRecordComponents()) {
                    addCustodyIfPresent(rc, rc.getName(), responseContract, createContract, updateContract, target);
                    if (rc.getAccessor() != null) {
                        addCustodyIfPresent(rc.getAccessor(), rc.getName(), responseContract, createContract, updateContract, target);
                    }
                }
            }
            for (Field f : collectEntityHierarchyFields(type)) {
                addCustodyIfPresent(f, f.getName(), responseContract, createContract, updateContract, target);
            }
            for (Method m : collectSortedHierarchyMethods(type)) {
                if (m.getParameterCount() == 0 && m.getReturnType() != void.class) {
                    String prop = extractGetterProperty(m);
                    if (prop != null) {
                        addCustodyIfPresent(m, prop, responseContract, createContract, updateContract, target);
                    }
                }
            }
        }

        private void addCustodyIfPresent(
                AnnotatedElement el,
                String propertyName,
                MetadataDtoGovernanceIntrospector.IntrospectedDtoGovernanceContract responseContract,
                MetadataDtoGovernanceIntrospector.IntrospectedDtoGovernanceContract createContract,
                MetadataDtoGovernanceIntrospector.IntrospectedDtoGovernanceContract updateContract,
                List<MemberCustodyInfo> target
        ) {
            AuthzCustodyPartition ann = AnnotatedElementUtils.findMergedAnnotation(el, AuthzCustodyPartition.class);
            if (ann == null) {
                return;
            }
            String attrId = resolveMemberAttributeId(
                    ann.attributeId(), el, propertyName, responseContract, createContract, updateContract);
            target.add(new MemberCustodyInfo(propertyName, attrId, ann));
        }

        private void introspectMaskAnnotations(
                MetadataDtoGovernanceIntrospector.IntrospectedDtoGovernanceContract dtoContract,
                Class<E> entityClass,
                Class<?> controllerClass,
                Class<?> serviceClass
        ) {
            Set<String> explicitAttrIds = new LinkedHashSet<>();
            Set<String> seenKeys = new LinkedHashSet<>();

            for (Class<?> ownerType : List.of(
                    nonNullOrVoid(serviceClass),
                    nonNullOrVoid(controllerClass),
                    nonNullOrVoid(entityClass))) {
                if (ownerType == Void.class) {
                    continue;
                }
                for (AuthzMask mask : AnnotatedElementUtils.findMergedRepeatableAnnotations(ownerType, AuthzMask.class)) {
                    if (mask.attributeId() != null && !mask.attributeId().isBlank()) {
                        DeclaredMaskSpec spec = MetadataDtoGovernanceIntrospector.toDeclaredMaskSpec(
                                mask, mask.attributeId().trim());
                        addUniqueMaskSpec(spec, explicitAttrIds, seenKeys);
                    }
                }
            }

            if (dtoContract != null) {
                for (DeclaredMaskSpec declared : dtoContract.declaredMasks()) {
                    addUniqueMaskSpec(declared, explicitAttrIds, seenKeys);
                }
                for (MaskContributionSpec derived : dtoContract.derivedMasks()) {
                    Set<String> attrs = derived.fieldSelector() != null
                            ? derived.fieldSelector().attributeIds()
                            : Set.of();
                    boolean overridden = !attrs.isEmpty() && attrs.stream().allMatch(explicitAttrIds::contains);
                    if (!overridden) {
                        DeclaredMaskSpec spec = new DeclaredMaskSpec(
                                derived,
                                Set.of(EvaluationMode.SEARCH, EvaluationMode.TARGET),
                                Set.of(),
                                "Derived automatically from @DomainGovernance classification"
                        );
                        addUniqueMaskSpec(spec, explicitAttrIds, seenKeys);
                    }
                }
            }
        }

        private void addUniqueMaskSpec(
                DeclaredMaskSpec spec,
                Set<String> explicitAttrIds,
                Set<String> seenKeys
        ) {
            Set<String> attrs = spec.contribution().fieldSelector() != null
                    ? spec.contribution().fieldSelector().attributeIds()
                    : Set.of();
            String key = attrs + "|" + spec.contribution().strategyId() + "|" + spec.surfaces() + "|" + spec.modes();
            if (seenKeys.add(key)) {
                this.maskSpecs.add(spec);
                explicitAttrIds.addAll(attrs);
            }
        }

        private String resolveMemberAttributeId(
                String explicitAttributeId,
                AnnotatedElement el,
                String propertyName,
                MetadataDtoGovernanceIntrospector.IntrospectedDtoGovernanceContract responseContract,
                MetadataDtoGovernanceIntrospector.IntrospectedDtoGovernanceContract createContract,
                MetadataDtoGovernanceIntrospector.IntrospectedDtoGovernanceContract updateContract
        ) {
            if (explicitAttributeId != null && !explicitAttributeId.isBlank()) {
                return explicitAttributeId.trim();
            }
            DomainLineage lineage = AnnotatedElementUtils.findMergedAnnotation(el, DomainLineage.class);
            if (lineage != null && lineage.attributeId() != null && !lineage.attributeId().isBlank()) {
                return lineage.attributeId().trim();
            }
            for (var contract : List.of(
                    responseContract != null ? responseContract : emptyContract(),
                    createContract != null ? createContract : emptyContract(),
                    updateContract != null ? updateContract : emptyContract())) {
                String mapped = contract.wirePointerToAttributeIdMap().get("/" + propertyName);
                if (mapped != null) {
                    return mapped;
                }
            }
            return resolveAttributeIdForPath(propertyName, responseContract);
        }

        private MetadataDtoGovernanceIntrospector.IntrospectedDtoGovernanceContract emptyContract() {
            return new MetadataDtoGovernanceIntrospector.IntrospectedDtoGovernanceContract(
                    this.resourceKey, Object.class, List.of(), Set.of(), Set.of(), List.of(), Map.of());
        }

        private static Class<?> nonNullOrVoid(Class<?> clazz) {
            return clazz == null ? Void.class : clazz;
        }

        private void introspectControllerEndpoints(Class<?> controllerClass) {
            introspectControllerEndpoints(controllerClass, null, null, null);
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
                    boolean isTenantScopeField = fieldName.equals(this.tenantFieldName);
                    boolean nullable = isNullableEntityField(field)
                            || (isTenantScopeField && this.allowGlobalNullScope);
                    scalarFieldBinding(
                            factPath,
                            attributeId,
                            fieldName,
                            valueType,
                            defaultOperatorsForValueType(valueType),
                            nullable
                    );
                    if (isTenantScopeField
                            && !this.allowGlobalNullScope
                            && this.tenantScopeMode != AuthzTenantScopeMode.AUTHENTICATED_SHARED) {
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
                String trimmedPath = candidatePath.trim();
                String factPath = "resource." + trimmedPath.replace('.', '_');
                if (!registeredFactPaths.add(factPath)) {
                    continue;
                }
                String attributeId = resolveAttributeIdForPath(trimmedPath, dtoContract);
                Set<SearchPredicateOperator> operators = defaultOperatorsForValueType(resolved.valueType());
                if (resolved.collectionTraversal()) {
                    collectionFieldBinding(factPath, attributeId, trimmedPath, resolved.valueType(), operators, true);
                } else {
                    boolean isTenantScopePath = trimmedPath.equals(this.tenantFieldName);
                    scalarFieldBinding(
                            factPath,
                            attributeId,
                            trimmedPath,
                            resolved.valueType(),
                            operators,
                            resolved.nullable() || (isTenantScopePath && this.allowGlobalNullScope)
                    );
                    if (isTenantScopePath
                            && !this.allowGlobalNullScope
                            && this.tenantScopeMode != AuthzTenantScopeMode.AUTHENTICATED_SHARED) {
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
                if (this.includeActionVerbFact) {
                    facts.putIfAbsent(
                            "action.verb",
                            new FactDescriptor(
                                    "action.verb",
                                    FactSlotNamespace.ACTION,
                                    FactValueType.STRING,
                                    FactCardinality.SCALAR,
                                    FactPresenceModel.MAY_BE_ABSENT,
                                    null,
                                    null,
                                    FactResolutionStage.EXTRACT,
                                    Set.of(ContextEvaluationPhase.TARGET),
                                    false,
                                    "INTERNAL",
                                    "OPERATIONAL",
                                    Set.of(),
                                    legalBasis,
                                    null
                            )
                    );
                }
                boolean requiresSubjectRoles = this.includeSubjectRolesFact
                        || this.actionRuleSpecs.values().stream().anyMatch(r -> !r.requiredRoles().isEmpty())
                        || this.surfaceRuleSpecs.values().stream().anyMatch(r -> !r.requiredRoles().isEmpty());
                if (requiresSubjectRoles) {
                    facts.putIfAbsent(
                            "subject.roles",
                            new FactDescriptor(
                                    "subject.roles",
                                    FactSlotNamespace.SUBJECT,
                                    FactValueType.STRING,
                                    FactCardinality.SET,
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
                }
                if (this.tenantScopeSpec != null
                        && this.tenantScopeSpec.subjectFactPath().startsWith("subject.")
                        && !"subject.principalId".equals(this.tenantScopeSpec.subjectFactPath())
                        && !"subject.organizationUnitIds".equals(this.tenantScopeSpec.subjectFactPath())) {
                    facts.putIfAbsent(
                            this.tenantScopeSpec.subjectFactPath(),
                            new FactDescriptor(
                                    this.tenantScopeSpec.subjectFactPath(),
                                    FactSlotNamespace.SUBJECT,
                                    this.tenantScopeMode == AuthzTenantScopeMode.TENANT_ONLY
                                            ? FactValueType.STRING
                                            : FactValueType.INT64,
                                    this.tenantScopeMode == AuthzTenantScopeMode.TENANT_ONLY
                                            ? FactCardinality.SCALAR
                                            : FactCardinality.SET,
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
                }
                if (this.tenantScopeSpec != null
                        && this.tenantScopeSpec.mode() != AuthzTenantScopeMode.AUTHENTICATED_SHARED
                        && this.tenantScopeSpec.resourceFactPath().startsWith("resource.")) {
                    facts.putIfAbsent(
                            this.tenantScopeSpec.resourceFactPath(),
                            new FactDescriptor(
                                    this.tenantScopeSpec.resourceFactPath(),
                                    FactSlotNamespace.RESOURCE,
                                    this.tenantScopeSpec.mode() == AuthzTenantScopeMode.TENANT_ONLY
                                            ? FactValueType.STRING
                                            : FactValueType.INT64,
                                    FactCardinality.SCALAR,
                                    FactPresenceModel.MAY_BE_ABSENT,
                                    this.tenantScopeSpec.tenantField(),
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
                if (this.tenantScopeSpec != null
                        && !this.tenantScopeSpec.sharedBulkNonNullFactPath().isBlank()) {
                    putSyntheticRuleFactIfAbsent(facts, this.tenantScopeSpec.sharedBulkNonNullFactPath(), legalBasis);
                }
                for (ActionRuleSpec rule : this.actionRuleSpecs.values()) {
                    putSyntheticRuleFactIfAbsent(facts, rule.conditionFactPath(), legalBasis);
                    putSyntheticJsonLogicFactsIfAbsent(facts, rule.conditionJsonLogic(), legalBasis);
                }
                for (ActionRuleSpec rule : this.surfaceRuleSpecs.values()) {
                    putSyntheticRuleFactIfAbsent(facts, rule.conditionFactPath(), legalBasis);
                    putSyntheticJsonLogicFactsIfAbsent(facts, rule.conditionJsonLogic(), legalBasis);
                }
                if (this.originSubjectFactKey != null && this.originSubjectFactKey.startsWith("subject.")) {
                    facts.putIfAbsent(
                            this.originSubjectFactKey,
                            new FactDescriptor(
                                    this.originSubjectFactKey,
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
                if (this.destinationSubjectFactKey != null && this.destinationSubjectFactKey.startsWith("subject.")) {
                    facts.putIfAbsent(
                            this.destinationSubjectFactKey,
                            new FactDescriptor(
                                    this.destinationSubjectFactKey,
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
                    String origFact = this.dualScopeDelegationSpec.originFactPath();
                    if (origFact != null && origFact.startsWith("resource.")) {
                        facts.putIfAbsent(
                                origFact,
                                new FactDescriptor(
                                        origFact,
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
                    String destFact = this.dualScopeDelegationSpec.destinationFactPath();
                    if (destFact != null && destFact.startsWith("resource.")) {
                        facts.putIfAbsent(
                                destFact,
                                new FactDescriptor(
                                        destFact,
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
                    if (this.dualScopeDelegationSpec.originExclusiveWriteAttributes() != null) {
                        declaredWriteOrAnchorAttrs.addAll(this.dualScopeDelegationSpec.originExclusiveWriteAttributes());
                    }
                    if (this.dualScopeDelegationSpec.destinationAllowedWriteAttributes() != null) {
                        declaredWriteOrAnchorAttrs.addAll(this.dualScopeDelegationSpec.destinationAllowedWriteAttributes());
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
                        ActionRuleSpec ruleSpec = this.actionRuleSpecs.get(act.actionKey());
                        boolean explicitNoFieldWrites = ruleSpec != null
                                && ruleSpec.allowedWriteAttributes().isEmpty()
                                && this.operationModifiedAttributes.getOrDefault(act.actionKey(), Set.of()).isEmpty();
                        Set<EnforcementCapability> actCapabilities;
                        if (act.bulkCollectionScope()) {
                            actCapabilities = explicitNoFieldWrites
                                    ? Set.of(EnforcementCapability.ACCESS, EnforcementCapability.DATA_SCOPE)
                                    : Set.of(
                                            EnforcementCapability.ACCESS,
                                            EnforcementCapability.DATA_SCOPE,
                                            EnforcementCapability.FIELD_WRITE
                                    );
                        } else {
                            actCapabilities = explicitNoFieldWrites
                                    ? Set.of(EnforcementCapability.ACCESS)
                                    : Set.of(
                                            EnforcementCapability.ACCESS,
                                            EnforcementCapability.FIELD_WRITE
                                    );
                        }
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

        private static void putSyntheticJsonLogicFactsIfAbsent(
                Map<String, FactDescriptor> facts,
                String conditionJsonLogic,
                String legalBasis
        ) {
            if (conditionJsonLogic == null || conditionJsonLogic.isBlank()) {
                return;
            }
            try {
                com.fasterxml.jackson.databind.JsonNode root =
                        new com.fasterxml.jackson.databind.ObjectMapper().readTree(conditionJsonLogic);
                collectJsonLogicVars(root, facts, legalBasis);
            } catch (Exception ignored) {
                // Invalid JSON-Logic will be caught with clear context during policy synthesis/compilation.
            }
        }

        private static void collectJsonLogicVars(
                com.fasterxml.jackson.databind.JsonNode node,
                Map<String, FactDescriptor> facts,
                String legalBasis
        ) {
            if (node == null) {
                return;
            }
            if (node.isObject()) {
                if (node.has("var") && node.get("var").isTextual()) {
                    putSyntheticRuleFactIfAbsent(facts, node.get("var").asText(), legalBasis);
                }
                node.fields().forEachRemaining(e -> collectJsonLogicVars(e.getValue(), facts, legalBasis));
            } else if (node.isArray()) {
                for (com.fasterxml.jackson.databind.JsonNode child : node) {
                    collectJsonLogicVars(child, facts, legalBasis);
                }
            }
        }

        private static void putSyntheticRuleFactIfAbsent(
                Map<String, FactDescriptor> facts,
                String factPath,
                String legalBasis
        ) {
            if (factPath == null || factPath.isBlank()) {
                return;
            }
            String trimmed = factPath.trim();
            FactSlotNamespace ns;
            FactResolutionStage stage;
            Set<ContextEvaluationPhase> phases;
            boolean resourceAttr = false;
            if (trimmed.startsWith("subject.")) {
                ns = FactSlotNamespace.SUBJECT;
                stage = FactResolutionStage.ENRICH;
                phases = Set.of(ContextEvaluationPhase.ADMISSION, ContextEvaluationPhase.TARGET);
            } else if (trimmed.startsWith("resource.")) {
                ns = FactSlotNamespace.RESOURCE;
                stage = FactResolutionStage.EXTRACT;
                phases = Set.of(ContextEvaluationPhase.TARGET);
                resourceAttr = true;
            } else if (trimmed.startsWith("action.")) {
                ns = FactSlotNamespace.ACTION;
                stage = FactResolutionStage.EXTRACT;
                phases = Set.of(ContextEvaluationPhase.ADMISSION, ContextEvaluationPhase.TARGET);
            } else if (trimmed.startsWith("context.")) {
                ns = FactSlotNamespace.CONTEXT;
                stage = FactResolutionStage.EXTRACT;
                phases = Set.of(ContextEvaluationPhase.ADMISSION, ContextEvaluationPhase.TARGET);
            } else {
                return;
            }
            String attrId = resourceAttr ? trimmed.substring("resource.".length()) : null;
            facts.putIfAbsent(
                    trimmed,
                    new FactDescriptor(
                            trimmed,
                            ns,
                            FactValueType.STRING,
                            FactCardinality.SCALAR,
                            FactPresenceModel.MAY_BE_ABSENT,
                            attrId,
                            null,
                            stage,
                            phases,
                            resourceAttr,
                            "INTERNAL",
                            "OPERATIONAL",
                            Set.of(),
                            legalBasis,
                            null
                    )
            );
        }
    }
}
