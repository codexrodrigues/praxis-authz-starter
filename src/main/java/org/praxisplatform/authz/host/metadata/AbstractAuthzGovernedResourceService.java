package org.praxisplatform.authz.host.metadata;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import jakarta.validation.Validator;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.RecordComponent;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.BiConsumer;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Supplier;
import org.praxisplatform.authz.catalog.FieldLineageCatalogEntry;
import org.praxisplatform.authz.catalog.SemanticDecisionPointCatalogService;
import org.praxisplatform.authz.contracts.context.FactResolutionStatus;
import org.praxisplatform.authz.contracts.decisionpoint.DecisionPointDescriptor;
import org.praxisplatform.authz.contracts.decisionpoint.FieldUseCategory;
import org.praxisplatform.authz.contracts.envelope.FieldUseEffectDirective;
import org.praxisplatform.authz.contracts.envelope.MaskDirective;
import org.praxisplatform.authz.contracts.envelope.RuleEffect;
import org.praxisplatform.authz.contracts.policy.DualScopeDelegationSpec;
import org.praxisplatform.authz.enforcement.context.UntrustedRequestHeaderGuard;
import org.praxisplatform.authz.enforcement.jpa.JpaDataScopeAdapter;
import org.praxisplatform.authz.host.metadata.MetadataDtoGovernanceIntrospector.IntrospectedDtoGovernanceContract;
import org.praxisplatform.authz.seams.GovernedExportAndAiToolAuthorizationSeam.AiGovernanceMetadataView;
import org.praxisplatform.authz.seams.GovernedExportAndAiToolAuthorizationSeam.SanitizedAiToolProjection;
import org.praxisplatform.authz.seams.MetadataResourceAuthorizationSeam.TargetReadProjectionEvaluation;
import org.praxisplatform.authz.seams.RuntimeDecisionPointRegistry;
import org.praxisplatform.uischema.annotation.DomainLineage;
import org.praxisplatform.uischema.capability.ResourceOperationAvailabilityProvider;
import org.praxisplatform.uischema.capability.ResourceStateSnapshot;
import org.praxisplatform.uischema.capability.ResourceStateSnapshotProvider;
import org.praxisplatform.uischema.capability.ResourceStateSnapshotScope;
import org.praxisplatform.uischema.command.GovernedResourceCommandExecutor;
import org.praxisplatform.uischema.command.ResourceCommandExecutionProvider;
import org.praxisplatform.uischema.concurrency.ResourceRepresentationResult;
import org.praxisplatform.uischema.concurrency.ResourceVersionEtagService;
import org.praxisplatform.uischema.concurrency.ResourceVersionScope;
import org.praxisplatform.uischema.concurrency.ResourceVersionUpdatePrecondition;
import org.praxisplatform.uischema.determination.ReactiveDeterminationDefinition;
import org.praxisplatform.uischema.determination.ReactiveDeterminationDefinitionProvider;
import org.praxisplatform.uischema.dto.CursorPage;
import org.praxisplatform.uischema.dto.OptionDTO;
import org.praxisplatform.uischema.exporting.CollectionExportExecutor;
import org.praxisplatform.uischema.exporting.CollectionExportRequest;
import org.praxisplatform.uischema.exporting.CollectionExportResult;
import org.praxisplatform.uischema.filter.dto.GenericFilterDTO;
import org.praxisplatform.uischema.filter.specification.GenericSpecificationsBuilder;
import org.praxisplatform.uischema.id.CompositeIdSupport;
import org.praxisplatform.uischema.mapper.base.ResourceMapper;
import org.praxisplatform.uischema.options.OptionSourceByIdsRequest;
import org.praxisplatform.uischema.options.OptionSourceEligibility;
import org.praxisplatform.uischema.options.OptionSourceFilterRequest;
import org.praxisplatform.uischema.options.service.OptionSourceQueryExecutor;
import org.praxisplatform.uischema.repository.base.BaseCrudRepository;
import org.praxisplatform.uischema.service.base.AbstractBaseQueryResourceService;
import org.praxisplatform.uischema.service.base.AbstractBaseResourceService;
import org.praxisplatform.uischema.service.base.BaseResourceCommandService;
import org.praxisplatform.uischema.service.base.ResourceFilterAccessScope;
import org.praxisplatform.uischema.stats.StatsEligibility;
import org.praxisplatform.uischema.stats.StatsFieldRegistry;
import org.praxisplatform.uischema.stats.StatsProperties;
import org.praxisplatform.uischema.stats.StatsSupportMode;
import org.praxisplatform.uischema.stats.dto.ComparisonStatsRequest;
import org.praxisplatform.uischema.stats.dto.ComparisonStatsResponse;
import org.praxisplatform.uischema.stats.dto.DistributionStatsRequest;
import org.praxisplatform.uischema.stats.dto.DistributionStatsResponse;
import org.praxisplatform.uischema.stats.dto.GroupByStatsRequest;
import org.praxisplatform.uischema.stats.dto.GroupByStatsResponse;
import org.praxisplatform.uischema.stats.dto.TimeSeriesStatsRequest;
import org.praxisplatform.uischema.stats.dto.TimeSeriesStatsResponse;
import org.praxisplatform.uischema.stats.service.StatsQueryExecutor;
import org.springframework.aop.support.AopUtils;
import org.springframework.core.ResolvableType;
import org.springframework.core.convert.support.DefaultConversionService;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;

/**
 * Canonical governed base class for mutable resources extending
 * {@link AbstractBaseResourceService} ({@code Fases P10.7 & P10.8}, {@code CC03}, {@code CC06},
 * {@code CC07}, {@code CC08}, {@code R-07}, {@code R-11}, {@code P01..P22}, {@code P34},
 * {@code P40}, {@code P46}, {@code P50}).
 *
 * <p>Enforces the 15-step authorization pipeline across all read and write lifecycles by
 * construction ({@code final} lifecycle hooks):</p>
 * <ul>
 *   <li><b>Query, Export, OptionSource &amp; Analytics Governance:</b> auto-introspects
 *       {@code responseType} and write DTO classes ({@code introspectWriteDto}), wraps
 *       {@link #getRawResourceMapper()} in {@link AuthzMaskingResourceMapperDecorator}, composes
 *       {@code hardScope} AND OPA {@code DataScopePlan} in
 *       {@link #resolveResourceFilterAccessScope()}, guards against {@code N+1} OPA {@code SEARCH}
 *       calls in {@link #assertEntityAccessAllowed(Object)}, and filters
 *       {@link #getStatsFieldRegistry()} against static {@code @DomainGovernance};</li>
 *   <li><b>Pre-Hydration Mutation Ordering ({@code R-11} / {@code STEP_11} before {@code STEP_12}):</b>
 *       {@link #beforeCreate(Object, Object)}, {@link #beforeUpdate(Object, Object, Object)}, and
 *       {@link #beforeDelete(Object, Object)} are {@code final} and execute
 *       {@link AuthzGovernedResourceServiceSupport#authorizeBeforeHydrationAndRules} /
 *       {@link AuthzGovernedResourceServiceSupport#authorizeBeforeDelete} <b>strictly before</b>
 *       invoking {@link #hydrateBeforeCreate(Object, Object)},
 *       {@link #hydrateBeforeUpdate(Object, Object, Object)}, and {@code validateCreate}/
 *       {@code validateUpdate}/{@code validateDelete};</li>
 *   <li><b>Smart Create &amp; Update Delta Extraction ({@code Fase P10.8}):</b> on {@code CREATE},
 *       omits optional {@code null} properties while retaining {@code null} mandatory scope anchors
 *       so a {@code Cedente}-only caller can initiate a record without false-positive
 *       {@code Cessionário} violations while still failing closed on missing scope anchors; on
 *       {@code UPDATE}, compares {@code UpdateDTO} against the existing entity's raw response
 *       projection so unchanged fields projected by {@code toBulkUpdate} are ignored;</li>
 *   <li><b>Unmasked Validation Drafts ({@code P13}, {@code P14}, {@code P40}):</b> overrides
 *       {@link #prepareUpdateValidationDraft(Object, Object, Object)} to project directly via
 *       {@link #getRawResourceMapper()} in {@code O(1)};</li>
 *   <li><b>Atomic Transactional Outbox &amp; Detached Masking ({@code STEP_14}/{@code STEP_15}):</b>
 *       marks post-mutation contexts ready in {@link #afterCreate} / {@link #afterUpdate}, drains
 *       FIFO delete outbox obligations in {@link #afterDelete}, and wraps
 *       {@link #bulkDomainAdapter} in {@link AuthzGovernedBulkDomainResourceAdapter}.</li>
 * </ul>
 *
 * @param <E> JPA entity type
 * @param <ResponseDTO> response DTO type annotated with {@code @DomainGovernance}
 * @param <ID> entity identifier type
 * @param <FilterDTO> filter DTO type
 * @param <CreateDTO> create DTO type
 * @param <UpdateDTO> update DTO type
 */
public abstract class AbstractAuthzGovernedResourceService<
        E,
        ResponseDTO,
        ID,
        FilterDTO extends GenericFilterDTO,
        CreateDTO,
        UpdateDTO
> extends AbstractBaseResourceService<E, ResponseDTO, ID, FilterDTO, CreateDTO, UpdateDTO> {

    private final Class<ResponseDTO> responseType;
    private final AuthzGovernedResourceServiceSupport serviceSupport;
    private final DecisionPointDescriptor decisionPoint;
    private final String factContractDigest;
    private final JpaDataScopeAdapter jpaDataScopeAdapter;
    private final JpaCriteriaDataScopeTranslator criteriaTranslator;
    private final AuthzResourceGovernanceSpec<E> governanceSpec;
    private final AuthzCallerContextProvider callerContextProvider;
    private final ObjectMapper deltaObjectMapper;
    private final Map<Class<?>, IntrospectedDtoGovernanceContract> writeContractCache = new ConcurrentHashMap<>();

    private volatile IntrospectedDtoGovernanceContract governanceContract;
    private volatile ResourceMapper<E, ResponseDTO, CreateDTO, UpdateDTO, ID> wrappedMapper;
    private volatile AuthzGovernedStatsQueryExecutor governedStatsExecutor;
    private volatile AuthzGovernedReactiveDeterminationProvider governedDeterminationProvider;

    /**
     * Creates a governed mutable resource service driven by a declarative
     * {@link AuthzResourceGovernanceSpec} and {@link AuthzCallerContextProvider} ({@code Fase P10.8}).
     */
    protected AbstractAuthzGovernedResourceService(
            BaseCrudRepository<E, ID> repository,
            Class<E> entityClass,
            Class<ResponseDTO> responseType,
            AuthzGovernedResourceServiceSupport serviceSupport,
            AuthzResourceGovernanceSpec<E> governanceSpec,
            AuthzCallerContextProvider callerContextProvider
    ) {
        this(
                repository,
                new GenericSpecificationsBuilder<>(),
                entityClass,
                responseType,
                serviceSupport,
                governanceSpec,
                callerContextProvider
        );
    }

    /**
     * Creates a governed mutable resource service driven by a declarative
     * {@link AuthzResourceGovernanceSpec}, {@link AuthzCallerContextProvider}, and explicit
     * {@link GenericSpecificationsBuilder} ({@code Fase P10.8}).
     */
    protected AbstractAuthzGovernedResourceService(
            BaseCrudRepository<E, ID> repository,
            GenericSpecificationsBuilder<E> specificationsBuilder,
            Class<E> entityClass,
            Class<ResponseDTO> responseType,
            AuthzGovernedResourceServiceSupport serviceSupport,
            AuthzResourceGovernanceSpec<E> governanceSpec,
            AuthzCallerContextProvider callerContextProvider
    ) {
        super(repository, specificationsBuilder, entityClass);
        Objects.requireNonNull(governanceSpec, "governanceSpec is required");
        this.responseType = Objects.requireNonNull(responseType, "responseType is required");
        this.serviceSupport = Objects.requireNonNull(serviceSupport, "serviceSupport is required");
        this.decisionPoint = governanceSpec.decisionPoint();
        this.factContractDigest = governanceSpec.factContractDigest();
        this.jpaDataScopeAdapter = governanceSpec.jpaDataScopeAdapter();
        this.criteriaTranslator = governanceSpec.criteriaTranslator();
        this.governanceSpec = governanceSpec;
        this.callerContextProvider = Objects.requireNonNull(callerContextProvider, "callerContextProvider is required");
        this.deltaObjectMapper = new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    }

    /**
     * Creates a governed mutable resource service with the default {@link GenericSpecificationsBuilder}.
     */
    protected AbstractAuthzGovernedResourceService(
            BaseCrudRepository<E, ID> repository,
            Class<E> entityClass,
            Class<ResponseDTO> responseType,
            AuthzGovernedResourceServiceSupport serviceSupport,
            DecisionPointDescriptor decisionPoint,
            String factContractDigest,
            JpaDataScopeAdapter jpaDataScopeAdapter,
            JpaCriteriaDataScopeTranslator criteriaTranslator
    ) {
        this(
                repository,
                new GenericSpecificationsBuilder<>(),
                entityClass,
                responseType,
                serviceSupport,
                decisionPoint,
                factContractDigest,
                jpaDataScopeAdapter,
                criteriaTranslator
        );
    }

    /**
     * Creates a governed mutable resource service with an explicit {@link GenericSpecificationsBuilder}.
     */
    protected AbstractAuthzGovernedResourceService(
            BaseCrudRepository<E, ID> repository,
            GenericSpecificationsBuilder<E> specificationsBuilder,
            Class<E> entityClass,
            Class<ResponseDTO> responseType,
            AuthzGovernedResourceServiceSupport serviceSupport,
            DecisionPointDescriptor decisionPoint,
            String factContractDigest,
            JpaDataScopeAdapter jpaDataScopeAdapter,
            JpaCriteriaDataScopeTranslator criteriaTranslator
    ) {
        super(repository, specificationsBuilder, entityClass);
        this.responseType = Objects.requireNonNull(responseType, "responseType is required");
        this.serviceSupport = Objects.requireNonNull(serviceSupport, "serviceSupport is required");
        this.decisionPoint = Objects.requireNonNull(decisionPoint, "decisionPoint is required");
        this.factContractDigest = Objects.requireNonNull(factContractDigest, "factContractDigest is required");
        this.jpaDataScopeAdapter = Objects.requireNonNull(jpaDataScopeAdapter, "jpaDataScopeAdapter is required");
        this.criteriaTranslator = Objects.requireNonNull(criteriaTranslator, "criteriaTranslator is required");
        this.governanceSpec = null;
        this.callerContextProvider = null;
        this.deltaObjectMapper = new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    }

    /** Returns the raw unmasked {@link ResourceMapper} to be wrapped automatically by this base class. */
    protected abstract ResourceMapper<E, ResponseDTO, CreateDTO, UpdateDTO, ID> getRawResourceMapper();

    /**
     * Extracts authoritative target facts from an existing or newly instantiated entity
     * (e.g. {@code Map.of("resource.lotacaoSetorId", entity.getLotacaoSetorId())}).
     *
     * <p>When an {@link AuthzResourceGovernanceSpec} is configured, target facts are extracted
     * automatically from its {@code fieldBindings} and optional {@code targetFactExtractor}
     * ({@code Fase P10.9}).</p>
     *
     * @param entity non-null target entity
     * @return authoritative target facts
     */
    protected Map<String, Object> extractEntityTargetFacts(E entity) {
        if (governanceSpec != null) {
            return governanceSpec.extractEntityTargetFacts(entity);
        }
        throw new IllegalStateException(
                "Override extractEntityTargetFacts(E) or supply an AuthzResourceGovernanceSpec");
    }

    @Override
    protected String resolveResourceKey() {
        if (governanceSpec != null) {
            return governanceSpec.resourceKey();
        }
        return super.resolveResourceKey();
    }

    /** Returns the authoritative subject and environment facts for the current caller. */
    protected Map<String, Object> resolveSubjectAndEnvironmentFacts() {
        if (callerContextProvider != null) {
            return callerContextProvider.currentCallerContext().subjectAndEnvironmentFacts();
        }
        throw new IllegalStateException(
                "Override resolveSubjectAndEnvironmentFacts() or supply an AuthzCallerContextProvider");
    }

    /** Returns the mandatory host-level {@link ResourceFilterAccessScope} (tenant/org hard scope). */
    protected ResourceFilterAccessScope<E> resolveHardScope() {
        if (governanceSpec != null && callerContextProvider != null) {
            return governanceSpec.buildHardScope(callerContextProvider.currentCallerContext().tenantId());
        }
        throw new IllegalStateException(
                "Override resolveHardScope() or supply an AuthzResourceGovernanceSpec + AuthzCallerContextProvider");
    }

    /** Returns the mandatory host-level JPQL hard-scope clause (e.g. {@code "e.tenantId = :__praxis_hard_tenant_id"}). */
    protected String resolveHardScopeJpql() {
        if (governanceSpec != null) {
            return governanceSpec.buildHardScopeJpql();
        }
        throw new IllegalStateException(
                "Override resolveHardScopeJpql() or supply an AuthzResourceGovernanceSpec");
    }

    /** Returns the mandatory host-level JPQL hard-scope parameters. */
    protected Map<String, Object> resolveHardScopeParams() {
        if (governanceSpec != null && callerContextProvider != null) {
            return governanceSpec.buildHardScopeParams(callerContextProvider.currentCallerContext().tenantId());
        }
        throw new IllegalStateException(
                "Override resolveHardScopeParams() or supply an AuthzResourceGovernanceSpec + AuthzCallerContextProvider");
    }

    /**
     * Verifies row-level entity access for {@link #assertEntityAccessAllowed(Object)} after the
     * active query scope context has been initialized.
     *
     * @param entity non-null unproxied entity
     */
    protected void verifyEntityAccessAllowed(E entity) {
        if (governanceSpec != null && callerContextProvider != null) {
            var activeQueryCtx = serviceSupport.currentQueryScopeContext();
            governanceSpec.verifyEntityAccessAllowed(
                    entity,
                    callerContextProvider.currentCallerContext(),
                    activeQueryCtx != null ? activeQueryCtx.dataScopePlan() : null
            );
            return;
        }
        throw new IllegalStateException(
                "Override verifyEntityAccessAllowed(E) or supply an AuthzResourceGovernanceSpec + AuthzCallerContextProvider");
    }

    /**
     * Optional {@link DualScopeDelegationSpec} governing split custody ({@code Cedente} vs
     * {@code Cessionário}) for this resource, or {@code null} when single-scope.
     */
    protected DualScopeDelegationSpec resolveDualScopeDelegationSpec() {
        if (governanceSpec != null) {
            return governanceSpec.dualScopeDelegationSpec();
        }
        return null;
    }

    /** Returns {@code true} when the current caller holds {@code Cedente} (origin) custody over {@code entity}. */
    protected boolean isCallerCedente(E entity) {
        if (governanceSpec != null && callerContextProvider != null) {
            return governanceSpec.isCallerCedente(entity, callerContextProvider.currentCallerContext());
        }
        return true;
    }

    /** Returns {@code true} when the current caller holds {@code Cessionário} (destination) custody over {@code entity}. */
    protected boolean isCallerCessionario(E entity) {
        if (governanceSpec != null && callerContextProvider != null) {
            return governanceSpec.isCallerCessionario(entity, callerContextProvider.currentCallerContext());
        }
        return true;
    }

    /**
     * Returns canonical {@code attributeId}s of mandatory scope anchors that cannot be cleared or
     * omitted on write ({@code CC06}, {@code P13}, {@code P14}).
     */
    protected Set<String> resolveMandatoryScopeAnchorAttributeIds() {
        if (governanceSpec != null) {
            return governanceSpec.mandatoryScopeAnchorAttributeIds();
        }
        return Set.of();
    }

    /**
     * Returns technical JSON pointers (e.g. {@code "/version"}) ignored during {@code WriteIntent} extraction.
     */
    protected Set<String> resolveTechnicalConcurrencyPointers() {
        if (governanceSpec != null) {
            return governanceSpec.technicalConcurrencyPointers();
        }
        return Set.of("/version");
    }

    /**
     * Server-side hydration hook for {@code create} guaranteed by {@link #beforeCreate} to execute
     * <b>strictly after</b> {@code STEP_11} ({@code authorizeBeforeHydrationAndRules}) and
     * <b>before</b> {@code STEP_12} ({@code validateCreate}) ({@code R-11}, {@code P13}, {@code P14}).
     */
    protected void hydrateBeforeCreate(CreateDTO dto, E entity) {
    }

    /**
     * Server-side hydration hook for {@code update} guaranteed by {@link #beforeUpdate} to execute
     * <b>strictly after</b> {@code STEP_11} ({@code authorizeBeforeHydrationAndRules}) and
     * <b>before</b> {@code STEP_12} ({@code validateUpdate}) ({@code R-11}, {@code P13}, {@code P14}).
     */
    protected void hydrateBeforeUpdate(ID id, E existing, UpdateDTO dto) {
    }

    /** Optional hook invoked inside {@link #beforeDelete(Object, Object)} after {@code STEP_11} admission. */
    protected void onBeforeDelete(ID id, E entity) {
    }

    /** Optional post-create side-effect hook invoked inside {@link #afterCreate(Object, Object)}. */
    protected void onAfterCreate(CreateDTO dto, E saved) {
    }

    /** Optional post-update side-effect hook invoked inside {@link #afterUpdate(Object, Object, Object)}. */
    protected void onAfterUpdate(ID id, E saved, UpdateDTO dto) {
    }

    /** Optional post-delete side-effect hook invoked inside {@link #afterDelete(Object, Object)}. */
    protected void onAfterDelete(ID id, E entity) {
    }

    /** Defines the raw {@link StatsFieldRegistry} before static {@code @DomainGovernance} filtering. */
    protected StatsFieldRegistry defineRawStatsFieldRegistry() {
        return StatsFieldRegistry.empty();
    }

    /**
     * Defines the raw {@link org.praxisplatform.uischema.exporting.CollectionExportField} allowlist
     * before static {@code @DomainGovernance} and {@code VALUE + DENY} filtering ({@code Fase P10.22-A}).
     */
    protected List<org.praxisplatform.uischema.exporting.CollectionExportField> defineRawExportFields() {
        return super.exportFields();
    }

    @Override
    protected final List<org.praxisplatform.uischema.exporting.CollectionExportField> exportFields() {
        return AuthzGovernedCollectionExportExecutor.filterDiscoveryExportFields(
                defineRawExportFields(),
                getGovernanceContract()
        );
    }

    /** Returns incoming HTTP request header names for anti-spoofing validation, or empty set. */
    protected Set<String> resolveRequestHeaderNames() {
        if (callerContextProvider != null) {
            return callerContextProvider.currentCallerContext().incomingHeaderNames();
        }
        return Set.of();
    }

    /** Returns requested query field uses ({@code FILTER}, {@code SORT}, {@code GROUP}) for the current request. */
    protected Map<FieldUseCategory, Set<String>> resolveRequestedQueryFieldUses() {
        Map<FieldUseCategory, Set<String>> callerUses = callerContextProvider != null
                ? callerContextProvider.currentCallerContext().requestedQueryFieldUses()
                : Map.of();
        return serviceSupport.mergeWithExtractedQueryFieldUses(callerUses);
    }

    /** Returns resolution statuses for the given facts, defaulting to {@link FactResolutionStatus#PRESENT}. */
    protected Map<String, FactResolutionStatus> resolveFactStatuses(Map<String, Object> facts) {
        if (facts == null || facts.isEmpty()) {
            return Map.of();
        }
        Map<String, FactResolutionStatus> statuses = new LinkedHashMap<>();
        if (callerContextProvider != null) {
            statuses.putAll(callerContextProvider.currentCallerContext().factStatuses());
        }
        for (String key : facts.keySet()) {
            statuses.putIfAbsent(key, FactResolutionStatus.PRESENT);
        }
        return Map.copyOf(statuses);
    }

    /** Returns the introspected {@link IntrospectedDtoGovernanceContract} for {@code responseType}. */
    public final IntrospectedDtoGovernanceContract getGovernanceContract() {
        IntrospectedDtoGovernanceContract current = this.governanceContract;
        if (current == null) {
            synchronized (this) {
                current = this.governanceContract;
                if (current == null) {
                    current = serviceSupport.dtoIntrospector().introspect(responseType, resolveResourceKey());
                    this.governanceContract = current;
                }
            }
        }
        return current;
    }

    /**
     * Returns the introspected write governance contract for {@code dto} (inheriting lineage from
     * {@code responseType} via {@link MetadataDtoGovernanceIntrospector#introspectWriteDto})
     * ({@code Fase P10.8}, {@code P10.8-R01}).
     */
    protected final IntrospectedDtoGovernanceContract getWriteGovernanceContract(Object dto) {
        if (dto == null || dto instanceof Map<?, ?> || dto instanceof String) {
            return getGovernanceContract();
        }
        return writeContractCache.computeIfAbsent(
                dto.getClass(),
                cls -> serviceSupport.dtoIntrospector().introspectWriteDto(cls, responseType, resolveResourceKey())
        );
    }

    /** Returns the {@link AuthzGovernedResourceServiceSupport} bridge backing this service. */
    public final AuthzGovernedResourceServiceSupport getServiceSupport() {
        return serviceSupport;
    }

    /** Returns the governed {@code ResponseDTO} class. */
    public final Class<ResponseDTO> getResponseType() {
        return responseType;
    }

    /** Returns the governed {@link DecisionPointDescriptor}. */
    public final DecisionPointDescriptor getDecisionPoint() {
        return decisionPoint;
    }

    /** Returns the governed {@code FactContract} digest. */
    public final String getFactContractDigest() {
        return factContractDigest;
    }

    /** Returns the optional {@link AuthzResourceGovernanceSpec} configured on this service. */
    public final AuthzResourceGovernanceSpec<E> getGovernanceSpec() {
        return governanceSpec;
    }

    @Override
    protected Optional<ResourceStateSnapshot> toResourceStateSnapshot(E entity) {
        if (entity == null) {
            return Optional.empty();
        }
        if (governanceSpec != null) {
            return Optional.of(governanceSpec.toResourceStateSnapshot(entity));
        }
        Map<String, Object> targetFacts = extractEntityTargetFacts(entity);
        return Optional.of(ResourceStateSnapshot.of(null, targetFacts));
    }

    @Override
    public final Optional<ResourceStateSnapshot> findResourceStateSnapshot(ID id) {
        if (id == null) {
            return Optional.empty();
        }
        return ResourceStateSnapshotScope.findSeededServiceSnapshot(this, id)
                .orElseGet(() -> {
                    Optional<ResourceStateSnapshot> snapshot = getRepository().findById(id)
                            .map(this::unproxyEntity)
                            .flatMap(this::toResourceStateSnapshot);
                    if (ResourceStateSnapshotScope.isOpen()) {
                        ResourceStateSnapshotScope.seedServiceSnapshot(this, id, snapshot);
                    }
                    return snapshot;
                });
    }

    /**
     * Resolves an item {@link ResourceStateSnapshot} for contextual availability probes by raw
     * resource ID ({@code Fase P10.9}).
     */
    @SuppressWarnings("unchecked")
    public Optional<ResourceStateSnapshot> resolveItemSnapshotForAvailability(Object rawResourceId) {
        if (rawResourceId == null) {
            return Optional.empty();
        }
        ID typedId;
        try {
            Class<?> idType = ResolvableType.forClass(AopUtils.getTargetClass(this))
                    .as(AbstractBaseQueryResourceService.class).getGeneric(2).resolve();
            if (idType == null || idType.isInstance(rawResourceId)) {
                typedId = (ID) rawResourceId;
            } else if (CompositeIdSupport.isCompositeIdType(idType)) {
                typedId = (ID) CompositeIdSupport.decode(rawResourceId.toString(), idType);
            } else {
                typedId = (ID) DefaultConversionService.getSharedInstance().convert(rawResourceId, idType);
            }
        } catch (RuntimeException ex) {
            return Optional.empty();
        }
        return findResourceStateSnapshot(typedId);
    }

    /**
     * Builds the declarative {@link AuthzResourceOperationAvailabilityProvider.ResourceAvailabilityPolicyBinding}
     * for this service when configured with {@link AuthzResourceGovernanceSpec} and
     * {@link AuthzCallerContextProvider} ({@code Fase P10.9}).
     */
    public AuthzResourceOperationAvailabilityProvider.ResourceAvailabilityPolicyBinding buildAvailabilityPolicyBinding() {
        if (governanceSpec == null || callerContextProvider == null) {
            throw new IllegalStateException(
                    "buildAvailabilityPolicyBinding() requires AuthzResourceGovernanceSpec and AuthzCallerContextProvider");
        }
        return new AuthzResourceOperationAvailabilityProvider.ResourceAvailabilityPolicyBinding(
                resolveResourceKey(),
                decisionPoint,
                factContractDigest,
                governanceSpec.dualScopeDelegationSpec(),
                governanceSpec.operationModifiedAttributes(),
                () -> {
                    AuthzCallerContext callerCtx = callerContextProvider.currentCallerContext();
                    boolean collectionCedente = callerCtx.callerMatchesCedente() != null
                            ? callerCtx.callerMatchesCedente()
                            : (governanceSpec.hasDeclarativeCedenteCustody()
                                    ? governanceSpec.isCallerCedente(null, callerCtx)
                                    : isCallerCedente(null));
                    boolean collectionCessionario = callerCtx.callerMatchesCessionario() != null
                            ? callerCtx.callerMatchesCessionario()
                            : (governanceSpec.hasDeclarativeCessionarioCustody()
                                    ? governanceSpec.isCallerCessionario(null, callerCtx)
                                    : isCallerCessionario(null));
                    return new AuthzResourceOperationAvailabilityProvider.CallerAvailabilityFactContext(
                            callerCtx.subjectAndEnvironmentFacts(),
                            callerCtx.factStatuses(),
                            collectionCedente,
                            collectionCessionario,
                            callerCtx.tenantId()
                    );
                },
                governanceSpec::extractSnapshotTargetFacts,
                this::resolveItemSnapshotForAvailability,
                (callerAvailabilityCtx, snapshot) -> {
                    AuthzCallerContext callerCtx = callerContextProvider.currentCallerContext();
                    if (callerCtx.callerMatchesCedente() != null) {
                        return callerCtx.callerMatchesCedente();
                    }
                    if (governanceSpec.hasDeclarativeCedenteCustody()) {
                        return governanceSpec.isCallerCedenteForSnapshot(snapshot, callerCtx);
                    }
                    return isCallerCedente(null);
                },
                (callerAvailabilityCtx, snapshot) -> {
                    AuthzCallerContext callerCtx = callerContextProvider.currentCallerContext();
                    if (callerCtx.callerMatchesCessionario() != null) {
                        return callerCtx.callerMatchesCessionario();
                    }
                    if (governanceSpec.hasDeclarativeCessionarioCustody()) {
                        return governanceSpec.isCallerCessionarioForSnapshot(snapshot, callerCtx);
                    }
                    return isCallerCessionario(null);
                },
                governanceSpec.actionDecisionPoints(),
                governanceSpec.surfaceDecisionPoints()
        );
    }

    /**
     * Resolves the effective {@link DecisionPointDescriptor} for {@code actionOrOperationId},
     * checking {@link AuthzResourceGovernanceSpec#actionDecisionPoints()} and
     * {@link AuthzResourceGovernanceSpec#surfaceDecisionPoints()} before falling back to the
     * resource's default {@code decisionPoint} ({@code Fase P10.10}).
     */
    protected DecisionPointDescriptor resolveOperationDecisionPoint(String actionOrOperationId) {
        if (governanceSpec != null && actionOrOperationId != null) {
            DecisionPointDescriptor actionDp = governanceSpec.actionDecisionPoints().get(actionOrOperationId);
            if (actionDp != null) {
                return actionDp;
            }
            DecisionPointDescriptor surfaceDp = governanceSpec.surfaceDecisionPoints().get(actionOrOperationId);
            if (surfaceDp != null) {
                return surfaceDp;
            }
        }
        return decisionPoint;
    }

    /**
     * Resolves the effective {@code FactContract} digest for {@code effectiveDecisionPoint},
     * preferring {@code effectiveDecisionPoint.factContractRef().factContractDigest()} when
     * an operation overrides the resource's default {@code decisionPoint} ({@code P10.12-R03}).
     */
    protected String resolveOperationFactContractDigest(DecisionPointDescriptor effectiveDecisionPoint) {
        if (effectiveDecisionPoint != null
                && effectiveDecisionPoint != decisionPoint
                && effectiveDecisionPoint.factContractRef() != null
                && effectiveDecisionPoint.factContractRef().factContractDigest() != null) {
            return effectiveDecisionPoint.factContractRef().factContractDigest();
        }
        return factContractDigest;
    }

    /**
     * Executes a governed, versioned ({@code If-Match}) item command ({@code @WorkflowAction} or
     * {@code @ResourceIntent}) enforcing the full 15-step authorization pipeline ({@code Fase P10.10},
     * {@code R-07}, {@code R-11}, {@code P10..P22}):
     * <ol>
     *   <li>Acquires pessimistic row lock ({@code findEntityForMutation}) and validates row-level
     *       tenant hard-scope + active {@code DataScopePlan};</li>
     *   <li>Validates {@code If-Match} precondition ({@code 412}/{@code 428}) before any authorization
     *       side effect;</li>
     *   <li>Executes {@code STEP_11} ({@code authorizeBeforeHydrationAndRules}) using
     *       {@link #resolveOperationDecisionPoint(String)}, {@link #extractCommandIntentPayload},
     *       and {@link #isCallerCedente(Object)} / {@link #isCallerCessionario(Object)};</li>
     *   <li>Applies {@code entityMutator} ({@code STEP_12}/{@code STEP_13}) on the raw unmasked entity;</li>
     *   <li>Marks post-mutation ready so {@code toResourceRepresentation(saved)} atomically fulfills
     *       {@code BEFORE_COMMIT_OUTBOX} ({@code STEP_14}) and masks the returned {@code ResponseDTO}
     *       ({@code STEP_15}).</li>
     * </ol>
     *
     * @param id target entity identifier
     * @param actionOrOperationId canonical workflow action or intent identifier
     * @param commandDto optional command payload DTO (may be {@code null} for parameterless actions)
     * @param precondition version update precondition ({@code If-Match})
     * @param entityMutator domain mutator applied to the locked, authorized entity
     * @return versioned {@link ResourceRepresentationResult} with masked {@code ResponseDTO}
     */
    protected final ResourceRepresentationResult<ResponseDTO> executeGovernedVersionedCommand(
            ID id,
            String actionOrOperationId,
            Object commandDto,
            ResourceVersionUpdatePrecondition<ID> precondition,
            Consumer<E> entityMutator
    ) {
        Objects.requireNonNull(entityMutator, "entityMutator is required");
        return serviceSupport.executeInReentrancyScope(() -> {
            try {
                return executeVersionedMutation(id, precondition, entity -> {
                    authorizeItemCommandAtStep11(id, entity, actionOrOperationId, commandDto);
                    entityMutator.accept(entity);
                    serviceSupport.markPostMutationReadyForOutboxAndMasking();
                });
            } catch (RuntimeException | Error ex) {
                serviceSupport.clearMutationAndQueryContextsOnFailure(this);
                throw ex;
            }
        });
    }

    /**
     * Executes a governed, versioned ({@code If-Match}) item command receiving both the detached
     * pre-mutation snapshot and the managed entity ({@code Fase P10.10}).
     */
    protected final ResourceRepresentationResult<ResponseDTO> executeGovernedVersionedCommand(
            ID id,
            String actionOrOperationId,
            Object commandDto,
            ResourceVersionUpdatePrecondition<ID> precondition,
            BiConsumer<E, E> previousAndCurrentMutator
    ) {
        Objects.requireNonNull(previousAndCurrentMutator, "previousAndCurrentMutator is required");
        return serviceSupport.executeInReentrancyScope(() -> {
            try {
                return executeVersionedMutation(id, precondition, (previous, current) -> {
                    authorizeItemCommandAtStep11(id, current, actionOrOperationId, commandDto);
                    previousAndCurrentMutator.accept(previous, current);
                    serviceSupport.markPostMutationReadyForOutboxAndMasking();
                });
            } catch (RuntimeException | Error ex) {
                serviceSupport.clearMutationAndQueryContextsOnFailure(this);
                throw ex;
            }
        });
    }

    /**
     * Executes a governed non-versioned item command ({@code @WorkflowAction} or {@code @ResourceIntent})
     * enforcing row-level scope, {@code STEP_11} pre-mutation authorization, {@code BEFORE_COMMIT_OUTBOX},
     * and detached {@code ResponseDTO} masking ({@code Fase P10.10}).
     */
    protected final ResponseDTO executeGovernedItemCommand(
            ID id,
            String actionOrOperationId,
            Object commandDto,
            Consumer<E> entityMutator
    ) {
        Objects.requireNonNull(entityMutator, "entityMutator is required");
        return serviceSupport.executeInReentrancyScope(() -> {
            try {
                E existing = findEntityById(id);
                authorizeItemCommandAtStep11(id, existing, actionOrOperationId, commandDto);
                entityMutator.accept(existing);
                E saved = getRepository().save(existing);
                serviceSupport.markPostMutationReadyForOutboxAndMasking();
                return enrichSingleResponse(getResourceMapper().toResponse(saved));
            } catch (RuntimeException | Error ex) {
                serviceSupport.clearMutationAndQueryContextsOnFailure(this);
                throw ex;
            }
        });
    }

    private void authorizeItemCommandAtStep11(
            ID id,
            E existing,
            String actionOrOperationId,
            Object commandDto
    ) {
        Map<String, Object> mergedFacts = mergeSubjectAndEntityFacts(existing);
        IntrospectedDtoGovernanceContract commandContract = getWriteGovernanceContract(commandDto);
        Map<String, String> mergedWireToAttr = new LinkedHashMap<>( getGovernanceContract().wirePointerToAttributeIdMap());
        mergedWireToAttr.putAll(commandContract.wirePointerToAttributeIdMap());
        Object commandPayload = extractCommandIntentPayload(
                id,
                existing,
                actionOrOperationId,
                commandDto,
                commandContract,
                mergedWireToAttr
        );
        DecisionPointDescriptor effectiveDp = resolveOperationDecisionPoint(actionOrOperationId);
        serviceSupport.authorizeBeforeHydrationAndRules(
                effectiveDp,
                resolveOperationFactContractDigest(effectiveDp),
                "POST",
                true,
                commandPayload,
                Map.copyOf(mergedWireToAttr),
                resolveTechnicalConcurrencyPointers(),
                resolveMandatoryScopeAnchorAttributeIds(),
                resolveDualScopeDelegationSpec(),
                isCallerCedente(existing),
                isCallerCessionario(existing),
                mergedFacts,
                resolveFactStatuses(mergedFacts),
                this
        );
    }

    /**
     * Executes a governed collection-scoped bulk domain command ({@code BulkMode.DOMAIN_COMMAND} /
     * {@code ActionScope.COLLECTION}) across a cohort selected via {@link #selectBulkIdentities}
     * ({@code Fase P10.16-A}, {@code P15}).
     */
    protected final List<AuthzGovernedBulkDomainResourceAdapter.BulkCohortItemOutcome<ID>> executeGovernedBulkCommand(
            FilterDTO filter,
            Collection<ID> included,
            Collection<ID> excluded,
            int maxTargets,
            String actionOrOperationId,
            Object commandDto,
            org.praxisplatform.authz.contracts.binding.BatchAuthorizationMode batchMode,
            Consumer<E> entityMutator
    ) {
        List<ID> cohortIds = selectBulkIdentities(filter, included, excluded, maxTargets);
        return executeGovernedBulkCommand(cohortIds, actionOrOperationId, commandDto, batchMode, entityMutator);
    }

    /**
     * Executes a governed collection-scoped bulk domain command ({@code BulkMode.DOMAIN_COMMAND} /
     * {@code ActionScope.COLLECTION}) across an explicit cohort of {@code targetIds}, enforcing
     * per-item {@code hardScope} + {@code DataScopePlan}, {@code STEP_11} {@code WriteIntent} +
     * {@link DualScopeDelegationSpec} + {@code FIELD_WRITE} authorization, atomic
     * {@code BEFORE_COMMIT_OUTBOX} fulfillment per committed item, and deterministic
     * {@link org.praxisplatform.authz.contracts.binding.BatchAuthorizationMode#REJECT_ALL} or
     * {@link org.praxisplatform.authz.contracts.binding.BatchAuthorizationMode#PER_ITEM} semantics
     * ({@code Fase P10.16-A}, {@code P13}, {@code P14}, {@code P15}).
     */
    protected final List<AuthzGovernedBulkDomainResourceAdapter.BulkCohortItemOutcome<ID>> executeGovernedBulkCommand(
            Collection<ID> targetIds,
            String actionOrOperationId,
            Object commandDto,
            org.praxisplatform.authz.contracts.binding.BatchAuthorizationMode batchMode,
            Consumer<E> entityMutator
    ) {
        Objects.requireNonNull(batchMode, "batchMode is required");
        Objects.requireNonNull(entityMutator, "entityMutator is required");
        if (targetIds == null || targetIds.isEmpty()) {
            return List.of();
        }
        return serviceSupport.executeInReentrancyScope(() -> {
            List<AuthzGovernedBulkDomainResourceAdapter.BulkCohortItemOutcome<ID>> outcomes =
                    new java.util.ArrayList<>(targetIds.size());
            try {
                // P10.16-R02: Resolve primary resource SEARCH scope once for the cohort (avoiding N+1 OPA SEARCH calls)
                serviceSupport.ensureActiveQueryContext(this, this::resolveResourceFilterAccessScope);
                var cohortQueryScope = serviceSupport.currentQueryScopeContext();

                // P10.16-R02: When the bulk action has its own SEARCH-capable DecisionPointDescriptor,
                // evaluate its SEARCH DataScopePlan once for the cohort as well.
                DecisionPointDescriptor effectiveActionDp = resolveOperationDecisionPoint(actionOrOperationId);
                org.praxisplatform.authz.contracts.datascope.DataScopePlan actionDataScopePlan = null;
                if (effectiveActionDp != null
                        && effectiveActionDp != decisionPoint
                        && effectiveActionDp.evaluationModes().contains(
                                org.praxisplatform.authz.contracts.decisionpoint.EvaluationMode.SEARCH)) {
                    Map<String, Object> subjectFacts = resolveSubjectAndEnvironmentFacts();
                    var actionSearchScope = serviceSupport.evaluateBulkActionSearchScope(
                            effectiveActionDp,
                            resolveOperationFactContractDigest(effectiveActionDp),
                            resolveRequestHeaderNames(),
                            subjectFacts,
                            resolveFactStatuses(subjectFacts),
                            jpaDataScopeAdapter,
                            resolveHardScopeJpql(),
                            resolveHardScopeParams()
                    );
                    actionDataScopePlan = actionSearchScope.dataScopePlan();
                }

                if (batchMode == org.praxisplatform.authz.contracts.binding.BatchAuthorizationMode.REJECT_ALL) {
                    for (ID id : targetIds) {
                        try {
                            serviceSupport.restoreQueryScopeContext(this, cohortQueryScope);
                            E existing = findEntityById(id);
                            if (actionDataScopePlan != null && governanceSpec != null && callerContextProvider != null) {
                                governanceSpec.verifyEntityAccessAllowed(
                                        existing,
                                        callerContextProvider.currentCallerContext(),
                                        actionDataScopePlan
                                );
                            }
                            authorizeItemCommandAtStep11(id, existing, actionOrOperationId, commandDto);
                            E candidate = snapshotBeforeMutation(existing);
                            entityMutator.accept(candidate);
                            E saved = getRepository().save(candidate);
                            serviceSupport.markPostMutationReadyForOutboxAndMasking();
                            serviceSupport.completePendingMutationOutboxIfNotDisclosed();
                            java.util.OptionalLong verOpt = getEntityResourceVersion(saved);
                            String version = verOpt.isPresent() ? String.valueOf(verOpt.getAsLong()) : null;
                            outcomes.add(new AuthzGovernedBulkDomainResourceAdapter.BulkCohortItemOutcome<>(
                                    id, true, version, "COMMITTED"
                            ));
                        } finally {
                            serviceSupport.clearPerItemMutationContext();
                            serviceSupport.restoreQueryScopeContext(this, cohortQueryScope);
                        }
                    }
                    return List.copyOf(outcomes);
                }

                // PER_ITEM mode: isolate per-item authorization/validation failures without aborting the cohort
                for (ID id : targetIds) {
                    E existing = null;
                    try {
                        serviceSupport.restoreQueryScopeContext(this, cohortQueryScope);
                        existing = findEntityById(id);
                        if (actionDataScopePlan != null && governanceSpec != null && callerContextProvider != null) {
                            governanceSpec.verifyEntityAccessAllowed(
                                    existing,
                                    callerContextProvider.currentCallerContext(),
                                    actionDataScopePlan
                            );
                        }
                        authorizeItemCommandAtStep11(id, existing, actionOrOperationId, commandDto);
                        // P10.16-R02: Mutate a detached snapshot candidate first so if entityMutator throws
                        // after modifying fields, the managed entity in the JPA PersistenceContext is never dirtied.
                        E candidate = snapshotBeforeMutation(existing);
                        entityMutator.accept(candidate);
                        E saved = getRepository().save(candidate);
                        serviceSupport.markPostMutationReadyForOutboxAndMasking();
                        serviceSupport.completePendingMutationOutboxIfNotDisclosed();
                        java.util.OptionalLong verOpt = getEntityResourceVersion(saved);
                        String version = verOpt.isPresent() ? String.valueOf(verOpt.getAsLong()) : null;
                        outcomes.add(new AuthzGovernedBulkDomainResourceAdapter.BulkCohortItemOutcome<>(
                                id, true, version, "COMMITTED"
                        ));
                    } catch (org.praxisplatform.authz.enforcement.writeintent.FieldWriteViolationException ex) {
                        detachEntityIfManaged(existing);
                        serviceSupport.clearPerItemMutationContext();
                        outcomes.add(new AuthzGovernedBulkDomainResourceAdapter.BulkCohortItemOutcome<>(
                                id, false, null, "FIELD_WRITE_DENIED"
                        ));
                    } catch (SecurityException ex) {
                        detachEntityIfManaged(existing);
                        serviceSupport.clearPerItemMutationContext();
                        outcomes.add(new AuthzGovernedBulkDomainResourceAdapter.BulkCohortItemOutcome<>(
                                id, false, null, "ACCESS_OR_SCOPE_DENIED"
                        ));
                    } catch (jakarta.persistence.EntityNotFoundException ex) {
                        serviceSupport.clearPerItemMutationContext();
                        outcomes.add(new AuthzGovernedBulkDomainResourceAdapter.BulkCohortItemOutcome<>(
                                id, false, null, "ENTITY_NOT_FOUND"
                        ));
                    } catch (RuntimeException ex) {
                        // P10.16-R02: Detach managed entity when entityMutator or save fails so Hibernate
                        // dirty checking never flushes an un-audited mutation when the cohort commits.
                        detachEntityIfManaged(existing);
                        serviceSupport.clearPerItemMutationContext();
                        outcomes.add(new AuthzGovernedBulkDomainResourceAdapter.BulkCohortItemOutcome<>(
                                id, false, null, "DOMAIN_VALIDATION_REJECTED"
                        ));
                    } finally {
                        serviceSupport.clearPerItemMutationContext();
                        serviceSupport.restoreQueryScopeContext(this, cohortQueryScope);
                    }
                }
                return List.copyOf(outcomes);
            } catch (RuntimeException | Error ex) {
                serviceSupport.clearMutationAndQueryContextsOnFailure(this);
                throw ex;
            }
        });
    }

    /**
     * Automatically registers this service's {@link AuthzResourceOperationAvailabilityProvider.ResourceAvailabilityPolicyBinding}
     * into {@code availabilityProvider} when configured with an {@link AuthzResourceGovernanceSpec}
     * ({@code Fase P10.9}).
     */
    public void registerAvailabilityBindingIfSupported(
            AuthzResourceOperationAvailabilityProvider availabilityProvider
    ) {
        if (availabilityProvider != null && governanceSpec != null && callerContextProvider != null) {
            availabilityProvider.registerResourceBindingIfAbsent(buildAvailabilityPolicyBinding());
        }
    }

    /**
     * Derives the canonical {@link FieldLineageCatalogEntry} list across this mutable service's
     * {@code ResponseDTO} ({@code READ_PROJECTION}), {@code CreateDTO} ({@code CREATE_INPUT}), and
     * {@code UpdateDTO} ({@code UPDATE_INPUT}) via {@link MetadataDtoGovernanceIntrospector}
     * ({@code Fase P10.13}, {@code P36}, {@code P44..P50}, {@code P57}, {@code P58}).
     */
    public List<FieldLineageCatalogEntry> deriveFieldLineageCatalogEntries() {
        Class<?> targetClass = AopUtils.getTargetClass(this);
        ResolvableType mutableType = ResolvableType.forClass(targetClass)
                .as(AbstractAuthzGovernedResourceService.class);
        Class<?> createDtoClass = mutableType.getGeneric(4).resolve();
        Class<?> updateDtoClass = mutableType.getGeneric(5).resolve();
        return serviceSupport.dtoIntrospector().deriveFieldLineageCatalogEntries(
                resolveResourceKey(),
                responseType,
                createDtoClass,
                updateDtoClass
        );
    }

    /**
     * Synchronizes this service's declarative governance metadata ({@code DualScopeDelegationSpec},
     * mandatory scope anchors, and introspected {@link FieldLineageCatalogEntry} list) into
     * {@link RuntimeDecisionPointRegistry} and {@link SemanticDecisionPointCatalogService}
     * ({@code Fase P10.13}).
     */
    public void synchronizeCatalogAndRegistryIfSupported(
            RuntimeDecisionPointRegistry registry,
            SemanticDecisionPointCatalogService catalogService
    ) {
        if (decisionPoint == null) {
            return;
        }
        List<FieldLineageCatalogEntry> lineageEntries = deriveFieldLineageCatalogEntries();
        DualScopeDelegationSpec dualScope = resolveDualScopeDelegationSpec();
        Set<String> anchors = resolveMandatoryScopeAnchorAttributeIds();
        String primaryKey = decisionPoint.identity().pointKey();
        if (registry != null) {
            registry.enrichRegisteredPointGovernance(primaryKey, dualScope, anchors, lineageEntries);
            if (governanceSpec != null) {
                for (DecisionPointDescriptor actionDp : governanceSpec.actionDecisionPoints().values()) {
                    registry.enrichRegisteredPointGovernance(
                            actionDp.identity().pointKey(), dualScope, anchors, lineageEntries);
                }
                for (DecisionPointDescriptor surfaceDp : governanceSpec.surfaceDecisionPoints().values()) {
                    registry.enrichRegisteredPointGovernance(
                            surfaceDp.identity().pointKey(), dualScope, anchors, lineageEntries);
                }
            }
        }
        if (catalogService != null) {
            catalogService.enrichFieldLineageForPointKey(primaryKey, lineageEntries);
            if (governanceSpec != null) {
                for (DecisionPointDescriptor actionDp : governanceSpec.actionDecisionPoints().values()) {
                    catalogService.enrichFieldLineageForPointKey(actionDp.identity().pointKey(), lineageEntries);
                }
                for (DecisionPointDescriptor surfaceDp : governanceSpec.surfaceDecisionPoints().values()) {
                    catalogService.enrichFieldLineageForPointKey(surfaceDp.identity().pointKey(), lineageEntries);
                }
            }
        }
    }

    /**
     * Creates a governed {@link AuthzResourceOperationAvailabilityProvider} bound to this service's
     * {@link AuthzGovernedResourceServiceSupport} ({@code Fase P10.8}).
     */
    public AuthzResourceOperationAvailabilityProvider createAvailabilityProvider(
            ResourceStateSnapshotProvider snapshotProviderFallback
    ) {
        return serviceSupport.createAvailabilityProvider(snapshotProviderFallback);
    }

    /**
     * Wraps a {@link ResourceCommandExecutionProvider} with fail-closed {@code STEP_11} permission
     * denial translation ({@code Fase P10.8}).
     */
    public ResourceCommandExecutionProvider wrapCommandExecutionProvider(
            ResourceCommandExecutionProvider delegate
    ) {
        return serviceSupport.wrapCommandExecutionProvider(delegate);
    }

    /**
     * Creates a {@link GovernedResourceCommandExecutor} wrapping {@code delegate} with fail-closed
     * {@code STEP_11} permission denial translation and wiring {@code availabilityProvider}
     * ({@code Fase P10.10}, {@code P10.10-R05}).
     */
    public GovernedResourceCommandExecutor createGovernedCommandExecutor(
            ResourceCommandExecutionProvider delegate,
            ResourceOperationAvailabilityProvider availabilityProvider
    ) {
        return new GovernedResourceCommandExecutor(
                wrapCommandExecutionProvider(delegate),
                availabilityProvider,
                null
        );
    }

    /**
     * Wraps a {@link ReactiveDeterminationDefinitionProvider} into an
     * {@link AuthzGovernedReactiveDeterminationProvider} bound to this service's {@code responseType}
     * and {@link #resolveResourceKey()} ({@code Fase P10.8}).
     */
    public AuthzGovernedReactiveDeterminationProvider wrapReactiveDeterminationProvider(
            ReactiveDeterminationDefinitionProvider delegate
    ) {
        return serviceSupport.wrapReactiveDeterminationProvider(delegate, responseType, resolveResourceKey());
    }

    /**
     * Hook for subclasses to declare {@link ReactiveDeterminationDefinition}s directly on the
     * resource service without creating a separate provider class ({@code Fase P10.11}).
     */
    protected Collection<ReactiveDeterminationDefinition> defineReactiveDeterminations() {
        return List.of();
    }

    /**
     * Returns the lazily cached {@link AuthzGovernedReactiveDeterminationProvider} backed by
     * {@link #defineReactiveDeterminations()} and bound to this service's {@code responseType}
     * and {@link #resolveResourceKey()} ({@code Fase P10.11}).
     */
    public final AuthzGovernedReactiveDeterminationProvider getGovernedReactiveDeterminationProvider() {
        AuthzGovernedReactiveDeterminationProvider current = this.governedDeterminationProvider;
        if (current == null) {
            synchronized (this) {
                current = this.governedDeterminationProvider;
                if (current == null) {
                    current = wrapReactiveDeterminationProvider(this::defineReactiveDeterminations);
                    this.governedDeterminationProvider = current;
                }
            }
        }
        return current;
    }

    /**
     * Executes a governed non-persistent reactive determination on an existing item by {@code id},
     * enforcing anti-spoofing headers, tenant hard-scope, {@code DataScopePlan}, live {@code TARGET}
     * projection, and detached DTO masking ({@code Fase P10.11}, {@code P05}, {@code P12}, {@code P50}).
     */
    public final Map<String, Object> evaluateGovernedItemDetermination(
            ID id,
            Function<E, Object> rawDeterminationEvaluator
    ) {
        return evaluateGovernedItemDetermination(id, "reactive-determination", rawDeterminationEvaluator);
    }

    /**
     * Executes a governed non-persistent reactive determination on an existing item by {@code id}
     * using the decision point resolved for {@code determinationId} ({@code P10.12-R03}).
     */
    public final Map<String, Object> evaluateGovernedItemDetermination(
            ID id,
            String determinationId,
            Function<E, Object> rawDeterminationEvaluator
    ) {
        Objects.requireNonNull(rawDeterminationEvaluator, "rawDeterminationEvaluator is required");
        return serviceSupport.executeInReentrancyScope(() -> {
            try {
                E entity = findEntityById(id);
                Map<String, Object> mergedFacts = mergeSubjectAndEntityFacts(entity);
                DecisionPointDescriptor effectiveDp = resolveOperationDecisionPoint(determinationId);
                Set<String> primaryValueDenied = Set.of();
                List<MaskDirective> primaryMasks = List.of();
                if (effectiveDp != null && effectiveDp != decisionPoint) {
                    var primaryEval = serviceSupport.authorizeTargetEntityProjection(
                            decisionPoint,
                            factContractDigest,
                            mergedFacts,
                            resolveFactStatuses(mergedFacts)
                    );
                    primaryValueDenied = primaryEval.valueDeniedAttributeIds();
                    primaryMasks = primaryEval.maskDirectives();
                }
                return getGovernedReactiveDeterminationProvider().evaluateGovernedDetermination(
                        effectiveDp,
                        resolveOperationFactContractDigest(effectiveDp),
                        mergedFacts,
                        resolveFactStatuses(mergedFacts),
                        () -> rawDeterminationEvaluator.apply(entity),
                        primaryValueDenied,
                        primaryMasks
                );
            } catch (RuntimeException | Error ex) {
                serviceSupport.clearMutationAndQueryContextsOnFailure(this);
                throw ex;
            } finally {
                serviceSupport.completeBatchEnrichResponses(this);
            }
        });
    }

    /**
     * Executes a governed non-persistent reactive determination on a candidate draft entity
     * (before or without DB persistence), enforcing anti-spoofing headers, candidate scope
     * verification ({@link #assertEntityAccessAllowed(Object)}), live {@code TARGET} projection,
     * and detached DTO masking ({@code Fase P10.11}, {@code P10.12-R01}, {@code P05}, {@code P12}, {@code P50}).
     */
    public final Map<String, Object> evaluateGovernedDraftDetermination(
            E candidateEntity,
            Supplier<Object> rawDeterminationEvaluator
    ) {
        return evaluateGovernedDraftDetermination(candidateEntity, "reactive-determination", rawDeterminationEvaluator);
    }

    /**
     * Executes a governed non-persistent reactive determination on a candidate draft entity
     * using the decision point resolved for {@code determinationId} ({@code P10.12-R01}, {@code P10.12-R03}).
     */
    public final Map<String, Object> evaluateGovernedDraftDetermination(
            E candidateEntity,
            String determinationId,
            Supplier<Object> rawDeterminationEvaluator
    ) {
        Objects.requireNonNull(rawDeterminationEvaluator, "rawDeterminationEvaluator is required");
        return serviceSupport.executeInReentrancyScope(() -> {
            try {
                Map<String, Object> mergedFacts = mergeSubjectAndEntityFacts(candidateEntity);
                if (candidateEntity != null) {
                    assertEntityAccessAllowed(candidateEntity);
                }
                DecisionPointDescriptor effectiveDp = resolveOperationDecisionPoint(determinationId);
                Set<String> primaryValueDenied = Set.of();
                List<MaskDirective> primaryMasks = List.of();
                if (effectiveDp != null && effectiveDp != decisionPoint) {
                    var primaryEval = serviceSupport.authorizeTargetEntityProjection(
                            decisionPoint,
                            factContractDigest,
                            mergedFacts,
                            resolveFactStatuses(mergedFacts)
                    );
                    primaryValueDenied = primaryEval.valueDeniedAttributeIds();
                    primaryMasks = primaryEval.maskDirectives();
                }
                return getGovernedReactiveDeterminationProvider().evaluateGovernedDetermination(
                        effectiveDp,
                        resolveOperationFactContractDigest(effectiveDp),
                        mergedFacts,
                        resolveFactStatuses(mergedFacts),
                        rawDeterminationEvaluator,
                        primaryValueDenied,
                        primaryMasks
                );
            } catch (RuntimeException | Error ex) {
                serviceSupport.clearMutationAndQueryContextsOnFailure(this);
                throw ex;
            } finally {
                serviceSupport.completeBatchEnrichResponses(this);
            }
        });
    }

    /**
     * Projects a sanitized detached payload for an AI tool, copilot, or RAG grounding consumer
     * for item {@code id}, enforcing anti-spoofing headers, tenant hard-scope, {@code DataScopePlan},
     * live {@code TARGET} evaluation, and complete suppression of {@code aiAllowed = false} /
     * {@code LGPD_SENSITIVE_DATA} attributes ({@code Fase P10.11}, {@code P47}, {@code P57}, {@code P62}).
     */
    public final SanitizedAiToolProjection projectGovernedItemAiContext(ID id) {
        return serviceSupport.executeInReentrancyScope(() -> {
            try {
                E entity = findEntityById(id);
                Map<String, Object> mergedFacts = mergeSubjectAndEntityFacts(entity);
                ResponseDTO rawDto = getRawResourceMapper().toResponse(entity);
                DecisionPointDescriptor effectiveDp = resolveOperationDecisionPoint("ai-context");
                Set<String> primaryValueDenied = Set.of();
                List<MaskDirective> primaryMasks = List.of();
                if (effectiveDp != null && effectiveDp != decisionPoint) {
                    var primaryEval = serviceSupport.authorizeTargetEntityProjection(
                            decisionPoint,
                            factContractDigest,
                            mergedFacts,
                            resolveFactStatuses(mergedFacts)
                    );
                    primaryValueDenied = primaryEval.valueDeniedAttributeIds();
                    primaryMasks = primaryEval.maskDirectives();
                }
                return getGovernedReactiveDeterminationProvider().projectGovernedAiContext(
                        effectiveDp,
                        resolveOperationFactContractDigest(effectiveDp),
                        null,
                        null,
                        rawDto != null ? rawDto : entity,
                        mergedFacts,
                        resolveFactStatuses(mergedFacts),
                        primaryValueDenied,
                        primaryMasks
                );
            } catch (RuntimeException | Error ex) {
                serviceSupport.clearMutationAndQueryContextsOnFailure(this);
                throw ex;
            } finally {
                serviceSupport.completeBatchEnrichResponses(this);
            }
        });
    }

    /**
     * Returns value-free AI authoring and discovery governance metadata derived from this
     * service's introspected {@code responseType} contract ({@code Fase P10.11}, {@code P62}).
     */
    public final List<AiGovernanceMetadataView> projectAiGovernanceMetadata() {
        return getGovernedReactiveDeterminationProvider().projectAiGovernanceMetadata();
    }

    /**
     * Executes a governed non-persistent assisted duplicate-draft preparation
     * ({@code DuplicateDraftResourceService#duplicateDraft(Object)}) ({@code Fase P10.11},
     * {@code P01}, {@code P05}, {@code P11..P14}, {@code P46}, {@code P49}, {@code P50}):
     * <ol>
     *   <li>Enforces anti-spoofing headers, tenant hard-scope, and {@code DataScopePlan} on
     *       {@code sourceId} via {@code findEntityById(sourceId)};</li>
     *   <li>Evaluates live {@code TARGET} read authorization on {@code sourceEntity};</li>
     *   <li>Verifies {@link DualScopeDelegationSpec} custody ({@code callerCedente || callerCessionario});</li>
     *   <li>Invokes {@code rawDraftBuilder} on the unmasked {@code sourceEntity};</li>
     *   <li>Sanitizes the returned {@code DraftDTO} by clearing to {@code null} any attribute that is
     *       {@code LGPD_SENSITIVE_DATA}/{@code SECRET}/{@code CREDENTIAL}, value-denied, targeted by
     *       a live {@link MaskDirective} (preventing both raw secret leakage and masked placeholder
     *       strings like {@code "***CID-RESTRITO***"} from polluting an editable {@code CREATE} draft),
     *       a technical concurrency pointer ({@code "/version"}), or outside the caller's
     *       {@link DualScopeDelegationSpec} write partition;</li>
     *   <li>Guarantees zero {@code BEFORE_COMMIT_OUTBOX} mutations and deterministic {@code ThreadLocal}
     *       cleanup in {@code finally}.</li>
     * </ol>
     */
    protected final <DraftDTO> DraftDTO executeGovernedDuplicateDraft(
            ID sourceId,
            Function<E, DraftDTO> rawDraftBuilder
    ) {
        return executeGovernedDuplicateDraft(sourceId, "duplicate-draft", rawDraftBuilder);
    }

    /**
     * Executes a governed non-persistent assisted duplicate-draft preparation using the decision
     * point resolved for {@code operationId} ({@code Fase P10.17-A}).
     */
    protected final <DraftDTO> DraftDTO executeGovernedDuplicateDraft(
            ID sourceId,
            String operationId,
            Function<E, DraftDTO> rawDraftBuilder
    ) {
        Objects.requireNonNull(rawDraftBuilder, "rawDraftBuilder is required");
        String effectiveOpId = (operationId == null || operationId.isBlank()) ? "duplicate-draft" : operationId;
        return serviceSupport.executeInReentrancyScope(() -> {
            try {
                E sourceEntity = findEntityById(sourceId);
                Map<String, Object> mergedFacts = mergeSubjectAndEntityFacts(sourceEntity);
                Map<String, FactResolutionStatus> statuses = resolveFactStatuses(mergedFacts);
                DecisionPointDescriptor effectiveDp = resolveOperationDecisionPoint(effectiveOpId);
                TargetReadProjectionEvaluation targetEval;
                if (effectiveDp != null && effectiveDp != decisionPoint) {
                    TargetReadProjectionEvaluation primaryEval = serviceSupport.authorizeTargetEntityProjection(
                            decisionPoint,
                            factContractDigest,
                            mergedFacts,
                            statuses
                    );
                    TargetReadProjectionEvaluation secondaryEval = serviceSupport.authorizeTargetEntityProjection(
                            effectiveDp,
                            resolveOperationFactContractDigest(effectiveDp),
                            mergedFacts,
                            statuses
                    );
                    targetEval = primaryEval.mergeWith(secondaryEval);
                } else {
                    DecisionPointDescriptor dp = effectiveDp != null ? effectiveDp : decisionPoint;
                    targetEval = serviceSupport.authorizeTargetEntityProjection(
                            dp,
                            resolveOperationFactContractDigest(dp),
                            mergedFacts,
                            statuses
                    );
                }
                DualScopeDelegationSpec dualScope = resolveDualScopeDelegationSpec();
                boolean callerCedente = isCallerCedente(sourceEntity);
                boolean callerCessionario = isCallerCessionario(sourceEntity);
                if (dualScope != null && !callerCedente && !callerCessionario) {
                    throw new SecurityException("AUTHZ_DUPLICATE_DRAFT_CUSTODY_DENIED: Caller holds neither Cedente nor Cessionário custody on source record '"
                            + sourceId + "'");
                }
                DraftDTO rawDraft = rawDraftBuilder.apply(sourceEntity);
                if (rawDraft == null) {
                    return null;
                }
                return sanitizeDuplicateDraftPayload(rawDraft, targetEval, dualScope, callerCedente, callerCessionario);
            } catch (RuntimeException | Error ex) {
                serviceSupport.clearMutationAndQueryContextsOnFailure(this);
                throw ex;
            } finally {
                serviceSupport.completeBatchEnrichResponses(this);
            }
        });
    }

    @SuppressWarnings("unchecked")
    private <DraftDTO> DraftDTO sanitizeDuplicateDraftPayload(
            DraftDTO rawDraft,
            TargetReadProjectionEvaluation targetEval,
            DualScopeDelegationSpec dualScope,
            boolean callerCedente,
            boolean callerCessionario
    ) {
        return sanitizeDuplicateDraftWithTracking(
                rawDraft,
                getGovernanceContract(),
                getWriteGovernanceContract(rawDraft),
                targetEval,
                dualScope,
                callerCedente,
                callerCessionario,
                resolveTechnicalConcurrencyPointers(),
                resolveMandatoryScopeAnchorAttributeIds(),
                deltaObjectMapper,
                null
        );
    }

    @SuppressWarnings("unchecked")
    static <DraftDTO> DraftDTO sanitizeDuplicateDraftWithTracking(
            DraftDTO rawDraft,
            IntrospectedDtoGovernanceContract responseContract,
            IntrospectedDtoGovernanceContract draftContract,
            TargetReadProjectionEvaluation targetEval,
            DualScopeDelegationSpec dualScope,
            boolean callerCedente,
            boolean callerCessionario,
            Set<String> technicalPointers,
            Set<String> mandatoryAnchors,
            ObjectMapper mapper,
            Set<String> strippedAttributeSink
    ) {
        if (rawDraft == null || rawDraft instanceof String) {
            return rawDraft;
        }
        Map<String, String> mergedWireToAttr = new LinkedHashMap<>(responseContract.wirePointerToAttributeIdMap());
        if (draftContract != null) {
            mergedWireToAttr.putAll(draftContract.wirePointerToAttributeIdMap());
        }

        // 1. Unconditional strip set: sensitive/LGPD attributes, VALUE+DENY, active MaskDirectives, and technical concurrency pointers
        Set<String> unconditionalStripAttributes = new LinkedHashSet<>(responseContract.aiContextDeniedAttributeIds());
        if (draftContract != null) {
            unconditionalStripAttributes.addAll(draftContract.aiContextDeniedAttributeIds());
        }
        if (targetEval != null) {
            unconditionalStripAttributes.addAll(targetEval.valueDeniedAttributeIds());
            if (targetEval.maskDirectives() != null) {
                for (MaskDirective mask : targetEval.maskDirectives()) {
                    if (mask != null && mask.attributeId() != null) {
                        unconditionalStripAttributes.add(mask.attributeId());
                    }
                }
            }
        }
        for (FieldUseEffectDirective dir : responseContract.baselineFieldUseDirectives()) {
            if (dir.category() == FieldUseCategory.VALUE && dir.effect() == RuleEffect.DENY) {
                unconditionalStripAttributes.add(dir.attributeId());
            }
        }
        if (draftContract != null && draftContract != responseContract) {
            for (FieldUseEffectDirective dir : draftContract.baselineFieldUseDirectives()) {
                if (dir.category() == FieldUseCategory.VALUE && dir.effect() == RuleEffect.DENY) {
                    unconditionalStripAttributes.add(dir.attributeId());
                }
            }
        }

        // 2. Write-denied and dual-scope out-of-partition strip set (exempts mandatory scope anchors that define custody itself)
        Set<String> writeRestrictedAttributes = new LinkedHashSet<>();
        if (targetEval != null && targetEval.fieldWriteDeniedAttributeIds() != null) {
            writeRestrictedAttributes.addAll(targetEval.fieldWriteDeniedAttributeIds());
        }
        if (dualScope != null) {
            if (!callerCedente && dualScope.cedenteExclusiveWriteAttributes() != null) {
                writeRestrictedAttributes.addAll(dualScope.cedenteExclusiveWriteAttributes());
            }
            if (!callerCessionario && dualScope.cessionarioAllowedWriteAttributes() != null) {
                writeRestrictedAttributes.addAll(dualScope.cessionarioAllowedWriteAttributes());
            }
        }

        Set<String> safeTechnicalPointers = technicalPointers == null ? Set.of() : technicalPointers;
        Set<String> safeMandatoryAnchors = mandatoryAnchors == null ? Set.of() : mandatoryAnchors;
        Map<String, Object> draftMap = rawDraft instanceof Map<?, ?> m
                ? new LinkedHashMap<>((Map<String, Object>) m)
                : mapper.convertValue(rawDraft, Map.class);
        Map<String, Object> sanitized = new LinkedHashMap<>();
        for (Map.Entry<String, Object> entry : draftMap.entrySet()) {
            String key = entry.getKey();
            String pointer = "/" + key;
            String attrId = mergedWireToAttr.get(pointer);
            boolean stripUnconditionally = safeTechnicalPointers.contains(pointer)
                    || unconditionalStripAttributes.contains(key)
                    || (attrId != null && unconditionalStripAttributes.contains(attrId));
            boolean stripForWriteRestriction = !stripUnconditionally
                    && ((attrId != null && writeRestrictedAttributes.contains(attrId) && !safeMandatoryAnchors.contains(attrId))
                            || (writeRestrictedAttributes.contains(key) && (attrId == null || !safeMandatoryAnchors.contains(attrId))));
            boolean stripped = stripUnconditionally || stripForWriteRestriction;
            if (stripped && entry.getValue() != null && strippedAttributeSink != null) {
                strippedAttributeSink.add(attrId != null ? attrId : key);
                strippedAttributeSink.add(key);
            }
            sanitized.put(key, stripped ? null : entry.getValue());
        }
        if (rawDraft instanceof Map<?, ?>) {
            return (DraftDTO) java.util.Collections.unmodifiableMap(sanitized);
        }
        return (DraftDTO) mapper.convertValue(sanitized, rawDraft.getClass());
    }

    /**
     * Opt-in hook enabling per-record contextual {@code TARGET} masking during read projections
     * ({@code P12}). Disabled by default to preserve {@code P10.4-R03} zero N+1 query guarantees.
     */
    protected boolean requiresRecordContextualSearchMasking() {
        return false;
    }

    private TargetReadProjectionEvaluation resolveContextualSearchTargetProjection(E entity) {
        if (!requiresRecordContextualSearchMasking() || entity == null) {
            return null;
        }
        Map<String, Object> mergedFacts = mergeSubjectAndEntityFacts(entity);
        return serviceSupport.authorizeTargetEntityProjection(
                decisionPoint,
                factContractDigest,
                mergedFacts,
                resolveFactStatuses(mergedFacts)
        );
    }

    @Override
    protected final ResourceMapper<E, ResponseDTO, CreateDTO, UpdateDTO, ID> getResourceMapper() {
        ResourceMapper<E, ResponseDTO, CreateDTO, UpdateDTO, ID> current = this.wrappedMapper;
        if (current == null) {
            synchronized (this) {
                current = this.wrappedMapper;
                if (current == null) {
                    ResourceMapper<E, ResponseDTO, CreateDTO, UpdateDTO, ID> raw = Objects.requireNonNull(
                            getRawResourceMapper(), "getRawResourceMapper() must not return null");
                    current = serviceSupport.wrapResourceMapper(
                            raw,
                            responseType,
                            resolveResourceKey(),
                            this::resolveContextualSearchTargetProjection
                    );
                    this.wrappedMapper = current;
                }
            }
        }
        return current;
    }

    @Override
    public Object prepareUpdateValidationDraft(ID id, E candidate, UpdateDTO dto) {
        return getRawResourceMapper().toResponse(candidate);
    }

    @Override
    protected final ResourceFilterAccessScope<E> resolveResourceFilterAccessScope() {
        Map<String, Object> subjectFacts = resolveSubjectAndEnvironmentFacts();
        return serviceSupport.authorizeAndResolveAccessScope(
                decisionPoint,
                factContractDigest,
                resolveRequestHeaderNames(),
                subjectFacts,
                resolveFactStatuses(subjectFacts),
                resolveRequestedQueryFieldUses(),
                getGovernanceContract().baselineFieldUseDirectives(),
                jpaDataScopeAdapter,
                resolveHardScopeJpql(),
                resolveHardScopeParams(),
                criteriaTranslator,
                resolveHardScope(),
                this
        );
    }

    @Override
    protected final void assertEntityAccessAllowed(E entity) {
        if (entity == null) {
            return;
        }
        serviceSupport.ensureActiveQueryContext(this, this::resolveResourceFilterAccessScope);
        try {
            verifyEntityAccessAllowed(entity);
        } catch (RuntimeException | Error ex) {
            serviceSupport.completeBatchEnrichResponses(this);
            throw ex;
        }
    }

    @Override
    public final void assertItemAccessible(ID id) {
        serviceSupport.executeInReentrancyScopeVoid(() -> {
            try {
                super.assertItemAccessible(id);
            } finally {
                serviceSupport.completeBatchEnrichResponses(this);
            }
        });
    }

    @Override
    protected void enrichResponses(List<ResponseDTO> responses) {
        try {
            super.enrichResponses(responses);
        } finally {
            serviceSupport.completeBatchEnrichResponses(this);
        }
    }

    /** Convenience overload delegating to {@link #filter(GenericFilterDTO, Pageable, Collection)}. */
    public Page<ResponseDTO> filter(FilterDTO filterDto, Pageable pageable) {
        return filter(filterDto, pageable, List.of());
    }

    @Override
    public Page<ResponseDTO> filter(FilterDTO filterDto, Pageable pageable, Collection<ID> includeIds) {
        Map<FieldUseCategory, Set<String>> extractedUses = serviceSupport.dtoIntrospector().extractQueryFieldUses(
                filterDto,
                pageable != null ? pageable.getSort() : null,
                getGovernanceContract(),
                governanceSpec
        );
        return serviceSupport.executeInReentrancyScope(() -> serviceSupport.executeWithExtractedQueryFieldUses(
                extractedUses,
                () -> super.filter(filterDto, pageable, includeIds)
        ));
    }

    @Override
    public CollectionExportResult exportCollection(CollectionExportRequest<FilterDTO> request) {
        Map<FieldUseCategory, Set<String>> extractedUses = serviceSupport.dtoIntrospector().extractExportQueryFieldUses(
                request,
                getGovernanceContract(),
                governanceSpec
        );
        return serviceSupport.executeInReentrancyScope(() -> serviceSupport.executeWithExtractedQueryFieldUses(
                extractedUses,
                () -> super.exportCollection(request)
        ));
    }

    @Override
    public CursorPage<ResponseDTO> filterByCursor(FilterDTO filter, Sort sort, String after, String before, int size) {
        Map<FieldUseCategory, Set<String>> extractedUses = serviceSupport.dtoIntrospector().extractQueryFieldUses(
                filter,
                sort,
                getGovernanceContract(),
                governanceSpec
        );
        return serviceSupport.executeInReentrancyScope(() -> serviceSupport.executeWithExtractedQueryFieldUses(
                extractedUses,
                () -> super.filterByCursor(filter, sort, after, before, size)
        ));
    }

    @Override
    public OptionalLong locate(FilterDTO filter, Sort sort, ID id) {
        Map<FieldUseCategory, Set<String>> extractedUses = serviceSupport.dtoIntrospector().extractQueryFieldUses(
                filter,
                sort,
                getGovernanceContract(),
                governanceSpec
        );
        return serviceSupport.executeInReentrancyScope(() -> serviceSupport.executeWithExtractedQueryFieldUses(
                extractedUses,
                () -> super.locate(filter, sort, id)
        ));
    }

    @Override
    public Page<OptionDTO<ID>> filterOptions(FilterDTO filter, Pageable pageable) {
        Map<FieldUseCategory, Set<String>> extractedUses = serviceSupport.dtoIntrospector().extractQueryFieldUses(
                filter,
                pageable != null ? pageable.getSort() : null,
                getGovernanceContract(),
                governanceSpec
        );
        return serviceSupport.executeInReentrancyScope(() -> serviceSupport.executeWithExtractedQueryFieldUses(
                extractedUses,
                () -> super.filterOptions(filter, pageable)
        ));
    }

    @Override
    public List<OptionDTO<ID>> byIdsOptions(Collection<ID> ids) {
        return serviceSupport.executeInReentrancyScope(() -> super.byIdsOptions(ids));
    }

    @Override
    public Page<OptionDTO<Object>> filterOptionSourceOptions(
            String sourceKey,
            OptionSourceFilterRequest<FilterDTO> request,
            Pageable pageable,
            Object providerFilterPayload
    ) {
        Map<FieldUseCategory, Set<String>> extractedUses = serviceSupport.dtoIntrospector().extractQueryFieldUses(
                request != null ? request.filter() : providerFilterPayload,
                pageable != null ? pageable.getSort() : null,
                getGovernanceContract(),
                governanceSpec
        );
        return serviceSupport.executeInReentrancyScope(() -> serviceSupport.executeWithExtractedQueryFieldUses(
                extractedUses,
                () -> super.filterOptionSourceOptions(sourceKey, request, pageable, providerFilterPayload)
        ));
    }

    @Override
    public List<OptionDTO<Object>> byIdsOptionSourceOptions(
            String sourceKey,
            OptionSourceByIdsRequest<FilterDTO> request,
            Object providerFilterPayload
    ) {
        Map<FieldUseCategory, Set<String>> extractedUses = serviceSupport.dtoIntrospector().extractQueryFieldUses(
                request != null ? request.filter() : providerFilterPayload,
                null,
                getGovernanceContract(),
                governanceSpec
        );
        return serviceSupport.executeInReentrancyScope(() -> serviceSupport.executeWithExtractedQueryFieldUses(
                extractedUses,
                () -> super.byIdsOptionSourceOptions(sourceKey, request, providerFilterPayload)
        ));
    }

    @Override
    public GroupByStatsResponse groupByStats(GroupByStatsRequest<FilterDTO> request) {
        Map<FieldUseCategory, Set<String>> extractedUses = serviceSupport.dtoIntrospector().extractQueryFieldUses(
                request != null ? request.filter() : null,
                null,
                getGovernanceContract(),
                governanceSpec
        );
        return serviceSupport.executeInReentrancyScope(() -> serviceSupport.executeWithExtractedQueryFieldUses(
                extractedUses,
                () -> super.groupByStats(request)
        ));
    }

    @Override
    public TimeSeriesStatsResponse timeSeriesStats(TimeSeriesStatsRequest<FilterDTO> request) {
        Map<FieldUseCategory, Set<String>> extractedUses = serviceSupport.dtoIntrospector().extractQueryFieldUses(
                request != null ? request.filter() : null,
                null,
                getGovernanceContract(),
                governanceSpec
        );
        return serviceSupport.executeInReentrancyScope(() -> serviceSupport.executeWithExtractedQueryFieldUses(
                extractedUses,
                () -> super.timeSeriesStats(request)
        ));
    }

    @Override
    public DistributionStatsResponse distributionStats(DistributionStatsRequest<FilterDTO> request) {
        Map<FieldUseCategory, Set<String>> extractedUses = serviceSupport.dtoIntrospector().extractQueryFieldUses(
                request != null ? request.filter() : null,
                null,
                getGovernanceContract(),
                governanceSpec
        );
        return serviceSupport.executeInReentrancyScope(() -> serviceSupport.executeWithExtractedQueryFieldUses(
                extractedUses,
                () -> super.distributionStats(request)
        ));
    }

    @Override
    public ComparisonStatsResponse comparisonStats(ComparisonStatsRequest<FilterDTO> request) {
        Map<FieldUseCategory, Set<String>> extractedUses = serviceSupport.dtoIntrospector().extractQueryFieldUses(
                request != null ? request.filter() : null,
                null,
                getGovernanceContract(),
                governanceSpec
        );
        return serviceSupport.executeInReentrancyScope(() -> serviceSupport.executeWithExtractedQueryFieldUses(
                extractedUses,
                () -> super.comparisonStats(request)
        ));
    }

    @Override
    public List<ID> selectBulkIdentities(FilterDTO filter, Collection<ID> included, Collection<ID> excluded, int maxTargets) {
        Map<FieldUseCategory, Set<String>> extractedUses = serviceSupport.dtoIntrospector().extractQueryFieldUses(
                filter,
                null,
                getGovernanceContract(),
                governanceSpec
        );
        return serviceSupport.executeInReentrancyScope(() -> serviceSupport.executeWithExtractedQueryFieldUses(
                extractedUses,
                () -> super.selectBulkIdentities(filter, included, excluded, maxTargets)
        ));
    }

    @Override
    public BaseResourceCommandService.SavedResult<ID, ResponseDTO> create(CreateDTO dto) {
        return serviceSupport.executeInReentrancyScope(() -> {
            try {
                return super.create(dto);
            } catch (RuntimeException | Error ex) {
                serviceSupport.clearMutationAndQueryContextsOnFailure(this);
                throw ex;
            }
        });
    }

    @Override
    public ResponseDTO update(ID id, UpdateDTO dto) {
        return serviceSupport.executeInReentrancyScope(() -> {
            try {
                return super.update(id, dto);
            } catch (RuntimeException | Error ex) {
                serviceSupport.clearMutationAndQueryContextsOnFailure(this);
                throw ex;
            }
        });
    }

    @Override
    public ResourceRepresentationResult<ResponseDTO> update(
            ID id,
            UpdateDTO dto,
            ResourceVersionUpdatePrecondition<ID> precondition
    ) {
        return serviceSupport.executeInReentrancyScope(() -> {
            try {
                return super.update(id, dto, precondition);
            } catch (RuntimeException | Error ex) {
                serviceSupport.clearMutationAndQueryContextsOnFailure(this);
                throw ex;
            }
        });
    }

    @Override
    public void deleteById(ID id) {
        serviceSupport.executeInReentrancyScopeVoid(() -> {
            try {
                super.deleteById(id);
            } catch (RuntimeException | Error ex) {
                serviceSupport.clearMutationAndQueryContextsOnFailure(this);
                throw ex;
            }
        });
    }

    @Override
    public void deleteAllById(Collection<ID> ids) {
        serviceSupport.executeInReentrancyScopeVoid(() -> {
            try {
                super.deleteAllById(ids);
            } catch (RuntimeException | Error ex) {
                serviceSupport.clearMutationAndQueryContextsOnFailure(this);
                throw ex;
            }
        });
    }

    @Override
    protected final void beforeCreate(CreateDTO dto, E entity) {
        Map<String, Object> mergedFacts = mergeSubjectAndEntityFacts(entity);
        IntrospectedDtoGovernanceContract writeContract = getWriteGovernanceContract(dto);
        Object createPayload = extractCreateIntentPayload(dto, entity, writeContract);
        serviceSupport.authorizeBeforeHydrationAndRules(
                decisionPoint,
                factContractDigest,
                "POST",
                true,
                createPayload,
                writeContract.wirePointerToAttributeIdMap(),
                resolveTechnicalConcurrencyPointers(),
                resolveMandatoryScopeAnchorAttributeIds(),
                resolveDualScopeDelegationSpec(),
                isCallerCedente(entity),
                isCallerCessionario(entity),
                mergedFacts,
                resolveFactStatuses(mergedFacts),
                this
        );
        hydrateBeforeCreate(dto, entity);
    }

    @Override
    protected void afterCreate(CreateDTO dto, E saved) {
        serviceSupport.markPostMutationReadyForOutboxAndMasking();
        onAfterCreate(dto, saved);
    }

    @Override
    protected final void beforeUpdate(ID id, E existing, UpdateDTO dto) {
        Map<String, Object> mergedFacts = mergeSubjectAndEntityFacts(existing);
        IntrospectedDtoGovernanceContract writeContract = getWriteGovernanceContract(dto);
        Object deltaPayload = extractUpdateIntentPayload(id, existing, dto, writeContract);
        serviceSupport.authorizeBeforeHydrationAndRules(
                decisionPoint,
                factContractDigest,
                "PATCH",
                true,
                deltaPayload,
                writeContract.wirePointerToAttributeIdMap(),
                resolveTechnicalConcurrencyPointers(),
                resolveMandatoryScopeAnchorAttributeIds(),
                resolveDualScopeDelegationSpec(),
                isCallerCedente(existing),
                isCallerCessionario(existing),
                mergedFacts,
                resolveFactStatuses(mergedFacts),
                this
        );
        hydrateBeforeUpdate(id, existing, dto);
    }

    @Override
    protected void afterUpdate(ID id, E saved, UpdateDTO dto) {
        serviceSupport.markPostMutationReadyForOutboxAndMasking();
        onAfterUpdate(id, saved, dto);
    }

    @Override
    protected final void beforeDelete(ID id, E entity) {
        Map<String, Object> mergedFacts = mergeSubjectAndEntityFacts(entity);
        serviceSupport.authorizeBeforeDelete(
                decisionPoint,
                factContractDigest,
                resolveDualScopeDelegationSpec(),
                isCallerCedente(entity),
                isCallerCessionario(entity),
                mergedFacts,
                resolveFactStatuses(mergedFacts),
                this
        );
        onBeforeDelete(id, entity);
    }

    @Override
    protected void afterDelete(ID id, E entity) {
        serviceSupport.completeAfterDeleteOutbox(this);
        onAfterDelete(id, entity);
    }

    /**
     * Creates a governed {@link AuthzGovernedBulkDomainResourceAdapter} deriving the
     * {@link ResourceVersionScope} automatically from {@link AuthzCallerContextProvider}
     * ({@code tenantId:principalId}) ({@code Fase P10.11}).
     */
    public AuthzGovernedBulkDomainResourceAdapter<ID, FilterDTO> bulkDomainAdapter(
            ObjectMapper mapper,
            Validator validator,
            ResourceVersionEtagService etags
    ) {
        return bulkDomainAdapter(mapper, validator, etags, () -> {
            if (callerContextProvider != null) {
                AuthzCallerContext callerCtx = callerContextProvider.currentCallerContext();
                Object principal = callerCtx.subjectAndEnvironmentFacts().get("subject.principalId");
                String principalStr = principal != null ? String.valueOf(principal) : "anonymous";
                return new ResourceVersionScope(callerCtx.tenantId() + ":" + principalStr);
            }
            Map<String, Object> facts = resolveSubjectAndEnvironmentFacts();
            Object principal = facts != null ? facts.get("subject.principalId") : null;
            return new ResourceVersionScope(principal != null ? String.valueOf(principal) : "governed-scope");
        });
    }

    @Override
    public AuthzGovernedBulkDomainResourceAdapter<ID, FilterDTO> bulkDomainAdapter(
            ObjectMapper mapper,
            Validator validator,
            ResourceVersionEtagService etags,
            Supplier<ResourceVersionScope> scope
    ) {
        return serviceSupport.wrapBulkDomainResourceAdapter(
                super.bulkDomainAdapter(mapper, validator, etags, scope),
                responseType,
                resolveResourceKey(),
                governanceSpec
        );
    }

    @Override
    public final StatsFieldRegistry getStatsFieldRegistry() {
        StatsFieldRegistry raw = defineRawStatsFieldRegistry();
        if (raw == null || raw.isEmpty()) {
            return StatsFieldRegistry.empty();
        }
        AuthzGovernedStatsQueryExecutor statsExec = this.governedStatsExecutor;
        if (statsExec != null) {
            return statsExec.filterStatsFieldRegistry(raw);
        }
        return serviceSupport.wrapStatsQueryExecutor(
                new NoOpStatsQueryExecutor(),
                responseType,
                resolveResourceKey(),
                governanceSpec
        ).filterStatsFieldRegistry(raw);
    }

    /**
     * Returns {@code true} when a {@code null} property on {@code UpdateDTO} represents an
     * explicit clear (`WriteChangeKind.CLEAR_EXPLICIT_NULL`) rather than an omitted partial field.
     *
     * <p>By default, returns {@code true} whenever {@code attributeId} is a mandatory scope anchor
     * ({@link #resolveMandatoryScopeAnchorAttributeIds()}), ensuring any attempt to clear a scope
     * anchor on {@code update} or {@code toBulkUpdate} fails closed with
     * {@code AUTHZ_SCOPE_ANCHOR_CLEAR_FORBIDDEN} ({@code P10.8-R02}).</p>
     */
    protected boolean isExplicitNullClearInUpdate(
            ID id,
            E existing,
            UpdateDTO dto,
            String wireFieldName,
            String attributeId
    ) {
        return attributeId != null && resolveMandatoryScopeAnchorAttributeIds().contains(attributeId);
    }

    /**
     * Extracts the create payload for {@code WriteIntent} extraction, omitting optional {@code null}
     * attributes on {@code CREATE} while retaining explicit {@code null} entries for all mandatory
     * scope anchors (including anchors omitted from a {@code Map} or {@code CreateDTO}) so missing
     * scope anchors always fail closed with {@code AUTHZ_SCOPE_ANCHOR_CLEAR_FORBIDDEN}
     * ({@code Fase P10.8}, {@code P10.8-R02}).
     */
    @SuppressWarnings("unchecked")
    protected Object extractCreateIntentPayload(
            CreateDTO dto,
            E entity,
            IntrospectedDtoGovernanceContract writeContract
    ) {
        if (dto instanceof String) {
            return dto;
        }
        Map<String, Object> dtoMap = dto == null
                ? Map.of()
                : (dto instanceof Map<?, ?> m
                        ? (Map<String, Object>) m
                        : deltaObjectMapper.convertValue(dto, Map.class));
        Set<String> anchors = resolveMandatoryScopeAnchorAttributeIds();
        Map<String, String> wireToAttr = writeContract.wirePointerToAttributeIdMap();
        Map<String, Object> filtered = new LinkedHashMap<>();
        Set<String> presentAnchorAttrs = new java.util.LinkedHashSet<>();
        for (Map.Entry<String, Object> entry : dtoMap.entrySet()) {
            String key = entry.getKey();
            Object val = entry.getValue();
            String attrId = wireToAttr.get("/" + key);
            if (val != null || (attrId != null && anchors.contains(attrId))) {
                filtered.put(key, val);
                if (attrId != null && anchors.contains(attrId) && val != null) {
                    presentAnchorAttrs.add(attrId);
                }
            }
        }
        for (String anchorAttrId : anchors) {
            if (!presentAnchorAttrs.contains(anchorAttrId)) {
                String anchorWireKey = findWireKeyForAttributeId(wireToAttr, anchorAttrId);
                if (anchorWireKey == null) {
                    throw new SecurityException("AUTHZ_SCOPE_ANCHOR_CLEAR_FORBIDDEN: Mandatory scope anchor '"
                            + anchorAttrId + "' is missing from create contract (CC06/P13/P14)");
                }
                filtered.put(anchorWireKey, null);
            }
        }
        return filtered;
    }

    /**
     * Extracts the update delta payload for {@code WriteIntent} extraction by comparing {@code dto}
     * against the raw response projection of {@code existing}, ensuring unchanged fields projected
     * during {@code AbstractBaseResourceService.toBulkUpdate} are omitted from the {@code PATCH}
     * {@code WriteIntent} while mandatory scope anchors cleared to {@code null} are captured as
     * {@code CLEAR_EXPLICIT_NULL} ({@code P10.8-R02}).
     */
    protected Object extractUpdateIntentPayload(ID id, E existing, UpdateDTO dto) {
        return extractUpdateIntentPayload(id, existing, dto, getWriteGovernanceContract(dto));
    }

    /**
     * Extracts the update delta payload for {@code WriteIntent} extraction using {@code writeContract}.
     */
    @SuppressWarnings("unchecked")
    protected Object extractUpdateIntentPayload(
            ID id,
            E existing,
            UpdateDTO dto,
            IntrospectedDtoGovernanceContract writeContract
    ) {
        if (dto == null) {
            return Map.of();
        }
        Map<String, Object> dtoMap = dto instanceof Map<?, ?> m
                ? (Map<String, Object>) m
                : deltaObjectMapper.convertValue(dto, Map.class);
        if (existing == null) {
            return dtoMap;
        }
        ResponseDTO baselineResponse = getRawResourceMapper().toResponse(existing);
        if (baselineResponse == null) {
            return dtoMap;
        }
        Map<String, Object> baselineMap = deltaObjectMapper.convertValue(baselineResponse, Map.class);
        Map<String, String> wireToAttr = writeContract.wirePointerToAttributeIdMap();
        Map<String, Object> delta = new LinkedHashMap<>();
        for (Map.Entry<String, Object> entry : dtoMap.entrySet()) {
            String key = entry.getKey();
            Object newVal = entry.getValue();
            String attrId = wireToAttr.get("/" + key);
            if (newVal == null) {
                if (isExplicitNullClearInUpdate(id, existing, dto, key, attrId)) {
                    delta.put(key, null);
                }
                continue;
            }
            Object oldVal = baselineMap.get(key);
            if (!Objects.equals(newVal, oldVal)) {
                delta.put(key, newVal);
            }
        }
        return delta;
    }

    /**
     * Extracts the command intent payload for {@link #executeGovernedVersionedCommand} and
     * {@link #executeGovernedItemCommand}, combining non-null properties from {@code commandDto}
     * with any target {@code attributeId}s declared in
     * {@link AuthzResourceGovernanceSpec#operationModifiedAttributes()} for {@code actionOrOperationId}
     * ({@code Fase P10.10}).
     */
    @SuppressWarnings("unchecked")
    protected Object extractCommandIntentPayload(
            ID id,
            E existing,
            String actionOrOperationId,
            Object commandDto,
            IntrospectedDtoGovernanceContract commandContract,
            Map<String, String> mergedWireToAttr
    ) {
        if (commandDto instanceof String) {
            return commandDto;
        }
        Map<String, Object> payload = new LinkedHashMap<>();
        Set<String> presentAttrIds = new java.util.LinkedHashSet<>();
        Set<String> anchors = resolveMandatoryScopeAnchorAttributeIds();
        Set<String> declaredModifiedAttrs = (governanceSpec != null && actionOrOperationId != null)
                ? governanceSpec.operationModifiedAttributes().getOrDefault(actionOrOperationId, Set.of())
                : Set.of();
        Map<String, String> responseWireToAttr = getGovernanceContract().wirePointerToAttributeIdMap();
        Map<String, Object> baselineMap = Map.of();
        if (existing != null) {
            ResponseDTO baselineResponse = getRawResourceMapper().toResponse(existing);
            if (baselineResponse != null) {
                baselineMap = deltaObjectMapper.convertValue(baselineResponse, Map.class);
            }
        }
        if (commandDto != null) {
            Map<String, Object> dtoMap = commandDto instanceof Map<?, ?> m
                    ? (Map<String, Object>) m
                    : deltaObjectMapper.convertValue(commandDto, Map.class);
            for (Map.Entry<String, Object> entry : dtoMap.entrySet()) {
                String key = entry.getKey();
                Object val = entry.getValue();
                String pointer = "/" + key;
                String attrId = mergedWireToAttr.get(pointer);
                boolean isGovernedEntityAttribute = responseWireToAttr.containsKey(pointer)
                        || (attrId != null && declaredModifiedAttrs.contains(attrId))
                        || (attrId != null && anchors.contains(attrId))
                        || hasExplicitDomainLineageOnProperty(commandDto.getClass(), key)
                        || declaredModifiedAttrs.isEmpty();
                if (!isGovernedEntityAttribute) {
                    continue;
                }
                if (val != null) {
                    if (existing != null
                            && baselineMap.containsKey(key)
                            && Objects.equals(val, baselineMap.get(key))
                            && (attrId == null || !declaredModifiedAttrs.contains(attrId))) {
                        continue;
                    }
                    payload.put(key, val);
                    if (attrId != null) {
                        presentAttrIds.add(attrId);
                    }
                } else if (attrId != null && anchors.contains(attrId)) {
                    payload.put(key, null);
                    presentAttrIds.add(attrId);
                }
            }
        }
        for (String attrId : declaredModifiedAttrs) {
            if (!presentAttrIds.contains(attrId)) {
                String wireKey = findWireKeyForAttributeId(mergedWireToAttr, attrId);
                if (wireKey == null) {
                    wireKey = attrId;
                    mergedWireToAttr.put("/" + wireKey, attrId);
                }
                payload.putIfAbsent(wireKey, "__governed_command_transition__");
            }
        }
        return payload;
    }

    private static boolean hasExplicitDomainLineageOnProperty(Class<?> dtoClass, String propertyName) {
        if (dtoClass == null || propertyName == null || Map.class.isAssignableFrom(dtoClass)) {
            return false;
        }
        if (dtoClass.isRecord() && dtoClass.getRecordComponents() != null) {
            for (RecordComponent rc : dtoClass.getRecordComponents()) {
                if (propertyName.equals(rc.getName())) {
                    if (rc.isAnnotationPresent(DomainLineage.class)) {
                        return true;
                    }
                    if (rc.getAccessor() != null && rc.getAccessor().isAnnotationPresent(DomainLineage.class)) {
                        return true;
                    }
                }
            }
        }
        for (Class<?> curr = dtoClass; curr != null && curr != Object.class; curr = curr.getSuperclass()) {
            try {
                Field f = curr.getDeclaredField(propertyName);
                if (f.isAnnotationPresent(DomainLineage.class)) {
                    return true;
                }
            } catch (NoSuchFieldException ignored) {
                // continue
            }
            for (Method m : curr.getDeclaredMethods()) {
                if (m.getParameterCount() == 0 && m.isAnnotationPresent(DomainLineage.class)) {
                    String name = m.getName();
                    if (propertyName.equals(name)
                            || (("get" + Character.toUpperCase(propertyName.charAt(0)) + propertyName.substring(1)).equals(name))) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    private static String findWireKeyForAttributeId(Map<String, String> wireToAttr, String targetAttributeId) {
        for (Map.Entry<String, String> entry : wireToAttr.entrySet()) {
            if (targetAttributeId.equals(entry.getValue())) {
                String pointer = entry.getKey();
                return pointer.startsWith("/") ? pointer.substring(1) : pointer;
            }
        }
        return null;
    }

    /**
     * Wires governed collection export, option-source, and analytics executors into the underlying
     * {@link AbstractBaseQueryResourceService} fields ({@code Fase P10.7}).
     */
    public void configureGovernedQueryInfrastructure(
            CollectionExportExecutor rawExportExecutor,
            OptionSourceQueryExecutor rawOptionSourceExecutor,
            StatsQueryExecutor rawStatsExecutor,
            StatsProperties statsProperties
    ) {
        if (rawExportExecutor != null) {
            CollectionExportExecutor wrappedExport = serviceSupport.wrapCollectionExportExecutor(
                    rawExportExecutor,
                    responseType,
                    resolveResourceKey()
            );
            setQueryServiceField("collectionExportExecutor", wrappedExport);
        }
        if (rawOptionSourceExecutor != null) {
            AuthzGovernedOptionSourceProvider wrappedOptionSource = serviceSupport.wrapOptionSourceQueryExecutor(
                    rawOptionSourceExecutor,
                    responseType,
                    resolveResourceKey(),
                    governanceSpec
            );
            setQueryServiceField("optionSourceQueryExecutor", wrappedOptionSource);
            setQueryServiceField("optionSourceEligibility", new OptionSourceEligibility());
        }
        if (rawStatsExecutor != null) {
            AuthzGovernedStatsQueryExecutor wrappedStats = serviceSupport.wrapStatsQueryExecutor(
                    rawStatsExecutor,
                    responseType,
                    resolveResourceKey(),
                    governanceSpec
            );
            this.governedStatsExecutor = wrappedStats;
            setQueryServiceField("statsQueryExecutor", wrappedStats);
            setQueryServiceField("statsEligibility", new StatsEligibility());
            setQueryServiceField(
                    "statsProperties",
                    statsProperties != null
                            ? statsProperties
                            : new StatsProperties(true, 20, 100, StatsSupportMode.AUTO)
            );
        }
    }

    private Map<String, Object> mergeSubjectAndEntityFacts(E entity) {
        Set<String> incomingHeaders = resolveRequestHeaderNames();
        if (incomingHeaders != null && !incomingHeaders.isEmpty()) {
            Map<String, String> headerProbe = new LinkedHashMap<>();
            for (String h : incomingHeaders) {
                headerProbe.put(h, "__untrusted_client_header_probe__");
            }
            UntrustedRequestHeaderGuard.assertNoAuthoritySpoofingHeaders(headerProbe, Map.of());
        }
        Map<String, Object> merged = new LinkedHashMap<>();
        Map<String, Object> subjectFacts = resolveSubjectAndEnvironmentFacts();
        if (subjectFacts != null) {
            merged.putAll(subjectFacts);
        }
        if (entity != null) {
            Map<String, Object> targetFacts = extractEntityTargetFacts(entity);
            if (targetFacts != null) {
                merged.putAll(targetFacts);
            }
        }
        return Map.copyOf(merged);
    }

    private void setQueryServiceField(String fieldName, Object value) {
        try {
            Field f = AbstractBaseQueryResourceService.class.getDeclaredField(fieldName);
            f.setAccessible(true);
            f.set(this, value);
        } catch (ReflectiveOperationException ex) {
            throw new IllegalStateException("Failed to configure AbstractBaseQueryResourceService field '" + fieldName + "'", ex);
        }
    }

    private void detachEntityIfManaged(E entity) {
        if (entity == null) {
            return;
        }
        try {
            Field emField = AbstractBaseQueryResourceService.class.getDeclaredField("entityManager");
            emField.setAccessible(true);
            Object emObj = emField.get(this);
            if (emObj instanceof jakarta.persistence.EntityManager em && em.contains(entity)) {
                em.detach(entity);
            }
        } catch (ReflectiveOperationException ignored) {
            // no-op when EntityManager is not bound
        }
    }

    private static final class NoOpStatsQueryExecutor implements StatsQueryExecutor {
        @Override
        public <T> org.praxisplatform.uischema.stats.dto.GroupByStatsResponse executeGroupBy(
                jakarta.persistence.EntityManager em,
                Class<T> entityClass,
                org.springframework.data.jpa.domain.Specification<T> spec,
                org.praxisplatform.uischema.stats.StatsFieldDescriptor groupDescriptor,
                List<org.praxisplatform.uischema.stats.service.ResolvedStatsMetric> resolvedMetrics,
                org.praxisplatform.uischema.stats.dto.GroupByStatsRequest<?> request,
                int maxBuckets
        ) {
            throw new UnsupportedOperationException("NoOpStatsQueryExecutor is used only for static registry filtering");
        }

        @Override
        public <T> org.praxisplatform.uischema.stats.dto.TimeSeriesStatsResponse executeTimeSeries(
                jakarta.persistence.EntityManager em,
                Class<T> entityClass,
                org.springframework.data.jpa.domain.Specification<T> spec,
                org.praxisplatform.uischema.stats.StatsFieldDescriptor timeDescriptor,
                List<org.praxisplatform.uischema.stats.service.ResolvedStatsMetric> resolvedMetrics,
                org.praxisplatform.uischema.stats.dto.TimeSeriesStatsRequest<?> request,
                int maxPoints
        ) {
            throw new UnsupportedOperationException("NoOpStatsQueryExecutor is used only for static registry filtering");
        }

        @Override
        public <T> org.praxisplatform.uischema.stats.dto.DistributionStatsResponse executeDistribution(
                jakarta.persistence.EntityManager em,
                Class<T> entityClass,
                org.springframework.data.jpa.domain.Specification<T> spec,
                org.praxisplatform.uischema.stats.StatsFieldDescriptor distributionDescriptor,
                org.praxisplatform.uischema.stats.StatsFieldDescriptor metricDescriptor,
                org.praxisplatform.uischema.stats.dto.DistributionStatsRequest<?> request,
                int maxBuckets
        ) {
            throw new UnsupportedOperationException("NoOpStatsQueryExecutor is used only for static registry filtering");
        }
    }
}
