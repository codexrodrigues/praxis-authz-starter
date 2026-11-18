package org.praxisplatform.authz.host.metadata;

import java.lang.reflect.Field;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;
import java.util.function.Function;
import java.util.function.Supplier;
import org.praxisplatform.authz.catalog.FieldLineageCatalogEntry;
import org.praxisplatform.authz.catalog.SemanticDecisionPointCatalogService;
import org.praxisplatform.authz.contracts.context.FactResolutionStatus;
import org.praxisplatform.authz.contracts.decisionpoint.DecisionPointDescriptor;
import org.praxisplatform.authz.contracts.decisionpoint.FieldUseCategory;
import org.praxisplatform.authz.contracts.envelope.MaskDirective;
import org.praxisplatform.authz.enforcement.context.UntrustedRequestHeaderGuard;
import org.praxisplatform.authz.enforcement.jpa.JpaDataScopeAdapter;
import org.praxisplatform.authz.host.metadata.MetadataDtoGovernanceIntrospector.IntrospectedDtoGovernanceContract;
import org.praxisplatform.authz.seams.GovernedExportAndAiToolAuthorizationSeam.AiGovernanceMetadataView;
import org.praxisplatform.authz.seams.GovernedExportAndAiToolAuthorizationSeam.SanitizedAiToolProjection;
import org.praxisplatform.authz.seams.MetadataResourceAuthorizationSeam.TargetReadProjectionEvaluation;
import org.praxisplatform.authz.seams.RuntimeDecisionPointRegistry;
import org.praxisplatform.uischema.capability.ResourceStateSnapshot;
import org.praxisplatform.uischema.capability.ResourceStateSnapshotProvider;
import org.praxisplatform.uischema.capability.ResourceStateSnapshotScope;
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
import org.praxisplatform.uischema.service.base.AbstractReadOnlyResourceService;
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
 * Canonical governed base class for read-only resources extending
 * {@link AbstractReadOnlyResourceService} ({@code Fases P10.7 & P10.8}, {@code CC03}, {@code CC06},
 * {@code CC07}, {@code P01..P14}, {@code P46}, {@code P50}).
 *
 * <p>Eliminates manual {@link AuthzGovernedResourceServiceSupport} boilerplate in read-only
 * resource services and Radar/analytical projections by wiring:</p>
 * <ul>
 *   <li>Automatic {@link MetadataDtoGovernanceIntrospector} introspection of {@code responseType};</li>
 *   <li>Automatic {@link AuthzMaskingResourceMapperDecorator} wrapping of {@link #getRawResourceMapper()};</li>
 *   <li>Unified {@link #resolveResourceFilterAccessScope()} composition ({@code hardScope} AND OPA
 *       {@code DataScopePlan}) and {@code N+1}-safe {@link #assertEntityAccessAllowed(Object)};</li>
 *   <li>Automatic {@code ThreadLocal} cleanup in {@link #enrichResponses(List)};</li>
 *   <li>Automatic discovery-time filtering of {@link #getStatsFieldRegistry()} via
 *       {@link AuthzGovernedStatsQueryExecutor#filterStatsFieldRegistry(StatsFieldRegistry)};</li>
 *   <li>Optional {@link AuthzResourceGovernanceSpec} + {@link AuthzCallerContextProvider} constructor
 *       eliminating manual {@code resolveHardScope*}, {@code resolveResourceKey}, and caller-fact overrides.</li>
 * </ul>
 *
 * @param <E> JPA entity type
 * @param <ResponseDTO> response DTO type annotated with {@code @DomainGovernance}
 * @param <ID> entity identifier type
 * @param <FilterDTO> filter DTO type
 */
public abstract class AbstractAuthzGovernedReadOnlyResourceService<
        E,
        ResponseDTO,
        ID,
        FilterDTO extends GenericFilterDTO
> extends AbstractReadOnlyResourceService<E, ResponseDTO, ID, FilterDTO> {

    private final Class<ResponseDTO> responseType;
    private final AuthzGovernedResourceServiceSupport serviceSupport;
    private final DecisionPointDescriptor decisionPoint;
    private final String factContractDigest;
    private final JpaDataScopeAdapter jpaDataScopeAdapter;
    private final JpaCriteriaDataScopeTranslator criteriaTranslator;
    private final AuthzResourceGovernanceSpec<E> governanceSpec;
    private final AuthzCallerContextProvider callerContextProvider;

    private volatile IntrospectedDtoGovernanceContract governanceContract;
    private volatile ResourceMapper<E, ResponseDTO, ?, ?, ID> wrappedMapper;
    private volatile AuthzGovernedStatsQueryExecutor governedStatsExecutor;
    private volatile AuthzGovernedReactiveDeterminationProvider governedDeterminationProvider;

    /**
     * Creates a governed read-only resource service driven by a declarative
     * {@link AuthzResourceGovernanceSpec} and {@link AuthzCallerContextProvider} ({@code Fase P10.8}).
     */
    protected AbstractAuthzGovernedReadOnlyResourceService(
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
     * Creates a governed read-only resource service driven by a declarative
     * {@link AuthzResourceGovernanceSpec}, {@link AuthzCallerContextProvider}, and explicit
     * {@link GenericSpecificationsBuilder} ({@code Fase P10.8}).
     */
    protected AbstractAuthzGovernedReadOnlyResourceService(
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
    }

    /**
     * Creates a governed read-only resource service with the default {@link GenericSpecificationsBuilder}.
     */
    protected AbstractAuthzGovernedReadOnlyResourceService(
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
     * Creates a governed read-only resource service with an explicit {@link GenericSpecificationsBuilder}.
     */
    protected AbstractAuthzGovernedReadOnlyResourceService(
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
    }

    /** Returns the raw unmasked {@link ResourceMapper} to be wrapped automatically by this base class. */
    protected abstract ResourceMapper<E, ResponseDTO, ?, ?, ID> getRawResourceMapper();

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
            return governanceSpec.buildHardScope(callerContextProvider.currentCallerContext());
        }
        throw new IllegalStateException(
                "Override resolveHardScope() or supply an AuthzResourceGovernanceSpec + AuthzCallerContextProvider");
    }

    /** Returns the mandatory host-level JPQL hard-scope clause (e.g. {@code "e.tenantId = :__praxis_hard_tenant_id"}). */
    protected String resolveHardScopeJpql() {
        if (governanceSpec != null) {
            if (callerContextProvider != null) {
                return governanceSpec.buildHardScopeJpql(callerContextProvider.currentCallerContext());
            }
            return governanceSpec.buildHardScopeJpql();
        }
        throw new IllegalStateException(
                "Override resolveHardScopeJpql() or supply an AuthzResourceGovernanceSpec");
    }

    /** Returns the mandatory host-level JPQL hard-scope parameters. */
    protected Map<String, Object> resolveHardScopeParams() {
        if (governanceSpec != null && callerContextProvider != null) {
            return governanceSpec.buildHardScopeParams(callerContextProvider.currentCallerContext());
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
     * Defines the raw {@link StatsFieldRegistry} before static {@code @DomainGovernance} filtering.
     */
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

    /** Returns validated incoming HTTP request headers for anti-spoofing verification, or empty map. */
    protected Map<String, String> resolveRequestHeaders() {
        if (callerContextProvider != null) {
            return callerContextProvider.currentCallerContext().incomingHeaders();
        }
        return Map.of();
    }

    /** Returns the authoritative tenant identifier for header anti-spoofing verification, or {@code null}. */
    protected String resolveCallerTenantId() {
        if (callerContextProvider != null) {
            return callerContextProvider.currentCallerContext().tenantId();
        }
        return null;
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
        return resolveFactStatuses(facts, null);
    }

    /**
     * Returns resolution statuses for the given facts and entity, recording {@link FactResolutionStatus#NULL}
     * for scalar bindings whose entity property evaluates to {@code null}.
     */
    protected Map<String, FactResolutionStatus> resolveFactStatuses(Map<String, Object> facts, E entity) {
        if ((facts == null || facts.isEmpty()) && entity == null) {
            return Map.of();
        }
        Map<String, FactResolutionStatus> callerStatuses =
                callerContextProvider != null ? callerContextProvider.currentCallerContext().factStatuses() : Map.of();
        return AuthzResourceGovernanceSpec.resolveFactStatuses(callerStatuses, facts, governanceSpec, entity);
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

    /**
     * Extracts authoritative target facts from an entity for contextual discovery and TARGET gates
     * ({@code Fase P10.9}).
     */
    protected Map<String, Object> extractEntityTargetFacts(E entity) {
        if (governanceSpec != null) {
            return governanceSpec.extractEntityTargetFacts(entity);
        }
        return Map.of();
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
                    boolean collectionOrigin = callerCtx.callerMatchesOrigin() != null
                            ? callerCtx.callerMatchesOrigin()
                            : governanceSpec.isCallerOrigin(null, callerCtx);
                    boolean collectionDestination = callerCtx.callerMatchesDestination() != null
                            ? callerCtx.callerMatchesDestination()
                            : governanceSpec.isCallerDestination(null, callerCtx);
                    return AuthzResourceOperationAvailabilityProvider.CallerAvailabilityFactContext.fromGovernanceSpec(
                            governanceSpec,
                            callerCtx,
                            collectionOrigin,
                            collectionDestination
                    );
                },
                governanceSpec::extractSnapshotTargetFacts,
                this::resolveItemSnapshotForAvailability,
                (callerAvailabilityCtx, snapshot) -> {
                    AuthzCallerContext callerCtx = callerContextProvider.currentCallerContext();
                    if (callerCtx.callerMatchesOrigin() != null) {
                        return callerCtx.callerMatchesOrigin();
                    }
                    return governanceSpec.isCallerOriginForSnapshot(snapshot, callerCtx);
                },
                (callerAvailabilityCtx, snapshot) -> {
                    AuthzCallerContext callerCtx = callerContextProvider.currentCallerContext();
                    if (callerCtx.callerMatchesDestination() != null) {
                        return callerCtx.callerMatchesDestination();
                    }
                    return governanceSpec.isCallerDestinationForSnapshot(snapshot, callerCtx);
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
     * Derives the canonical {@link FieldLineageCatalogEntry} list for this read-only service's
     * {@code ResponseDTO} ({@code READ_PROJECTION}) via {@link MetadataDtoGovernanceIntrospector}
     * ({@code Fase P10.13}, {@code P36}, {@code P44..P50}, {@code P57}, {@code P58}).
     */
    public List<FieldLineageCatalogEntry> deriveFieldLineageCatalogEntries() {
        return serviceSupport.dtoIntrospector().deriveFieldLineageCatalogEntries(
                resolveResourceKey(),
                responseType,
                null,
                null
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
        String primaryKey = decisionPoint.identity().pointKey();
        if (registry != null) {
            registry.enrichRegisteredPointGovernance(
                    primaryKey,
                    governanceSpec != null ? governanceSpec.dualScopeDelegationSpec() : null,
                    governanceSpec != null ? governanceSpec.mandatoryScopeAnchorAttributeIds() : Set.of(),
                    lineageEntries
            );
            if (governanceSpec != null) {
                for (DecisionPointDescriptor actionDp : governanceSpec.actionDecisionPoints().values()) {
                    registry.enrichRegisteredPointGovernance(
                            actionDp.identity().pointKey(),
                            governanceSpec.dualScopeDelegationSpec(),
                            governanceSpec.mandatoryScopeAnchorAttributeIds(),
                            lineageEntries
                    );
                }
                for (DecisionPointDescriptor surfaceDp : governanceSpec.surfaceDecisionPoints().values()) {
                    registry.enrichRegisteredPointGovernance(
                            surfaceDp.identity().pointKey(),
                            governanceSpec.dualScopeDelegationSpec(),
                            governanceSpec.mandatoryScopeAnchorAttributeIds(),
                            lineageEntries
                    );
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

    private Map<String, Object> mergeSubjectAndEntityFacts(E entity) {
        Map<String, Object> subjectFacts = resolveSubjectAndEnvironmentFacts();
        Set<String> incomingHeaders = resolveRequestHeaderNames();
        Map<String, String> headerProbe = AuthzCallerContext.buildHeaderProbeMap(incomingHeaders, resolveRequestHeaders());
        if (!headerProbe.isEmpty()) {
            UntrustedRequestHeaderGuard.assertNoAuthoritySpoofingHeaders(
                    headerProbe,
                    org.praxisplatform.authz.seams.MetadataResourceAuthorizationSeam.toAuthoritativeSubjectFactMap(
                            subjectFacts,
                            resolveFactStatuses(subjectFacts),
                            resolveCallerTenantId()
                    )
            );
        }
        Map<String, Object> merged = new LinkedHashMap<>();
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
                resolveFactStatuses(mergedFacts, entity)
        );
    }

    @Override
    protected final ResourceMapper<E, ResponseDTO, ?, ?, ID> getResourceMapper() {
        ResourceMapper<E, ResponseDTO, ?, ?, ID> current = this.wrappedMapper;
        if (current == null) {
            synchronized (this) {
                current = this.wrappedMapper;
                if (current == null) {
                    @SuppressWarnings("unchecked")
                    ResourceMapper<E, ResponseDTO, Object, Object, ID> raw =
                            (ResourceMapper<E, ResponseDTO, Object, Object, ID>) Objects.requireNonNull(
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
    protected final ResourceFilterAccessScope<E> resolveResourceFilterAccessScope() {
        Map<String, Object> subjectFacts = resolveSubjectAndEnvironmentFacts();
        return serviceSupport.authorizeAndResolveAccessScope(
                decisionPoint,
                factContractDigest,
                resolveRequestHeaderNames(),
                resolveRequestHeaders(),
                resolveCallerTenantId(),
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

    private void setQueryServiceField(String fieldName, Object value) {
        try {
            Field f = AbstractBaseQueryResourceService.class.getDeclaredField(fieldName);
            f.setAccessible(true);
            f.set(this, value);
        } catch (ReflectiveOperationException ex) {
            throw new IllegalStateException("Failed to configure AbstractBaseQueryResourceService field '" + fieldName + "'", ex);
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
