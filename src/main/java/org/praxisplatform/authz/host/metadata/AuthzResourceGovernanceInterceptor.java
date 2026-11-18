package org.praxisplatform.authz.host.metadata;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.function.Function;
import org.praxisplatform.authz.catalog.FieldLineageCatalogEntry;
import org.praxisplatform.authz.catalog.SemanticDecisionPointCatalogService;
import org.praxisplatform.authz.contracts.annotation.AuthzActionRule;
import org.praxisplatform.authz.contracts.annotation.AuthzCustodyPartition;
import org.praxisplatform.authz.contracts.annotation.AuthzMask;
import org.praxisplatform.authz.contracts.annotation.AuthzMasks;
import org.praxisplatform.authz.contracts.annotation.AuthzScopeAnchor;
import org.praxisplatform.authz.contracts.annotation.AuthzTenantScope;
import org.praxisplatform.authz.contracts.context.FactResolutionStatus;
import org.praxisplatform.authz.contracts.datascope.DataScopePlan;
import org.praxisplatform.authz.contracts.decisionpoint.DecisionPointDescriptor;
import org.praxisplatform.authz.contracts.decisionpoint.FieldUseCategory;
import org.praxisplatform.authz.contracts.policy.DualScopeDelegationSpec;
import org.praxisplatform.authz.host.metadata.MetadataDtoGovernanceIntrospector.IntrospectedDtoGovernanceContract;
import org.praxisplatform.authz.seams.MetadataResourceAuthorizationSeam.AuthorizedQueryScopeContext;
import org.praxisplatform.authz.seams.MetadataResourceAuthorizationSeam.TargetReadProjectionEvaluation;
import org.praxisplatform.authz.seams.RuntimeDecisionPointRegistry;
import org.praxisplatform.uischema.annotation.ApiResource;
import org.praxisplatform.uischema.capability.ResourceStateSnapshot;
import org.praxisplatform.uischema.capability.ResourceStateSnapshotScope;
import org.praxisplatform.uischema.exporting.CollectionExportField;
import org.praxisplatform.uischema.exporting.CollectionExportRequest;
import org.praxisplatform.uischema.governance.AccessMode;
import org.praxisplatform.uischema.governance.MutationContext;
import org.praxisplatform.uischema.governance.MutationKind;
import org.praxisplatform.uischema.governance.ResourceGovernanceInterceptor;
import org.praxisplatform.uischema.id.CompositeIdSupport;
import org.praxisplatform.uischema.service.base.AbstractBaseQueryResourceService;
import org.praxisplatform.uischema.service.base.AbstractBaseResourceService;
import org.praxisplatform.uischema.service.base.BaseResourceCommandService;
import org.praxisplatform.uischema.service.base.BaseResourceQueryService;
import org.praxisplatform.uischema.service.base.ResourceFilterAccessScope;
import org.praxisplatform.uischema.stats.StatsFieldDescriptor;
import org.praxisplatform.uischema.stats.StatsFieldRegistry;
import org.praxisplatform.uischema.stats.dto.DistributionStatsRequest;
import org.praxisplatform.uischema.stats.dto.DistributionStatsResponse;
import org.praxisplatform.uischema.stats.dto.GroupByStatsRequest;
import org.praxisplatform.uischema.stats.dto.GroupByStatsResponse;
import org.praxisplatform.uischema.stats.dto.TimeSeriesStatsRequest;
import org.praxisplatform.uischema.stats.dto.TimeSeriesStatsResponse;
import org.praxisplatform.uischema.stats.service.ResolvedStatsMetric;
import org.praxisplatform.uischema.stats.service.StatsQueryExecutor;
import org.springframework.aop.support.AopUtils;
import org.springframework.context.ApplicationContext;
import org.springframework.core.Ordered;
import org.springframework.core.ResolvableType;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.core.convert.support.DefaultConversionService;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.util.ClassUtils;

/**
 * Auto-configured {@link ResourceGovernanceInterceptor} bringing full Praxis Authorization
 * enforcement (hard tenant/multi-organization scoping, OPA {@code DataScopePlan}, pre-hydration
 * {@code WriteIntent} checks, {@code BEFORE_COMMIT_OUTBOX} obligations, detached DTO masking,
 * and governed export/stats field-use filtering) to plain {@link AbstractBaseQueryResourceService}
 * and {@link AbstractBaseResourceService} subclasses without inheriting custom base classes
 * ({@code Wave 1.4B}).
 *
 * <p>Services extending {@link AbstractAuthzGovernedReadOnlyResourceService} or
 * {@link AbstractAuthzGovernedResourceService} already enforce the full governance pipeline directly
 * and are bypassed cleanly to prevent double enforcement.</p>
 */
public class AuthzResourceGovernanceInterceptor implements ResourceGovernanceInterceptor, Ordered {

    /** Default interceptor order running early in Praxis service governance chains. */
    public static final int DEFAULT_ORDER = Ordered.HIGHEST_PRECEDENCE + 200;

    private static final StatsQueryExecutor NO_OP_STATS_EXECUTOR = new StatsQueryExecutor() {
        @Override
        public <E> GroupByStatsResponse executeGroupBy(
                jakarta.persistence.EntityManager entityManager,
                Class<E> entityClass,
                Specification<E> specification,
                StatsFieldDescriptor groupDescriptor,
                List<ResolvedStatsMetric> resolvedMetrics,
                GroupByStatsRequest<?> request,
                int maxBuckets
        ) {
            throw new UnsupportedOperationException("Registry filtering does not execute stats SQL");
        }

        @Override
        public <E> TimeSeriesStatsResponse executeTimeSeries(
                jakarta.persistence.EntityManager entityManager,
                Class<E> entityClass,
                Specification<E> specification,
                StatsFieldDescriptor timeDescriptor,
                List<ResolvedStatsMetric> resolvedMetrics,
                TimeSeriesStatsRequest<?> request,
                int maxPoints
        ) {
            throw new UnsupportedOperationException("Registry filtering does not execute stats SQL");
        }

        @Override
        public <E> DistributionStatsResponse executeDistribution(
                jakarta.persistence.EntityManager entityManager,
                Class<E> entityClass,
                Specification<E> specification,
                StatsFieldDescriptor distributionDescriptor,
                StatsFieldDescriptor metricDescriptor,
                DistributionStatsRequest<?> request,
                int maxBuckets
        ) {
            throw new UnsupportedOperationException("Registry filtering does not execute stats SQL");
        }
    };

    private final AuthzGovernedResourceServiceSupport serviceSupport;
    private final AuthzCallerContextProvider callerContextProvider;
    private final RuntimeDecisionPointRegistry decisionPointRegistry;
    private final ApplicationContext applicationContext;
    private final boolean failClosedOnUnconfiguredService;
    private final ConcurrentMap<String, AuthzResourceGovernanceSpec<?>> specsByResourceKey = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, Class<?>> controllersByResourceKey = new ConcurrentHashMap<>();
    private final ConcurrentMap<Class<?>, ResolvedGovernanceMetadata> metadataCache = new ConcurrentHashMap<>();
    private volatile boolean controllerBeansScanned = false;
    private final ObjectMapper objectMapper;
    private final ObjectMapper writeIntentBeanMapper =
            AuthzGovernedResourceServiceSupport.createWriteIntentBeanObjectMapper();
    private final ThreadLocal<SnapshotCaptureSlot> snapshotCapture = new ThreadLocal<>();
    private final ThreadLocal<Map<String, ResourceStateSnapshot>> scopedSnapshotCache = new ThreadLocal<>();

    private static final class SnapshotCaptureSlot {
        private final BaseResourceQueryService<?, ?, ?> expectedService;
        private Object capturedEntity;

        private SnapshotCaptureSlot(BaseResourceQueryService<?, ?, ?> expectedService) {
            this.expectedService = expectedService;
        }
    }

    private record ResolvedGovernanceMetadata(
            String resourceKey,
            Class<?> serviceClass,
            Class<?> entityClass,
            Class<?> responseDtoClass,
            Class<?> createDtoClass,
            Class<?> updateDtoClass,
            Class<?> controllerClass,
            AuthzResourceGovernanceSpec<?> spec,
            IntrospectedDtoGovernanceContract responseContract
    ) {}

    /** Creates an interceptor using auto-discovery on plain Praxis services (permissive for unannotated auxiliary services). */
    public AuthzResourceGovernanceInterceptor(
            AuthzGovernedResourceServiceSupport serviceSupport,
            AuthzCallerContextProvider callerContextProvider
    ) {
        this(serviceSupport, callerContextProvider, null, List.of(), null, false);
    }

    /** Creates an interceptor wired with Spring registry, pre-registered specs, and optional application context scanning. */
    public AuthzResourceGovernanceInterceptor(
            AuthzGovernedResourceServiceSupport serviceSupport,
            AuthzCallerContextProvider callerContextProvider,
            RuntimeDecisionPointRegistry decisionPointRegistry,
            Collection<? extends AuthzResourceGovernanceSpec<?>> registeredSpecs,
            ApplicationContext applicationContext,
            boolean failClosedOnUnconfiguredService
    ) {
        this.serviceSupport = Objects.requireNonNull(serviceSupport, "serviceSupport is required");
        this.callerContextProvider = Objects.requireNonNull(callerContextProvider, "callerContextProvider is required");
        this.decisionPointRegistry = decisionPointRegistry;
        this.applicationContext = applicationContext;
        this.failClosedOnUnconfiguredService = failClosedOnUnconfiguredService;
        if (registeredSpecs != null) {
            for (AuthzResourceGovernanceSpec<?> spec : registeredSpecs) {
                if (spec != null && spec.resourceKey() != null) {
                    this.specsByResourceKey.put(spec.resourceKey(), spec);
                }
            }
        }
        this.objectMapper = new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
                .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
    }

    /** Registers or replaces an explicit {@link AuthzResourceGovernanceSpec} by {@code resourceKey}. */
    public AuthzResourceGovernanceInterceptor registerSpec(AuthzResourceGovernanceSpec<?> spec) {
        Objects.requireNonNull(spec, "spec is required");
        specsByResourceKey.put(spec.resourceKey(), spec);
        metadataCache.clear();
        return this;
    }

    /** Associates a {@code @ApiResource} controller class with a {@code resourceKey} for annotation discovery. */
    public AuthzResourceGovernanceInterceptor registerControllerClass(String resourceKey, Class<?> controllerClass) {
        Objects.requireNonNull(resourceKey, "resourceKey is required");
        Objects.requireNonNull(controllerClass, "controllerClass is required");
        controllersByResourceKey.put(resourceKey, controllerClass);
        metadataCache.clear();
        return this;
    }

    /** Returns the resolved or auto-introspected {@link AuthzResourceGovernanceSpec} for {@code service}, if governed. */
    public AuthzResourceGovernanceSpec<?> resolvedSpecFor(BaseResourceQueryService<?, ?, ?> service) {
        if (isExplicitlyGovernedService(service)) {
            return null;
        }
        ResolvedGovernanceMetadata meta = resolveMetadataIfGoverned(service, false);
        return meta != null ? meta.spec() : null;
    }

    /** Registers a {@link AuthzResourceOperationAvailabilityProvider.ResourceAvailabilityPolicyBinding} for {@code service} if governed. */
    public void registerAvailabilityBindingIfSupported(
            BaseResourceQueryService<?, ?, ?> service,
            AuthzResourceOperationAvailabilityProvider availabilityProvider
    ) {
        if (availabilityProvider == null || isExplicitlyGovernedService(service)) {
            return;
        }
        ResolvedGovernanceMetadata meta = resolveMetadataIfGoverned(service, false);
        if (meta == null || meta.spec() == null) {
            return;
        }
        AuthzResourceGovernanceSpec<?> spec = meta.spec();
        DecisionPointDescriptor dp = spec.decisionPoint();
        if (dp == null || spec.factContractDigest() == null) {
            return;
        }
        @SuppressWarnings("unchecked")
        AuthzResourceGovernanceSpec<Object> rawSpec = (AuthzResourceGovernanceSpec<Object>) spec;
        availabilityProvider.registerResourceBindingIfAbsent(
                new AuthzResourceOperationAvailabilityProvider.ResourceAvailabilityPolicyBinding(
                        meta.resourceKey(),
                        dp,
                        spec.factContractDigest(),
                        spec.dualScopeDelegationSpec(),
                        spec.operationModifiedAttributes(),
                        () -> buildCallerAvailabilityContext(rawSpec),
                        rawSpec::extractSnapshotTargetFacts,
                        id -> safeFindStateSnapshot(service, rawSpec, id),
                        (ctx, snap) -> {
                            AuthzCallerContext callerCtx = callerContextProvider.currentCallerContext();
                            if (callerCtx.callerMatchesOrigin() != null) {
                                return callerCtx.callerMatchesOrigin();
                            }
                            return rawSpec.isCallerOriginForSnapshot(snap, callerCtx);
                        },
                        (ctx, snap) -> {
                            AuthzCallerContext callerCtx = callerContextProvider.currentCallerContext();
                            if (callerCtx.callerMatchesDestination() != null) {
                                return callerCtx.callerMatchesDestination();
                            }
                            return rawSpec.isCallerDestinationForSnapshot(snap, callerCtx);
                        },
                        spec.actionDecisionPoints(),
                        spec.surfaceDecisionPoints()
                )
        );
    }

    /** Synchronizes registry governance and semantic catalog lineage for an interceptor-governed {@code service}. */
    public void synchronizeCatalogAndRegistryIfSupported(
            BaseResourceQueryService<?, ?, ?> service,
            RuntimeDecisionPointRegistry registry,
            SemanticDecisionPointCatalogService catalogService
    ) {
        if (isExplicitlyGovernedService(service)) {
            return;
        }
        ResolvedGovernanceMetadata meta = resolveMetadataIfGoverned(service, false);
        if (meta == null || meta.spec() == null || meta.spec().decisionPoint() == null) {
            return;
        }
        AuthzResourceGovernanceSpec<?> spec = meta.spec();
        List<FieldLineageCatalogEntry> lineageEntries = serviceSupport.dtoIntrospector().deriveFieldLineageCatalogEntries(
                meta.resourceKey(),
                meta.responseDtoClass(),
                meta.createDtoClass(),
                meta.updateDtoClass()
        );
        if (registry != null) {
            String primaryKey = spec.decisionPoint().identity().pointKey();
            registry.enrichRegisteredPointGovernance(
                    primaryKey,
                    spec.dualScopeDelegationSpec(),
                    spec.mandatoryScopeAnchorAttributeIds(),
                    lineageEntries
            );
            for (DecisionPointDescriptor actionDp : spec.actionDecisionPoints().values()) {
                registry.enrichRegisteredPointGovernance(
                        actionDp.identity().pointKey(),
                        spec.dualScopeDelegationSpec(),
                        spec.mandatoryScopeAnchorAttributeIds(),
                        lineageEntries
                );
            }
            for (DecisionPointDescriptor surfaceDp : spec.surfaceDecisionPoints().values()) {
                registry.enrichRegisteredPointGovernance(
                        surfaceDp.identity().pointKey(),
                        spec.dualScopeDelegationSpec(),
                        spec.mandatoryScopeAnchorAttributeIds(),
                        lineageEntries
                );
            }
        }
        if (catalogService != null) {
            catalogService.enrichFieldLineageForPointKey(
                    spec.decisionPoint().identity().pointKey(),
                    lineageEntries
            );
            for (DecisionPointDescriptor actionDp : spec.actionDecisionPoints().values()) {
                catalogService.enrichFieldLineageForPointKey(actionDp.identity().pointKey(), lineageEntries);
            }
            for (DecisionPointDescriptor surfaceDp : spec.surfaceDecisionPoints().values()) {
                catalogService.enrichFieldLineageForPointKey(surfaceDp.identity().pointKey(), lineageEntries);
            }
        }
    }

    @Override
    public int getOrder() {
        return DEFAULT_ORDER;
    }

    @Override
    @SuppressWarnings("unchecked")
    public <E> ResourceFilterAccessScope<E> customizeFilterAccessScope(
            BaseResourceQueryService<?, ?, ?> service,
            ResourceFilterAccessScope<E> baseScope
    ) {
        if (isExplicitlyGovernedService(service)) {
            return baseScope;
        }
        ResolvedGovernanceMetadata meta = resolveMetadataIfGoverned(service, true);
        if (meta == null) {
            return baseScope;
        }
        AuthzResourceGovernanceSpec<E> spec = (AuthzResourceGovernanceSpec<E>) meta.spec();
        AuthzCallerContext callerCtx = callerContextProvider.currentCallerContext();
        Map<String, Object> subjectFacts = callerCtx.subjectAndEnvironmentFacts();
        Map<String, FactResolutionStatus> statuses = resolveFactStatuses(callerCtx, subjectFacts);

        ensureTransactionCleanupRegistered(service);
        ResourceFilterAccessScope<E> authzScope = serviceSupport.authorizeAndResolveAccessScope(
                spec.decisionPoint(),
                spec.factContractDigest(),
                callerCtx.incomingHeaderNames(),
                callerCtx.incomingHeaders(),
                callerCtx.tenantId(),
                subjectFacts,
                statuses,
                callerCtx.requestedQueryFieldUses(),
                meta.responseContract().baselineFieldUseDirectives(),
                spec.jpaDataScopeAdapter(),
                spec.buildHardScopeJpql(callerCtx),
                spec.buildHardScopeParams(callerCtx),
                spec.criteriaTranslator(),
                spec.buildHardScope(callerCtx),
                service
        );
        return combineAccessScopes(baseScope, authzScope);
    }

    @Override
    @SuppressWarnings("unchecked")
    public <E> void verifyEntityAccess(
            BaseResourceQueryService<?, ?, ?> service,
            E entity,
            AccessMode mode
    ) {
        E unwrapped = AuthzEntityUnproxySupport.unproxy(entity);
        if (unwrapped == null || isExplicitlyGovernedService(service)) {
            return;
        }
        ResolvedGovernanceMetadata meta = resolveMetadataIfGoverned(service, true);
        if (meta == null) {
            return;
        }
        AuthzResourceGovernanceSpec<E> spec = (AuthzResourceGovernanceSpec<E>) meta.spec();
        AuthzCallerContext callerCtx = callerContextProvider.currentCallerContext();

        AuthorizedQueryScopeContext activeQueryCtx = ensureActiveQueryContext(service, meta, callerCtx);
        DataScopePlan activePlan = activeQueryCtx != null ? activeQueryCtx.dataScopePlan() : null;
        spec.verifyEntityAccessAllowed(unwrapped, callerCtx, activePlan);

        if (mode == AccessMode.READ || mode == AccessMode.EXPORT) {
            evaluateTargetReadProjection(spec, unwrapped, callerCtx);
        }
        SnapshotCaptureSlot slot = snapshotCapture.get();
        if (slot != null && slot.expectedService == service) {
            slot.capturedEntity = unwrapped;
        }
        if (ResourceStateSnapshotScope.isOpen()) {
            Object entityId = readPropertyQuietly(unwrapped, "id");
            if (entityId != null) {
                Map<String, ResourceStateSnapshot> cache = scopedSnapshotCache.get();
                if (cache == null) {
                    cache = new LinkedHashMap<>();
                    scopedSnapshotCache.set(cache);
                }
                cache.put(scopedCacheKey(service, entityId), spec.toResourceStateSnapshot(unwrapped));
            }
        } else {
            scopedSnapshotCache.remove();
        }
    }

    @Override
    @SuppressWarnings("unchecked")
    public <E> void verifyEntitiesAccess(
            BaseResourceQueryService<?, ?, ?> service,
            Collection<E> entities,
            AccessMode mode
    ) {
        if (entities == null || entities.isEmpty() || isExplicitlyGovernedService(service)) {
            return;
        }
        ResolvedGovernanceMetadata meta = resolveMetadataIfGoverned(service, true);
        if (meta == null) {
            return;
        }
        AuthzResourceGovernanceSpec<E> spec = (AuthzResourceGovernanceSpec<E>) meta.spec();
        AuthzCallerContext callerCtx = callerContextProvider.currentCallerContext();
        AuthorizedQueryScopeContext activeQueryCtx = ensureActiveQueryContext(service, meta, callerCtx);
        DataScopePlan activePlan = activeQueryCtx != null ? activeQueryCtx.dataScopePlan() : null;
        boolean checkTargetPerEntity = (mode == AccessMode.READ || mode == AccessMode.EXPORT)
                && requiresRecordContextualTargetMasking(spec);
        for (E entity : entities) {
            E unwrapped = AuthzEntityUnproxySupport.unproxy(entity);
            if (unwrapped == null) {
                continue;
            }
            spec.verifyEntityAccessAllowed(unwrapped, callerCtx, activePlan);
            if (checkTargetPerEntity) {
                evaluateTargetReadProjection(spec, unwrapped, callerCtx);
            }
        }
    }

    @Override
    @SuppressWarnings("unchecked")
    public <E, R> R decorateResponse(
            BaseResourceQueryService<?, ?, ?> service,
            E entity,
            R dto,
            String surfaceOrOperation
    ) {
        if (dto == null || isExplicitlyGovernedService(service)) {
            return dto;
        }
        ResolvedGovernanceMetadata meta = resolveMetadataIfGoverned(service, true);
        if (meta == null) {
            return dto;
        }
        E unwrapped = AuthzEntityUnproxySupport.unproxy(entity);
        AuthzResourceGovernanceSpec<E> spec = (AuthzResourceGovernanceSpec<E>) meta.spec();
        AuthzCallerContext callerCtx = callerContextProvider.currentCallerContext();
        if (!serviceSupport.hasActiveMutationContext() && serviceSupport.currentQueryScopeContext() == null) {
            ensureActiveQueryContext(service, meta, callerCtx);
        }

        Class<R> dtoClass = (Class<R>) dto.getClass();
        Function<E, TargetReadProjectionEvaluation> contextualTargetEval = null;
        if (unwrapped != null && (requiresRecordContextualTargetMasking(spec)
                || isCustomSurfaceOperation(spec, surfaceOrOperation))) {
            contextualTargetEval = rawEntity -> evaluateTargetReadProjectionForOperation(
                    spec, AuthzEntityUnproxySupport.unproxy(rawEntity), callerCtx, surfaceOrOperation);
        }
        return serviceSupport.maskMapperResponseIfReady(
                unwrapped,
                dto,
                dtoClass,
                meta.responseContract().fieldSchemas(),
                contextualTargetEval
        );
    }

    @Override
    public <R> List<R> decorateResponses(
            BaseResourceQueryService<?, ?, ?> service,
            List<R> dtos,
            String surfaceOrOperation
    ) {
        if (isExplicitlyGovernedService(service)) {
            return dtos;
        }
        ResolvedGovernanceMetadata meta = resolveMetadataIfGoverned(service, true);
        if (meta == null) {
            return dtos;
        }
        if (!TransactionSynchronizationManager.isSynchronizationActive()) {
            serviceSupport.completeBatchEnrichResponses(service);
        }
        return dtos;
    }

    @Override
    public List<CollectionExportField> filterExportFields(
            BaseResourceQueryService<?, ?, ?> service,
            List<CollectionExportField> fields
    ) {
        if (isExplicitlyGovernedService(service)) {
            return fields;
        }
        ResolvedGovernanceMetadata meta = resolveMetadataIfGoverned(service, true);
        if (meta == null) {
            return fields;
        }
        return AuthzGovernedCollectionExportExecutor.filterDiscoveryExportFields(fields, meta.responseContract());
    }

    @Override
    public void authorizeExport(
            BaseResourceQueryService<?, ?, ?> service,
            CollectionExportRequest<?> request
    ) {
        if (isExplicitlyGovernedService(service)) {
            return;
        }
        ResolvedGovernanceMetadata meta = resolveMetadataIfGoverned(service, true);
        if (meta == null) {
            return;
        }
        AuthzResourceGovernanceSpec<?> spec = meta.spec();
        AuthzCallerContext callerCtx = callerContextProvider.currentCallerContext();
        Map<FieldUseCategory, Set<String>> requestedUses = new LinkedHashMap<>();
        if (callerCtx.requestedQueryFieldUses() != null) {
            callerCtx.requestedQueryFieldUses().forEach((k, v) -> requestedUses.put(k, new LinkedHashSet<>(v)));
        }
        Map<FieldUseCategory, Set<String>> exportUses = serviceSupport.dtoIntrospector().extractExportQueryFieldUses(
                request,
                meta.responseContract(),
                spec
        );
        if (exportUses != null) {
            exportUses.forEach((k, v) -> requestedUses.computeIfAbsent(k, ignored -> new LinkedHashSet<>()).addAll(v));
        }
        Map<String, Object> subjectFacts = callerCtx.subjectAndEnvironmentFacts();
        serviceSupport.authorizeAndResolveAccessScope(
                spec.decisionPoint(),
                spec.factContractDigest(),
                callerCtx.incomingHeaderNames(),
                callerCtx.incomingHeaders(),
                callerCtx.tenantId(),
                subjectFacts,
                resolveFactStatuses(callerCtx, subjectFacts),
                requestedUses,
                meta.responseContract().baselineFieldUseDirectives(),
                spec.jpaDataScopeAdapter(),
                spec.buildHardScopeJpql(callerCtx),
                spec.buildHardScopeParams(callerCtx),
                spec.criteriaTranslator(),
                spec.buildHardScope(callerCtx),
                service
        );
        if (!TransactionSynchronizationManager.isSynchronizationActive()) {
            serviceSupport.completeBatchEnrichResponses(service);
        }
    }

    @Override
    public StatsFieldRegistry filterStatsRegistry(
            BaseResourceQueryService<?, ?, ?> service,
            StatsFieldRegistry registry
    ) {
        if (registry == null || registry.isEmpty() || isExplicitlyGovernedService(service)) {
            return registry;
        }
        ResolvedGovernanceMetadata meta = resolveMetadataIfGoverned(service, false);
        if (meta == null) {
            return registry;
        }
        return new AuthzGovernedStatsQueryExecutor(
                NO_OP_STATS_EXECUTOR,
                serviceSupport,
                meta.responseContract(),
                meta.spec()
        ).filterStatsFieldRegistry(registry);
    }

    @Override
    @SuppressWarnings("unchecked")
    public <E> void beforeMutation(
            BaseResourceQueryService<?, ?, ?> service,
            MutationContext mutationContext,
            E candidate,
            E previous
    ) {
        if (isExplicitlyGovernedService(service)) {
            return;
        }
        ResolvedGovernanceMetadata meta = resolveMetadataIfGoverned(service, true);
        if (meta == null) {
            return;
        }
        AuthzResourceGovernanceSpec<E> spec = (AuthzResourceGovernanceSpec<E>) meta.spec();
        AuthzCallerContext callerCtx = callerContextProvider.currentCallerContext();
        ensureTransactionCleanupRegistered(service);

        E unwrappedCandidate = AuthzEntityUnproxySupport.unproxy(candidate);
        E unwrappedPrevious = AuthzEntityUnproxySupport.unproxy(previous);
        MutationKind kind = mutationContext != null ? mutationContext.kind() : MutationKind.UPDATE;
        if (kind != MutationKind.DELETE) {
            spec.verifyWritableTarget(unwrappedCandidate, unwrappedPrevious, callerCtx);
        }

        E targetEntityForFacts = unwrappedPrevious != null ? unwrappedPrevious : unwrappedCandidate;
        Map<String, Object> mergedFacts = mergeSubjectAndEntityFacts(spec, callerCtx, targetEntityForFacts, unwrappedCandidate);
        Map<String, FactResolutionStatus> statuses =
                resolveFactStatuses(callerCtx, mergedFacts, spec, targetEntityForFacts);
        boolean callerOrigin = spec.isCallerOrigin(targetEntityForFacts, callerCtx);
        boolean callerDestination = spec.isCallerDestination(targetEntityForFacts, callerCtx);

        if (kind == MutationKind.DELETE) {
            serviceSupport.authorizeBeforeDelete(
                    spec.decisionPoint(),
                    spec.factContractDigest(),
                    spec.dualScopeDelegationSpec(),
                    callerOrigin,
                    callerDestination,
                    mergedFacts,
                    statuses,
                    service
            );
            return;
        }

        Object dto = mutationContext != null ? mutationContext.dto() : null;
        IntrospectedDtoGovernanceContract writeContract = resolveWriteContract(meta, dto);
        Object intentPayload = buildMutationIntentPayload(
                meta,
                writeContract,
                kind,
                mutationContext,
                unwrappedCandidate,
                unwrappedPrevious
        );
        String verb = kind == MutationKind.CREATE ? "POST" : "PATCH";
        serviceSupport.authorizeBeforeHydrationAndRules(
                spec.decisionPoint(),
                spec.factContractDigest(),
                verb,
                true,
                intentPayload,
                writeContract.wirePointerToAttributeIdMap(),
                spec.technicalConcurrencyPointers(),
                spec.mandatoryScopeAnchorAttributeIds(),
                spec.dualScopeDelegationSpec(),
                callerOrigin,
                callerDestination,
                mergedFacts,
                statuses,
                service
        );
    }

    @Override
    public <E> void afterMutationBeforeCommit(
            BaseResourceQueryService<?, ?, ?> service,
            MutationContext mutationContext,
            E persistedEntity
    ) {
        if (isExplicitlyGovernedService(service)) {
            return;
        }
        ResolvedGovernanceMetadata meta = resolveMetadataIfGoverned(service, true);
        if (meta == null) {
            return;
        }
        MutationKind kind = mutationContext != null ? mutationContext.kind() : MutationKind.UPDATE;
        if (kind == MutationKind.DELETE) {
            serviceSupport.completeAfterDeleteOutbox(service);
            return;
        }
        serviceSupport.markPostMutationReadyForOutboxAndMasking();
        if (!TransactionSynchronizationManager.isSynchronizationActive()) {
            // Leave frame ready for immediate toResourceRepresentation/decorateResponse on same thread;
            // non-disclosed direct mutations won't hang without TX beforeCommit.
        }
    }

    private AuthorizedQueryScopeContext ensureActiveQueryContext(
            BaseResourceQueryService<?, ?, ?> service,
            ResolvedGovernanceMetadata meta,
            AuthzCallerContext callerCtx
    ) {
        AuthorizedQueryScopeContext current = serviceSupport.currentQueryScopeContext();
        if (current != null) {
            return current;
        }
        ensureTransactionCleanupRegistered(service);
        @SuppressWarnings("unchecked")
        AuthzResourceGovernanceSpec<Object> spec = (AuthzResourceGovernanceSpec<Object>) meta.spec();
        Map<String, Object> subjectFacts = callerCtx.subjectAndEnvironmentFacts();
        serviceSupport.authorizeAndResolveAccessScope(
                spec.decisionPoint(),
                spec.factContractDigest(),
                callerCtx.incomingHeaderNames(),
                callerCtx.incomingHeaders(),
                callerCtx.tenantId(),
                subjectFacts,
                resolveFactStatuses(callerCtx, subjectFacts),
                callerCtx.requestedQueryFieldUses(),
                meta.responseContract().baselineFieldUseDirectives(),
                spec.jpaDataScopeAdapter(),
                spec.buildHardScopeJpql(callerCtx),
                spec.buildHardScopeParams(callerCtx),
                spec.criteriaTranslator(),
                spec.buildHardScope(callerCtx),
                service
        );
        return serviceSupport.currentQueryScopeContext();
    }

    private <E> TargetReadProjectionEvaluation evaluateTargetReadProjection(
            AuthzResourceGovernanceSpec<E> spec,
            E entity,
            AuthzCallerContext callerCtx
    ) {
        return evaluateTargetReadProjectionForOperation(spec, entity, callerCtx, null);
    }

    private <E> TargetReadProjectionEvaluation evaluateTargetReadProjectionForOperation(
            AuthzResourceGovernanceSpec<E> spec,
            E entity,
            AuthzCallerContext callerCtx,
            String surfaceOrOperation
    ) {
        DecisionPointDescriptor dp = spec.decisionPoint();
        String digest = spec.factContractDigest();
        if (surfaceOrOperation != null && !surfaceOrOperation.isBlank()) {
            DecisionPointDescriptor surfaceDp = spec.surfaceDecisionPoints().get(surfaceOrOperation);
            if (surfaceDp != null) {
                dp = surfaceDp;
                if (surfaceDp.factContractRef() != null && surfaceDp.factContractRef().factContractDigest() != null) {
                    digest = surfaceDp.factContractRef().factContractDigest();
                }
            }
        }
        Map<String, Object> mergedFacts = mergeSubjectAndEntityFacts(spec, callerCtx, entity, null);
        return serviceSupport.authorizeTargetEntityProjection(
                dp,
                digest,
                mergedFacts,
                resolveFactStatuses(callerCtx, mergedFacts, spec, entity)
        );
    }

    private static boolean isCustomSurfaceOperation(AuthzResourceGovernanceSpec<?> spec, String surfaceOrOperation) {
        return surfaceOrOperation != null && spec.surfaceDecisionPoints().containsKey(surfaceOrOperation);
    }

    private static boolean requiresRecordContextualTargetMasking(AuthzResourceGovernanceSpec<?> spec) {
        return spec.dualScopeDelegationSpec() != null || !spec.surfaceDecisionPoints().isEmpty();
    }

    private <E> Map<String, Object> mergeSubjectAndEntityFacts(
            AuthzResourceGovernanceSpec<E> spec,
            AuthzCallerContext callerCtx,
            E primaryEntity,
            E fallbackCandidate
    ) {
        Map<String, Object> merged = new LinkedHashMap<>(callerCtx.subjectAndEnvironmentFacts());
        if (fallbackCandidate != null) {
            merged.putAll(spec.extractEntityTargetFacts(fallbackCandidate));
        }
        if (primaryEntity != null) {
            merged.putAll(spec.extractEntityTargetFacts(primaryEntity));
        }
        return Map.copyOf(merged);
    }

    private static Map<String, FactResolutionStatus> resolveFactStatuses(
            AuthzCallerContext callerCtx,
            Map<String, Object> facts
    ) {
        return resolveFactStatuses(callerCtx, facts, null, null);
    }

    private static <E> Map<String, FactResolutionStatus> resolveFactStatuses(
            AuthzCallerContext callerCtx,
            Map<String, Object> facts,
            AuthzResourceGovernanceSpec<E> spec,
            E entity
    ) {
        return AuthzResourceGovernanceSpec.resolveFactStatuses(
                callerCtx != null ? callerCtx.factStatuses() : Map.of(),
                facts,
                spec,
                entity
        );
    }

    private IntrospectedDtoGovernanceContract resolveWriteContract(
            ResolvedGovernanceMetadata meta,
            Object dto
    ) {
        if (dto == null || dto instanceof Map<?, ?> || dto instanceof String) {
            return meta.responseContract();
        }
        return serviceSupport.dtoIntrospector().introspectWriteDto(
                dto.getClass(),
                meta.responseDtoClass(),
                meta.resourceKey()
        );
    }

    @SuppressWarnings("unchecked")
    private <E> Object buildMutationIntentPayload(
            ResolvedGovernanceMetadata meta,
            IntrospectedDtoGovernanceContract writeContract,
            MutationKind kind,
            MutationContext mutationContext,
            E candidate,
            E previous
    ) {
        Object dto = mutationContext != null ? mutationContext.dto() : null;
        Set<String> anchors = meta.spec().mandatoryScopeAnchorAttributeIds();
        Map<String, String> wireToAttr = writeContract.wirePointerToAttributeIdMap();
        List<String> modifiedFields = mutationContext != null && mutationContext.modifiedFields() != null
                ? mutationContext.modifiedFields()
                : List.of();
        boolean partialIntent = mutationContext != null && mutationContext.partialIntent();

        Map<String, Object> dtoMap = null;
        if (dto instanceof String str) {
            return str;
        }
        if (dto instanceof Map<?, ?> map) {
            dtoMap = (Map<String, Object>) map;
        } else if (dto != null) {
            dtoMap = writeIntentBeanMapper.convertValue(dto, Map.class);
        } else if (candidate != null) {
            dtoMap = readEntityReadableProperties(candidate, wireToAttr);
        } else {
            dtoMap = Map.of();
        }

        if (kind == MutationKind.CREATE || previous == null) {
            Map<String, Object> filtered = new LinkedHashMap<>();
            Set<String> presentAnchors = new LinkedHashSet<>();
            for (Map.Entry<String, Object> entry : dtoMap.entrySet()) {
                String key = entry.getKey();
                Object val = entry.getValue();
                String attrId = wireToAttr.get("/" + key);
                if (val != null || (attrId != null && anchors.contains(attrId))) {
                    filtered.put(key, val);
                    if (attrId != null && anchors.contains(attrId) && val != null) {
                        presentAnchors.add(attrId);
                    }
                }
            }
            for (String anchorAttrId : anchors) {
                if (!presentAnchors.contains(anchorAttrId)) {
                    String wireKey = findWireKeyForAttributeId(wireToAttr, anchorAttrId);
                    if (wireKey == null) {
                        throw new SecurityException("AUTHZ_SCOPE_ANCHOR_CLEAR_FORBIDDEN: Mandatory scope anchor '"
                                + anchorAttrId + "' is missing from create contract (CC06/P13/P14)");
                    }
                    filtered.put(wireKey, null);
                }
            }
            return filtered;
        }

        Map<String, Object> prevMap = objectMapper.convertValue(
                readEntityReadableProperties(previous, wireToAttr),
                Map.class
        );
        Map<String, Object> delta = new LinkedHashMap<>();
        if (partialIntent && !modifiedFields.isEmpty()) {
            Set<String> touchedSet = new LinkedHashSet<>(modifiedFields);
            for (String field : touchedSet) {
                Object val = dtoMap.get(field);
                String attrId = wireToAttr.get("/" + field);
                if (val != null || (attrId != null && anchors.contains(attrId))) {
                    delta.put(field, val);
                } else {
                    delta.put(field, null);
                }
            }
            return delta;
        }

        for (Map.Entry<String, Object> entry : dtoMap.entrySet()) {
            String key = entry.getKey();
            Object newVal = entry.getValue();
            String attrId = wireToAttr.get("/" + key);
            if (newVal == null) {
                if (attrId != null && anchors.contains(attrId)) {
                    delta.put(key, null);
                }
                continue;
            }
            Object oldVal = prevMap.get(key);
            if (!Objects.equals(newVal, oldVal)) {
                delta.put(key, newVal);
            }
        }
        return delta;
    }

    private static Map<String, Object> readEntityReadableProperties(
            Object entity,
            Map<String, String> wireToAttr
    ) {
        if (entity == null || wireToAttr == null || wireToAttr.isEmpty()) {
            return Map.of();
        }
        Map<String, Object> result = new LinkedHashMap<>();
        for (String pointer : wireToAttr.keySet()) {
            String wireName = pointer.startsWith("/") ? pointer.substring(1) : pointer;
            if (!wireName.isEmpty() && !wireName.contains("/")) {
                Object val = readPropertyQuietly(entity, wireName);
                if (val != null) {
                    result.put(wireName, val);
                }
            }
        }
        return result;
    }

    private static Object readPropertyQuietly(Object target, String propertyName) {
        Object unwrapped = AuthzEntityUnproxySupport.unproxy(target);
        if (unwrapped == null) {
            return null;
        }
        Class<?> type = ClassUtils.getUserClass(unwrapped);
        String cap = Character.toUpperCase(propertyName.charAt(0)) + propertyName.substring(1);
        for (String methodName : List.of("get" + cap, "is" + cap, propertyName)) {
            try {
                Method m = type.getMethod(methodName);
                if (m.getParameterCount() == 0) {
                    return m.invoke(unwrapped);
                }
            } catch (Exception ignored) {
                // fall back
            }
        }
        for (Class<?> curr = type; curr != null && curr != Object.class; curr = curr.getSuperclass()) {
            try {
                Field f = curr.getDeclaredField(propertyName);
                f.setAccessible(true);
                return f.get(unwrapped);
            } catch (Exception ignored) {
                // continue
            }
        }
        return null;
    }

    private static String findWireKeyForAttributeId(Map<String, String> wireToAttr, String attrId) {
        for (Map.Entry<String, String> entry : wireToAttr.entrySet()) {
            if (attrId.equals(entry.getValue())) {
                String pointer = entry.getKey();
                return pointer.startsWith("/") ? pointer.substring(1) : pointer;
            }
        }
        return null;
    }

    private AuthzResourceOperationAvailabilityProvider.CallerAvailabilityFactContext buildCallerAvailabilityContext(
            AuthzResourceGovernanceSpec<Object> spec
    ) {
        AuthzCallerContext callerCtx = callerContextProvider.currentCallerContext();
        boolean originMatch = callerCtx.callerMatchesOrigin() != null
                ? callerCtx.callerMatchesOrigin()
                : spec.isCallerOrigin(null, callerCtx);
        boolean destinationMatch = callerCtx.callerMatchesDestination() != null
                ? callerCtx.callerMatchesDestination()
                : spec.isCallerDestination(null, callerCtx);
        return AuthzResourceOperationAvailabilityProvider.CallerAvailabilityFactContext.fromGovernanceSpec(
                spec,
                callerCtx,
                originMatch,
                destinationMatch
        );
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    private Optional<ResourceStateSnapshot> safeFindStateSnapshot(
            BaseResourceQueryService<?, ?, ?> service,
            AuthzResourceGovernanceSpec<Object> rawSpec,
            Object id
    ) {
        if (id == null) {
            return Optional.empty();
        }
        Object typedId = coerceServiceId(service, id);
        if (typedId == null) {
            return Optional.empty();
        }
        if (!ResourceStateSnapshotScope.isOpen()) {
            scopedSnapshotCache.remove();
        }
        SnapshotCaptureSlot slot = new SnapshotCaptureSlot(service);
        snapshotCapture.set(slot);
        try {
            Optional<ResourceStateSnapshot> serviceSnap =
                    ((BaseResourceQueryService) service).findResourceStateSnapshot(typedId);
            if (slot.capturedEntity != null) {
                ResourceStateSnapshot specSnap = rawSpec.toResourceStateSnapshot(slot.capturedEntity);
                if (serviceSnap == null || serviceSnap.isEmpty()) {
                    return Optional.of(specSnap);
                }
                ResourceStateSnapshot custom = serviceSnap.get();
                Map<String, Object> mergedMeta = new LinkedHashMap<>(specSnap.metadata());
                mergedMeta.putAll(custom.metadata());
                String state = (custom.state() != null && !custom.state().isBlank())
                        ? custom.state()
                        : specSnap.state();
                return Optional.of(ResourceStateSnapshot.of(state, mergedMeta));
            }
            if (ResourceStateSnapshotScope.isOpen()) {
                Map<String, ResourceStateSnapshot> cache = scopedSnapshotCache.get();
                if (cache != null) {
                    ResourceStateSnapshot cached = cache.get(scopedCacheKey(service, typedId));
                    if (cached != null) {
                        if (serviceSnap == null || serviceSnap.isEmpty()) {
                            return Optional.of(cached);
                        }
                        ResourceStateSnapshot custom = serviceSnap.get();
                        Map<String, Object> mergedMeta = new LinkedHashMap<>(cached.metadata());
                        mergedMeta.putAll(custom.metadata());
                        String state = (custom.state() != null && !custom.state().isBlank())
                                ? custom.state()
                                : cached.state();
                        return Optional.of(ResourceStateSnapshot.of(state, mergedMeta));
                    }
                }
            }
            return serviceSnap == null ? Optional.empty() : serviceSnap;
        } catch (RuntimeException ex) {
            return Optional.empty();
        } finally {
            snapshotCapture.remove();
        }
    }

    private static String scopedCacheKey(BaseResourceQueryService<?, ?, ?> service, Object id) {
        return System.identityHashCode(service) + ":" + String.valueOf(id);
    }

    private static Object coerceServiceId(BaseResourceQueryService<?, ?, ?> service, Object rawId) {
        try {
            Class<?> idType = ResolvableType.forClass(AopUtils.getTargetClass(service))
                    .as(AbstractBaseQueryResourceService.class).getGeneric(2).resolve();
            if (idType == null || idType.isInstance(rawId)) {
                return rawId;
            }
            if (CompositeIdSupport.isCompositeIdType(idType)) {
                return CompositeIdSupport.decode(rawId.toString(), idType);
            }
            return DefaultConversionService.getSharedInstance().convert(rawId, idType);
        } catch (RuntimeException ex) {
            return null;
        }
    }

    private static <E> ResourceFilterAccessScope<E> combineAccessScopes(
            ResourceFilterAccessScope<E> baseScope,
            ResourceFilterAccessScope<E> authzScope
    ) {
        if (authzScope == null) {
            return baseScope;
        }
        if (authzScope.mode() == ResourceFilterAccessScope.Mode.DENIED) {
            return authzScope;
        }
        if (baseScope == null || baseScope.mode() == ResourceFilterAccessScope.Mode.UNRESTRICTED) {
            return authzScope;
        }
        if (baseScope.mode() == ResourceFilterAccessScope.Mode.DENIED) {
            return baseScope;
        }
        if (authzScope.mode() == ResourceFilterAccessScope.Mode.UNRESTRICTED) {
            return baseScope;
        }
        Specification<E> combinedSpec = (root, query, cb) -> cb.and(
                baseScope.specification().toPredicate(root, query, cb),
                authzScope.specification().toPredicate(root, query, cb)
        );
        return ResourceFilterAccessScope.restricted(combinedSpec);
    }

    private void ensureTransactionCleanupRegistered(BaseResourceQueryService<?, ?, ?> service) {
        if (!TransactionSynchronizationManager.isSynchronizationActive()) {
            return;
        }
        Object key = new TxSyncKey(this, service);
        if (TransactionSynchronizationManager.hasResource(key)) {
            return;
        }
        TransactionSynchronizationManager.bindResource(key, Boolean.TRUE);
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override
            public void beforeCommit(boolean readOnly) {
                if (!readOnly && serviceSupport.hasActiveMutationContext()) {
                    serviceSupport.completePendingMutationOutboxIfNotDisclosed();
                }
            }

            @Override
            public void afterCompletion(int status) {
                TransactionSynchronizationManager.unbindResourceIfPossible(key);
                if (status != STATUS_COMMITTED) {
                    serviceSupport.clearMutationAndQueryContextsOnFailure(service);
                } else {
                    serviceSupport.completeBatchEnrichResponses(service);
                }
            }
        });
    }

    private record TxSyncKey(AuthzResourceGovernanceInterceptor owner, BaseResourceQueryService<?, ?, ?> service) {}

    private static boolean isExplicitlyGovernedService(BaseResourceQueryService<?, ?, ?> service) {
        return service == null
                || service instanceof AbstractAuthzGovernedResourceService<?, ?, ?, ?, ?, ?>
                || service instanceof AbstractAuthzGovernedReadOnlyResourceService<?, ?, ?, ?>;
    }

    private ResolvedGovernanceMetadata resolveMetadataIfGoverned(
            BaseResourceQueryService<?, ?, ?> service,
            boolean enforceMissingWhenConfigured
    ) {
        Class<?> targetClass = AopUtils.getTargetClass(service);
        ResolvedGovernanceMetadata cached = metadataCache.get(targetClass);
        if (cached != null) {
            return cached;
        }
        String resourceKey = safeResolveResourceKey(service);
        scanApiResourceControllersOnce();
        Class<?> controllerClass = resourceKey != null ? controllersByResourceKey.get(resourceKey) : null;

        Class<?>[] genericTypes = resolveServiceGenericTypes(targetClass);
        Class<?> entityClass = genericTypes[0];
        Class<?> responseDtoClass = genericTypes[1];
        Class<?> createDtoClass = genericTypes[2];
        Class<?> updateDtoClass = genericTypes[3];
        Class<?> filterDtoClass = genericTypes[4];

        AuthzResourceGovernanceSpec<?> spec = resourceKey != null ? specsByResourceKey.get(resourceKey) : null;
        if (spec == null && entityClass != null && hasAnyAuthzGovernanceAnnotation(
                targetClass, controllerClass, entityClass, responseDtoClass, createDtoClass, updateDtoClass)) {
            String effectiveResourceKey = resourceKey != null
                    ? resourceKey
                    : entityClass.getSimpleName().toLowerCase();
            String resolvedServiceKey = resolveServiceKeyForResource(effectiveResourceKey);
            @SuppressWarnings("unchecked")
            AuthzResourceGovernanceSpec<?> introspected = AuthzResourceGovernanceSpec.fromAnnotatedResource(
                    resolvedServiceKey,
                    effectiveResourceKey,
                    null,
                    (Class<Object>) entityClass,
                    responseDtoClass,
                    filterDtoClass,
                    createDtoClass,
                    updateDtoClass,
                    controllerClass,
                    targetClass
            );
            spec = introspected;
            if (resourceKey != null) {
                specsByResourceKey.putIfAbsent(resourceKey, spec);
            }
        }

        if (spec == null) {
            boolean hasRegisteredDecisionPoint = resourceKey != null
                    && decisionPointRegistry != null
                    && decisionPointRegistry.getDecisionPointsByKey().values().stream()
                            .anyMatch(dp -> resourceKey.equals(dp.identity().resourceKey()));
            if (enforceMissingWhenConfigured && (hasRegisteredDecisionPoint || failClosedOnUnconfiguredService)) {
                throw new SecurityException("AUTHZ_INTERCEPTOR_GOVERNANCE_MISSING: Resource '"
                        + (resourceKey != null ? resourceKey : targetClass.getSimpleName())
                        + "' requires an AuthzResourceGovernanceSpec bean or @AuthzTenantScope annotation (P01/P20)");
            }
            return null;
        }

        Class<?> contractDto = responseDtoClass != null ? responseDtoClass : entityClass;
        IntrospectedDtoGovernanceContract responseContract = contractDto != null
                ? serviceSupport.dtoIntrospector().introspect(contractDto, spec.resourceKey())
                : new IntrospectedDtoGovernanceContract(
                        spec.resourceKey(),
                        Object.class,
                        List.of(),
                        Set.of(),
                        Set.of(),
                        List.of(),
                        Map.of()
                );

        ResolvedGovernanceMetadata resolved = new ResolvedGovernanceMetadata(
                spec.resourceKey(),
                targetClass,
                entityClass,
                responseDtoClass,
                createDtoClass,
                updateDtoClass,
                controllerClass,
                spec,
                responseContract
        );
        metadataCache.putIfAbsent(targetClass, resolved);
        return resolved;
    }

    private void scanApiResourceControllersOnce() {
        if (controllerBeansScanned || applicationContext == null) {
            return;
        }
        synchronized (this) {
            if (controllerBeansScanned) {
                return;
            }
            try {
                Map<String, Object> beans = applicationContext.getBeansWithAnnotation(ApiResource.class);
                for (Object bean : beans.values()) {
                    if (bean == null) {
                        continue;
                    }
                    Class<?> controllerClass = AopUtils.getTargetClass(bean);
                    ApiResource apiResource = AnnotatedElementUtils.findMergedAnnotation(controllerClass, ApiResource.class);
                    if (apiResource != null && apiResource.resourceKey() != null && !apiResource.resourceKey().isBlank()) {
                        controllersByResourceKey.putIfAbsent(apiResource.resourceKey().trim(), controllerClass);
                    }
                }
            } catch (RuntimeException ignored) {
                // Lazy scan tolerant during early startup phases.
            } finally {
                controllerBeansScanned = true;
            }
        }
    }

    private static boolean hasAnyAuthzGovernanceAnnotation(Class<?>... classes) {
        for (Class<?> candidate : classes) {
            if (candidate == null) {
                continue;
            }
            if (AnnotatedElementUtils.hasAnnotation(candidate, AuthzTenantScope.class)
                    || AnnotatedElementUtils.hasAnnotation(candidate, AuthzCustodyPartition.class)
                    || AnnotatedElementUtils.hasAnnotation(candidate, AuthzScopeAnchor.class)
                    || AnnotatedElementUtils.hasAnnotation(candidate, AuthzMask.class)
                    || AnnotatedElementUtils.hasAnnotation(candidate, AuthzMasks.class)
                    || AnnotatedElementUtils.hasAnnotation(candidate, AuthzActionRule.class)) {
                return true;
            }
            for (Field f : candidate.getDeclaredFields()) {
                if (AnnotatedElementUtils.hasAnnotation(f, AuthzTenantScope.class)
                        || AnnotatedElementUtils.hasAnnotation(f, AuthzCustodyPartition.class)
                        || AnnotatedElementUtils.hasAnnotation(f, AuthzScopeAnchor.class)
                        || AnnotatedElementUtils.hasAnnotation(f, AuthzMask.class)
                        || AnnotatedElementUtils.hasAnnotation(f, AuthzMasks.class)) {
                    return true;
                }
            }
            for (Method m : candidate.getDeclaredMethods()) {
                if (AnnotatedElementUtils.hasAnnotation(m, AuthzTenantScope.class)
                        || AnnotatedElementUtils.hasAnnotation(m, AuthzActionRule.class)
                        || AnnotatedElementUtils.hasAnnotation(m, AuthzScopeAnchor.class)
                        || AnnotatedElementUtils.hasAnnotation(m, AuthzMask.class)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static String safeResolveResourceKey(BaseResourceQueryService<?, ?, ?> service) {
        try {
            return service.getResourceKey();
        } catch (RuntimeException ex) {
            return null;
        }
    }

    private String resolveServiceKeyForResource(String resourceKey) {
        if (decisionPointRegistry != null && resourceKey != null) {
            var matched = decisionPointRegistry.getDecisionPointsByKey().values().stream()
                    .filter(dp -> resourceKey.equals(dp.identity().resourceKey()))
                    .findFirst();
            if (matched.isPresent() && matched.get().identity().serviceKey() != null
                    && !matched.get().identity().serviceKey().isBlank()) {
                return matched.get().identity().serviceKey();
            }
        }
        if (applicationContext != null) {
            String appName = applicationContext.getEnvironment().getProperty("spring.application.name");
            if (appName != null && !appName.isBlank()) {
                return appName.trim();
            }
        }
        return "praxis-host";
    }

    private static Class<?>[] resolveServiceGenericTypes(Class<?> targetClass) {
        Class<?> entityClass = null;
        Class<?> responseDto = null;
        Class<?> createDto = null;
        Class<?> updateDto = null;
        Class<?> filterDto = null;
        ResolvableType mutableType = ResolvableType.forClass(targetClass).as(AbstractBaseResourceService.class);
        if (mutableType != ResolvableType.NONE) {
            entityClass = mutableType.getGeneric(0).resolve();
            responseDto = mutableType.getGeneric(1).resolve();
            filterDto = mutableType.getGeneric(3).resolve();
            createDto = mutableType.getGeneric(4).resolve();
            updateDto = mutableType.getGeneric(5).resolve();
        } else {
            ResolvableType queryType = ResolvableType.forClass(targetClass).as(AbstractBaseQueryResourceService.class);
            if (queryType != ResolvableType.NONE) {
                entityClass = queryType.getGeneric(0).resolve();
                responseDto = queryType.getGeneric(1).resolve();
                filterDto = queryType.getGeneric(3).resolve();
            } else {
                ResolvableType ifaceQuery = ResolvableType.forClass(targetClass).as(BaseResourceQueryService.class);
                if (ifaceQuery != ResolvableType.NONE) {
                    responseDto = ifaceQuery.getGeneric(0).resolve();
                    filterDto = ifaceQuery.getGeneric(2).resolve();
                }
                ResolvableType ifaceCmd = ResolvableType.forClass(targetClass).as(BaseResourceCommandService.class);
                if (ifaceCmd != ResolvableType.NONE) {
                    createDto = ifaceCmd.getGeneric(2).resolve();
                    updateDto = ifaceCmd.getGeneric(3).resolve();
                }
            }
        }
        return new Class<?>[] {entityClass, responseDto, createDto, updateDto, filterDto};
    }
}
