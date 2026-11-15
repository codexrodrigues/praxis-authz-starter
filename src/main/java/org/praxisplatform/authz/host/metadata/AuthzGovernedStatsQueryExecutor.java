package org.praxisplatform.authz.host.metadata;

import jakarta.persistence.EntityManager;
import java.util.ArrayList;
import java.util.Collection;
import java.util.EnumMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import org.praxisplatform.authz.contracts.decisionpoint.FieldUseCategory;
import org.praxisplatform.authz.contracts.envelope.FieldUseEffectDirective;
import org.praxisplatform.authz.enforcement.fielduse.FieldUseQueryGuard;
import org.praxisplatform.authz.enforcement.fielduse.FieldUseViolationException;
import org.praxisplatform.authz.enforcement.masking.DtoFieldSchemaMetadata;
import org.praxisplatform.authz.host.metadata.MetadataDtoGovernanceIntrospector.IntrospectedDtoGovernanceContract;
import org.praxisplatform.authz.seams.MetadataResourceAuthorizationSeam.AuthorizedQueryScopeContext;
import org.praxisplatform.uischema.stats.StatsFieldDescriptor;
import org.praxisplatform.uischema.stats.StatsFieldRegistry;
import org.praxisplatform.uischema.stats.StatsMetric;
import org.praxisplatform.uischema.stats.dto.ComparisonPeriodWindow;
import org.praxisplatform.uischema.stats.dto.DistributionStatsRequest;
import org.praxisplatform.uischema.stats.dto.DistributionStatsResponse;
import org.praxisplatform.uischema.stats.dto.GroupByStatsRequest;
import org.praxisplatform.uischema.stats.dto.GroupByStatsResponse;
import org.praxisplatform.uischema.stats.dto.TimeSeriesStatsRequest;
import org.praxisplatform.uischema.stats.dto.TimeSeriesStatsResponse;
import org.praxisplatform.uischema.stats.service.ResolvedStatsDimension;
import org.praxisplatform.uischema.stats.service.ResolvedStatsMetric;
import org.praxisplatform.uischema.stats.service.StatsQueryExecutor;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/**
 * Governed implementation of {@code praxis-metadata-starter}'s {@link StatsQueryExecutor}
 * bridging {@code AbstractBaseQueryResourceService.groupByStats(...)},
 * {@code timeSeriesStats(...)}, {@code distributionStats(...)}, and
 * {@code comparisonStats(...)} to the 15-step authorization pipeline
 * ({@code P05}, {@code P08}, {@code P10}, {@code P14}, {@code P46}, {@code P50}).
 *
 * <p>Enforces the following enterprise invariants across all analytical endpoints:</p>
 * <ol>
 *   <li><b>Pre-SQL {@code FIELD_USE} Enforcement ({@code GROUP} and {@code AGGREGATE}):</b>
 *       Before delegating to the underlying {@link StatsQueryExecutor} (e.g.,
 *       {@code JpaStatsQueryExecutor}), inspects every requested dimension
 *       ({@link StatsFieldDescriptor#field()}, {@link StatsFieldDescriptor#keyPropertyPath()},
 *       {@link StatsFieldDescriptor#labelPropertyPath()}) for {@link FieldUseCategory#GROUP}
 *       and every requested metric field ({@link ResolvedStatsMetric#descriptor()}) for
 *       {@link FieldUseCategory#AGGREGATE}. If static {@code @DomainGovernance} directives
 *       (such as {@code LGPD_SENSITIVE_DATA} or {@code analyticsEligible = false}) or dynamic
 *       OPA {@code FIELD_USE} / {@code valueDeniedAttributeIds} forbid grouping or aggregating
 *       that attribute, throws {@link FieldUseViolationException} ({@code 403}) before any SQL
 *       {@code GROUP BY} or aggregation query is executed;</li>
 *   <li><b>Scoped Analytical Cohort ({@code P05}, {@code P14}):</b> Preserves the composed
 *       {@link Specification} ({@code hardScope AND policyDataScope AND requestFilter}) resolved
 *       by {@code AbstractBaseQueryResourceService.resolveResourceFilterQuery(...)};</li>
 *   <li><b>Discovery-Time {@link StatsFieldRegistry} Filtering ({@code P10}, {@code P46}):</b>
 *       Provides {@link #filterStatsFieldRegistry(StatsFieldRegistry)} so resources can strip or
 *       restrict non-analytics-eligible attributes from {@code /schemas/filtered} and
 *       {@code /capabilities} while retaining runtime fail-closed enforcement;</li>
 *   <li><b>Transaction-Aware {@code ThreadLocal} Cleanup:</b> Registers a
 *       {@link TransactionSynchronization} when inside a Spring {@code @Transactional(readOnly = true)}
 *       stats method (allowing {@code comparisonStats} to execute both {@code current} and
 *       {@code previous} period queries under the same {@link AuthorizedQueryScopeContext}) and
 *       deterministically clears {@code activeQueryContext} on transaction completion (or
 *       immediately in {@code finally} when invoked outside a transaction).</li>
 * </ol>
 */
public final class AuthzGovernedStatsQueryExecutor implements StatsQueryExecutor {

    private static final String TX_CLEANUP_RESOURCE_KEY =
            AuthzGovernedStatsQueryExecutor.class.getName() + ".TX_CLEANUP_REGISTERED";

    private final StatsQueryExecutor delegate;
    private final AuthzGovernedResourceServiceSupport serviceSupport;
    private final IntrospectedDtoGovernanceContract governanceContract;
    private final AuthzResourceGovernanceSpec<?> governanceSpec;
    private final FieldUseQueryGuard fieldUseQueryGuard;

    public AuthzGovernedStatsQueryExecutor(
            StatsQueryExecutor delegate,
            AuthzGovernedResourceServiceSupport serviceSupport,
            IntrospectedDtoGovernanceContract governanceContract
    ) {
        this(delegate, serviceSupport, governanceContract, null);
    }

    public AuthzGovernedStatsQueryExecutor(
            StatsQueryExecutor delegate,
            AuthzGovernedResourceServiceSupport serviceSupport,
            IntrospectedDtoGovernanceContract governanceContract,
            AuthzResourceGovernanceSpec<?> governanceSpec
    ) {
        this.delegate = Objects.requireNonNull(delegate, "delegate is required");
        this.serviceSupport = Objects.requireNonNull(serviceSupport, "serviceSupport is required");
        this.governanceContract = Objects.requireNonNull(governanceContract, "governanceContract is required");
        this.governanceSpec = governanceSpec;
        this.fieldUseQueryGuard = new FieldUseQueryGuard();
    }

    @Override
    public <E> GroupByStatsResponse executeGroupBy(
            EntityManager entityManager,
            Class<E> entityClass,
            Specification<E> specification,
            StatsFieldDescriptor groupDescriptor,
            List<ResolvedStatsMetric> resolvedMetrics,
            GroupByStatsRequest<?> request,
            int maxBuckets
    ) {
        registerOrScheduleContextCleanup();
        try {
            enforceStatsFieldUses(
                    groupDescriptor == null ? List.of() : List.of(groupDescriptor),
                    resolvedMetrics,
                    request == null ? null : request.periodField(),
                    request == null ? null : request.filter()
            );
            return delegate.executeGroupBy(
                    entityManager,
                    entityClass,
                    specification,
                    groupDescriptor,
                    resolvedMetrics,
                    request,
                    maxBuckets
            );
        } finally {
            clearIfNoTransactionSynchronization();
        }
    }

    @Override
    public <E> GroupByStatsResponse executeGroupBy(
            EntityManager entityManager,
            Class<E> entityClass,
            Specification<E> specification,
            List<ResolvedStatsDimension> dimensions,
            List<ResolvedStatsMetric> resolvedMetrics,
            GroupByStatsRequest<?> request,
            ComparisonPeriodWindow window,
            int maxBuckets,
            int maxCells
    ) {
        registerOrScheduleContextCleanup();
        try {
            List<StatsFieldDescriptor> dimensionDescriptors = new ArrayList<>();
            if (dimensions != null) {
                for (ResolvedStatsDimension dim : dimensions) {
                    if (dim != null && dim.descriptor() != null) {
                        dimensionDescriptors.add(dim.descriptor());
                    }
                }
            }
            enforceStatsFieldUses(
                    dimensionDescriptors,
                    resolvedMetrics,
                    request == null ? null : request.periodField(),
                    request == null ? null : request.filter()
            );
            return delegate.executeGroupBy(
                    entityManager,
                    entityClass,
                    specification,
                    dimensions,
                    resolvedMetrics,
                    request,
                    window,
                    maxBuckets,
                    maxCells
            );
        } finally {
            clearIfNoTransactionSynchronization();
        }
    }

    @Override
    public <E> TimeSeriesStatsResponse executeTimeSeries(
            EntityManager entityManager,
            Class<E> entityClass,
            Specification<E> specification,
            StatsFieldDescriptor timeDescriptor,
            List<ResolvedStatsMetric> resolvedMetrics,
            TimeSeriesStatsRequest<?> request,
            int maxPoints
    ) {
        registerOrScheduleContextCleanup();
        try {
            enforceStatsFieldUses(
                    timeDescriptor == null ? List.of() : List.of(timeDescriptor),
                    resolvedMetrics,
                    null,
                    request == null ? null : request.filter()
            );
            return delegate.executeTimeSeries(
                    entityManager,
                    entityClass,
                    specification,
                    timeDescriptor,
                    resolvedMetrics,
                    request,
                    maxPoints
            );
        } finally {
            clearIfNoTransactionSynchronization();
        }
    }

    @Override
    public <E> DistributionStatsResponse executeDistribution(
            EntityManager entityManager,
            Class<E> entityClass,
            Specification<E> specification,
            StatsFieldDescriptor distributionDescriptor,
            StatsFieldDescriptor metricDescriptor,
            DistributionStatsRequest<?> request,
            int maxBuckets
    ) {
        registerOrScheduleContextCleanup();
        try {
            List<ResolvedStatsMetric> metrics = new ArrayList<>();
            if (metricDescriptor != null && request != null && request.metric() != null) {
                metrics.add(new ResolvedStatsMetric(request.metric(), metricDescriptor));
            }
            enforceStatsFieldUses(
                    distributionDescriptor == null ? List.of() : List.of(distributionDescriptor),
                    metrics,
                    null,
                    request == null ? null : request.filter()
            );
            return delegate.executeDistribution(
                    entityManager,
                    entityClass,
                    specification,
                    distributionDescriptor,
                    metricDescriptor,
                    request,
                    maxBuckets
            );
        } finally {
            clearIfNoTransactionSynchronization();
        }
    }

    /**
     * Filters a {@link StatsFieldRegistry} for capability/schema discovery ({@code P10}, {@code P46}),
     * removing or restricting descriptors whose {@link FieldUseCategory#GROUP} or
     * {@link FieldUseCategory#AGGREGATE} is statically denied by {@code @DomainGovernance}.
     */
    public StatsFieldRegistry filterStatsFieldRegistry(StatsFieldRegistry rawRegistry) {
        if (rawRegistry == null || rawRegistry.isEmpty()) {
            return StatsFieldRegistry.empty();
        }
        Set<String> groupDenied = collectStaticallyDeniedAttributes(FieldUseCategory.GROUP);
        Set<String> aggregateDenied = collectStaticallyDeniedAttributes(FieldUseCategory.AGGREGATE);

        List<StatsFieldDescriptor> allowedDescriptors = new ArrayList<>();
        for (StatsFieldDescriptor descriptor : rawRegistry.descriptors()) {
            if (descriptor == null) {
                continue;
            }
            Set<String> candidateAttrIds = resolveCandidateAttributeIds(descriptor);
            boolean isGroupBlocked = candidateAttrIds.stream().anyMatch(groupDenied::contains);
            boolean isAggregateBlocked = candidateAttrIds.stream().anyMatch(aggregateDenied::contains);

            boolean groupByEligible = descriptor.groupByEligible() && !isGroupBlocked;
            boolean timeSeriesEligible = descriptor.timeSeriesEligible() && !isGroupBlocked;
            boolean distributionTermsEligible = descriptor.distributionTermsEligible() && !isGroupBlocked;
            boolean distributionHistogramEligible = descriptor.distributionHistogramEligible() && !isGroupBlocked && !isAggregateBlocked;
            boolean metricFieldEligible = descriptor.metricFieldEligible() && !isAggregateBlocked;

            Set<StatsMetric> allowedMetrics = isAggregateBlocked
                    ? (isGroupBlocked ? Set.of() : descriptor.metrics().stream()
                            .filter(m -> m == StatsMetric.COUNT)
                            .collect(java.util.stream.Collectors.toUnmodifiableSet()))
                    : descriptor.metrics();

            if (!groupByEligible && !timeSeriesEligible && !distributionTermsEligible
                    && !distributionHistogramEligible && !metricFieldEligible) {
                continue;
            }
            allowedDescriptors.add(new StatsFieldDescriptor(
                    descriptor.field(),
                    descriptor.keyPropertyPath(),
                    descriptor.labelPropertyPath(),
                    allowedMetrics,
                    groupByEligible,
                    timeSeriesEligible,
                    distributionTermsEligible,
                    distributionHistogramEligible,
                    metricFieldEligible
            ));
        }
        return StatsFieldRegistry.of(allowedDescriptors);
    }

    private void enforceStatsFieldUses(
            Collection<StatsFieldDescriptor> groupDescriptors,
            Collection<ResolvedStatsMetric> resolvedMetrics,
            String explicitPeriodField,
            Object filterPayload
    ) {
        Set<String> requestedFilterAttributes = new LinkedHashSet<>();
        if (filterPayload != null) {
            Map<FieldUseCategory, Set<String>> extracted = serviceSupport.dtoIntrospector().extractQueryFieldUses(
                    filterPayload,
                    null,
                    governanceContract,
                    governanceSpec
            );
            Set<String> filterUses = extracted.get(FieldUseCategory.FILTER);
            if (filterUses != null) {
                for (String attr : filterUses) {
                    requestedFilterAttributes.addAll(resolveFieldIdentifierToAttributeIds(attr));
                }
            }
        }
        Set<String> requestedGroupAttributes = new LinkedHashSet<>();
        if (groupDescriptors != null) {
            for (StatsFieldDescriptor desc : groupDescriptors) {
                if (desc != null) {
                    requestedGroupAttributes.addAll(resolveCandidateAttributeIds(desc));
                }
            }
        }
        if (explicitPeriodField != null && !explicitPeriodField.isBlank()) {
            requestedGroupAttributes.addAll(resolveFieldIdentifierToAttributeIds(explicitPeriodField.trim()));
        }

        Set<String> requestedAggregateAttributes = new LinkedHashSet<>();
        if (resolvedMetrics != null) {
            for (ResolvedStatsMetric resolvedMetric : resolvedMetrics) {
                if (resolvedMetric == null) {
                    continue;
                }
                if (resolvedMetric.descriptor() != null) {
                    requestedAggregateAttributes.addAll(resolveCandidateAttributeIds(resolvedMetric.descriptor()));
                } else if (resolvedMetric.metric() != null
                        && resolvedMetric.metric().field() != null
                        && !resolvedMetric.metric().field().isBlank()) {
                    requestedAggregateAttributes.addAll(
                            resolveFieldIdentifierToAttributeIds(resolvedMetric.metric().field().trim())
                    );
                }
            }
        }

        Map<FieldUseCategory, Set<String>> requestedByCategory = new EnumMap<>(FieldUseCategory.class);
        if (!requestedFilterAttributes.isEmpty()) {
            requestedByCategory.put(FieldUseCategory.FILTER, requestedFilterAttributes);
        }
        if (!requestedGroupAttributes.isEmpty()) {
            requestedByCategory.put(FieldUseCategory.GROUP, requestedGroupAttributes);
        }
        if (!requestedAggregateAttributes.isEmpty()) {
            requestedByCategory.put(FieldUseCategory.AGGREGATE, requestedAggregateAttributes);
        }
        if (requestedByCategory.isEmpty()) {
            return;
        }

        List<FieldUseEffectDirective> effectiveDirectives = new ArrayList<>(governanceContract.baselineFieldUseDirectives());
        AuthorizedQueryScopeContext queryCtx = serviceSupport.currentQueryScopeContext();
        if (queryCtx != null && queryCtx.combinedFieldUseDirectives() != null) {
            effectiveDirectives.addAll(queryCtx.combinedFieldUseDirectives());
        }
        fieldUseQueryGuard.guardQueryFieldUses(
                requestedByCategory,
                effectiveDirectives
        );

        Set<String> denied = new LinkedHashSet<>(fieldUseQueryGuard.extractValueDeniedAttributeIds(effectiveDirectives));
        if (queryCtx != null && queryCtx.valueDeniedAttributeIds() != null) {
            denied.addAll(queryCtx.valueDeniedAttributeIds());
        }
        if (!denied.isEmpty()) {
            for (Map.Entry<FieldUseCategory, Set<String>> entry : requestedByCategory.entrySet()) {
                for (String attr : entry.getValue()) {
                    if (denied.contains(attr)) {
                        throw new FieldUseViolationException(
                                entry.getKey(),
                                Set.of(attr),
                                "Field use category " + entry.getKey() + " is denied for attribute: " + attr
                        );
                    }
                }
            }
        }
    }

    private Set<String> collectStaticallyDeniedAttributes(FieldUseCategory category) {
        Set<String> denied = new LinkedHashSet<>();
        for (FieldUseEffectDirective directive : governanceContract.baselineFieldUseDirectives()) {
            if (directive.category() == category
                    && directive.effect() == org.praxisplatform.authz.contracts.envelope.RuleEffect.DENY) {
                denied.add(directive.attributeId());
            }
        }
        return Set.copyOf(denied);
    }

    private Set<String> resolveCandidateAttributeIds(StatsFieldDescriptor descriptor) {
        Set<String> ids = new LinkedHashSet<>();
        if (descriptor.field() != null && !descriptor.field().isBlank()) {
            ids.addAll(resolveFieldIdentifierToAttributeIds(descriptor.field().trim()));
        }
        if (descriptor.keyPropertyPath() != null && !descriptor.keyPropertyPath().isBlank()) {
            ids.addAll(resolveFieldIdentifierToAttributeIds(descriptor.keyPropertyPath().trim()));
        }
        if (descriptor.labelPropertyPath() != null && !descriptor.labelPropertyPath().isBlank()) {
            ids.addAll(resolveFieldIdentifierToAttributeIds(descriptor.labelPropertyPath().trim()));
        }
        return ids;
    }

    private Set<String> resolveFieldIdentifierToAttributeIds(String fieldOrPath) {
        Set<String> resolved = new LinkedHashSet<>();
        String clean = fieldOrPath.startsWith("/") ? fieldOrPath.substring(1) : fieldOrPath;
        resolved.add(clean);
        if (governanceContract.wirePointerToAttributeIdMap() != null) {
            String mapped = governanceContract.wirePointerToAttributeIdMap().get("/" + clean);
            if (mapped != null) {
                resolved.add(mapped);
            }
        }
        if (governanceSpec != null && governanceSpec.fieldBindings() != null) {
            for (var binding : governanceSpec.fieldBindings()) {
                if (clean.equals(binding.nativeJpaPath())
                        || clean.equals(binding.fieldPath())
                        || ("resource." + clean).equals(binding.fieldPath())
                        || clean.equals(binding.attributeId())) {
                    resolved.add(binding.attributeId());
                    resolved.add(binding.fieldPath());
                }
            }
        }
        for (DtoFieldSchemaMetadata schema : governanceContract.fieldSchemas()) {
            if (resolved.contains(schema.wireFieldName()) || resolved.contains(schema.attributeId())) {
                resolved.add(schema.attributeId());
                resolved.add(schema.wireFieldName());
            }
        }
        return resolved;
    }

    private void registerOrScheduleContextCleanup() {
        if (TransactionSynchronizationManager.isSynchronizationActive()) {
            if (!TransactionSynchronizationManager.hasResource(TX_CLEANUP_RESOURCE_KEY)) {
                TransactionSynchronizationManager.bindResource(TX_CLEANUP_RESOURCE_KEY, Boolean.TRUE);
                TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                    @Override
                    public void afterCompletion(int status) {
                        if (TransactionSynchronizationManager.hasResource(TX_CLEANUP_RESOURCE_KEY)) {
                            TransactionSynchronizationManager.unbindResource(TX_CLEANUP_RESOURCE_KEY);
                        }
                        serviceSupport.clearTransientRequestContexts();
                    }
                });
            }
        }
    }

    private void clearIfNoTransactionSynchronization() {
        if (!TransactionSynchronizationManager.isSynchronizationActive()) {
            serviceSupport.clearTransientRequestContexts();
        }
    }
}
