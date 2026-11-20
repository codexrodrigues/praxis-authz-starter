package org.praxisplatform.authz.host.metadata;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.introspect.Annotated;
import com.fasterxml.jackson.databind.introspect.AnnotatedMember;
import com.fasterxml.jackson.databind.introspect.JacksonAnnotationIntrospector;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Function;
import java.util.function.Supplier;
import org.praxisplatform.authz.contracts.context.FactResolutionStatus;
import org.praxisplatform.authz.contracts.datascope.DataScopeOutcome;
import org.praxisplatform.authz.contracts.decisionpoint.DecisionPointDescriptor;
import org.praxisplatform.authz.contracts.decisionpoint.FieldUseCategory;
import org.praxisplatform.authz.contracts.envelope.FieldUseEffectDirective;
import org.praxisplatform.authz.contracts.envelope.MaskDirective;
import org.praxisplatform.authz.contracts.envelope.RuleEffect;
import org.praxisplatform.authz.contracts.policy.DualScopeDelegationSpec;
import org.praxisplatform.authz.enforcement.jpa.JpaDataScopeAdapter;
import org.praxisplatform.authz.enforcement.masking.DetachedDtoMaskingProcessor;
import org.praxisplatform.authz.enforcement.masking.DetachedDtoMaskingResult;
import org.praxisplatform.authz.enforcement.masking.DtoFieldSchemaMetadata;
import org.praxisplatform.authz.enforcement.writeintent.FieldWriteViolationException;
import org.praxisplatform.authz.host.metadata.MetadataDtoGovernanceIntrospector.IntrospectedDtoGovernanceContract;
import org.praxisplatform.authz.seams.MetadataResourceAuthorizationSeam;
import org.praxisplatform.authz.seams.MetadataResourceAuthorizationSeam.AuthorizedPreMutationContext;
import org.praxisplatform.authz.seams.MetadataResourceAuthorizationSeam.AuthorizedQueryScopeContext;
import org.praxisplatform.authz.seams.MetadataResourceAuthorizationSeam.TargetReadProjectionEvaluation;
import org.praxisplatform.uischema.bulk.BulkDomainResourceAdapter;
import org.praxisplatform.uischema.capability.ResourceStateSnapshotProvider;
import org.praxisplatform.uischema.command.ResourceCommandExecutionException;
import org.praxisplatform.uischema.command.ResourceCommandExecutionProvider;
import org.praxisplatform.uischema.command.ResourceCommandOutcome;
import org.praxisplatform.uischema.determination.ReactiveDeterminationDefinitionProvider;
import org.praxisplatform.uischema.exporting.CollectionExportExecutor;
import org.praxisplatform.uischema.mapper.base.ResourceMapper;
import org.praxisplatform.uischema.options.service.OptionSourceProvider;
import org.praxisplatform.uischema.options.service.OptionSourceQueryExecutor;
import org.praxisplatform.uischema.service.base.AbstractBaseResourceService;
import org.praxisplatform.uischema.service.base.ResourceFilterAccessScope;
import org.praxisplatform.uischema.stats.service.StatsQueryExecutor;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

/**
 * Canonical Spring/JPA lifecycle bridge connecting {@code praxis-metadata-starter}'s
 * {@code AbstractBaseQueryResourceService} and {@code AbstractBaseResourceService} hooks directly
 * to {@link MetadataResourceAuthorizationSeam} and {@link JpaCriteriaDataScopeTranslator}
 * ({@code CC03}, {@code CC06}, {@code CC07}, {@code CC08}, {@code R-11}, {@code P01..P22}).
 *
 * <p>Provides a thread-safe transaction/request-scoped context holder so that:</p>
 * <ul>
 *   <li>{@code resolveResourceFilterAccessScope()} evaluates OPA {@code SEARCH} (3-step {@code SameInstanceSearchRevisionGuard}),
 *       enforces {@code FieldUseQueryGuard} ({@code FILTER}/{@code SORT}/{@code GROUP}), composes the
 *       {@link ResourceFilterAccessScope} via {@link JpaCriteriaDataScopeTranslator}, and pins the
 *       {@link AuthorizedQueryScopeContext} for response masking;</li>
 *   <li>{@code beforeUpdate(...)} / {@code beforeCreate(...)} executes pre-hydration {@code FIELD_WRITE}
 *       and {@code DualScopeDelegationSpec} ({@code Cedente} vs {@code Cessionário}) strictly before
 *       {@code hydrate*} and {@code PraxisRulesEngine} ({@code R-11} / {@code STEP_11} before {@code STEP_12});</li>
 *   <li>{@code afterUpdate(...)} / {@code afterCreate(...)} fulfills {@code BEFORE_COMMIT_OUTBOX}
 *       obligations ({@code JdbcTransactionalAuditOutbox}) inside the same {@code @Transactional} boundary
 *       ({@code STEP_14}) and masks the detached {@code ResponseDTO} ({@code STEP_15}).</li>
 * </ul>
 */
public final class AuthzGovernedResourceServiceSupport {

    private static final StackWalker STACK_WALKER =
            StackWalker.getInstance(StackWalker.Option.RETAIN_CLASS_REFERENCE);

    private final MetadataResourceAuthorizationSeam authorizationSeam;
    private final DetachedDtoMaskingProcessor maskingProcessor;
    private final MetadataDtoGovernanceIntrospector dtoIntrospector;
    private final ObjectMapper objectMapper;
    private final ObjectMapper maskedProjectionMapper;

    private static final Object DEFAULT_OWNER = new Object();
    private static final Object TX_CLEANUP_KEY = new Object();

    private sealed interface AuthorizationFrame permits QueryFrame, MutationFrame {
        Object owner();
    }

    private record QueryFrame(Object owner, AuthorizedQueryScopeContext context) implements AuthorizationFrame {}

    private record MutationFrame(Object owner, AuthorizedPreMutationContext context, boolean readyForMasking)
            implements AuthorizationFrame {}

    private record ExportMaskFrame(List<MaskDirective> maskDirectives, Set<String> valueDeniedAttributeIds) {}

    /**
     * Reentrant call-stack checkpoint capturing authorization, export, and extracted-field-use
     * stacks so nested service invocations restore outer frames deterministically in {@code finally}
     * without wiping them.
     */
    public static final class FrameCheckpoint {
        private final List<AuthorizationFrame> frames;
        private final List<ExportMaskFrame> exportFrames;
        private final Map<FieldUseCategory, Set<String>> extractedFieldUses;

        private FrameCheckpoint(
                List<AuthorizationFrame> frames,
                List<ExportMaskFrame> exportFrames,
                Map<FieldUseCategory, Set<String>> extractedFieldUses
        ) {
            this.frames = frames;
            this.exportFrames = exportFrames;
            this.extractedFieldUses = extractedFieldUses;
        }

        public int frameDepth() {
            return frames.size();
        }

        public int exportDepth() {
            return exportFrames.size();
        }
    }

    private final ThreadLocal<Deque<AuthorizationFrame>> frameStack = ThreadLocal.withInitial(ArrayDeque::new);
    private final ThreadLocal<Deque<ExportMaskFrame>> exportFrameStack = ThreadLocal.withInitial(ArrayDeque::new);
    private final ThreadLocal<Map<Object, Deque<AuthorizedPreMutationContext>>> pendingDeleteContextsByOwner =
            ThreadLocal.withInitial(IdentityHashMap::new);
    private final ThreadLocal<Map<FieldUseCategory, Set<String>>> activeExtractedQueryFieldUses = new ThreadLocal<>();
    private final ThreadLocal<IntrospectedDtoGovernanceContract> currentThreadContract = new ThreadLocal<>();
    private volatile IntrospectedDtoGovernanceContract lastIntrospectedContract;

    /**
     * Creates a governed resource service support bridge.
     *
     * @param authorizationSeam canonical metadata resource authorization seam
     * @param maskingProcessor detached DTO masking processor
     */
    public AuthzGovernedResourceServiceSupport(
            MetadataResourceAuthorizationSeam authorizationSeam,
            DetachedDtoMaskingProcessor maskingProcessor
    ) {
        this(authorizationSeam, maskingProcessor, new MetadataDtoGovernanceIntrospector());
    }

    /**
     * Creates a governed resource service support bridge with an explicit {@link MetadataDtoGovernanceIntrospector}.
     *
     * @param authorizationSeam canonical metadata resource authorization seam
     * @param maskingProcessor detached DTO masking processor
     * @param dtoIntrospector metadata DTO governance introspector
     */
    public AuthzGovernedResourceServiceSupport(
            MetadataResourceAuthorizationSeam authorizationSeam,
            DetachedDtoMaskingProcessor maskingProcessor,
            MetadataDtoGovernanceIntrospector dtoIntrospector
    ) {
        this.authorizationSeam = Objects.requireNonNull(authorizationSeam, "authorizationSeam is required");
        this.maskingProcessor = Objects.requireNonNull(maskingProcessor, "maskingProcessor is required");
        this.dtoIntrospector = Objects.requireNonNull(dtoIntrospector, "dtoIntrospector is required");
        this.objectMapper = new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
                .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
        this.maskedProjectionMapper = createMaskedProjectionObjectMapper();
    }

    /**
     * Creates an {@link ObjectMapper} for internal re-hydration of sanitized detached projections
     * back into typed DTOs, treating {@code @JsonProperty(access = READ_ONLY)} as deserializable
     * so host read-only properties (e.g. {@code id}, {@code ativo}) are never wiped during masking.
     */
    public static ObjectMapper createMaskedProjectionObjectMapper() {
        return new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
                .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
                .setVisibility(PropertyAccessor.FIELD, JsonAutoDetect.Visibility.ANY)
                .setAnnotationIntrospector(new JacksonAnnotationIntrospector() {
                    @Override
                    public JsonProperty.Access findPropertyAccess(Annotated m) {
                        JsonProperty.Access access = super.findPropertyAccess(m);
                        return access == JsonProperty.Access.READ_ONLY ? JsonProperty.Access.AUTO : access;
                    }
                });
    }

    /**
     * Creates an {@link ObjectMapper} for converting already-deserialized inbound Java write DTO
     * beans into maps for {@code WriteIntent} extraction, excluding {@code READ_ONLY} default
     * field initializers that cannot be supplied by clients.
     */
    public static ObjectMapper createWriteIntentBeanObjectMapper() {
        return new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS)
                .disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
                .setAnnotationIntrospector(new JacksonAnnotationIntrospector() {
                    @Override
                    public boolean hasIgnoreMarker(AnnotatedMember m) {
                        return super.hasIgnoreMarker(m)
                                || super.findPropertyAccess(m) == JsonProperty.Access.READ_ONLY;
                    }
                });
    }

    /** Returns the {@link MetadataDtoGovernanceIntrospector} used to inspect DTO annotations. */
    public MetadataDtoGovernanceIntrospector dtoIntrospector() {
        return dtoIntrospector;
    }

    /**
     * Wraps a host {@link ResourceMapper} in an {@link AuthzMaskingResourceMapperDecorator} using
     * schema metadata automatically introspected from {@code responseType} ({@code P11}, {@code P12}, {@code P13}, {@code P40}).
     */
    public <E, R, C, U, ID> ResourceMapper<E, R, C, U, ID> wrapResourceMapper(
            ResourceMapper<E, R, C, U, ID> delegate,
            Class<R> responseType,
            String resourceKey
    ) {
        return wrapResourceMapper(delegate, responseType, resourceKey, null);
    }

    /**
     * Wraps a host {@link ResourceMapper} in an {@link AuthzMaskingResourceMapperDecorator} with an
     * optional per-record contextual {@code TARGET} evaluator ({@code P12}).
     */
    public <E, R, C, U, ID> ResourceMapper<E, R, C, U, ID> wrapResourceMapper(
            ResourceMapper<E, R, C, U, ID> delegate,
            Class<R> responseType,
            String resourceKey,
            Function<E, TargetReadProjectionEvaluation> targetEvalResolver
    ) {
        IntrospectedDtoGovernanceContract contract = dtoIntrospector.introspect(responseType, resourceKey);
        recordIntrospectedContract(contract);
        return new AuthzMaskingResourceMapperDecorator<>(
                delegate,
                this,
                responseType,
                contract.fieldSchemas(),
                targetEvalResolver
        );
    }

    /**
     * Wraps a host {@link CollectionExportExecutor} in an {@link AuthzGovernedCollectionExportExecutor}
     * using schema and governance metadata automatically introspected from {@code responseType} and
     * dynamically applying the per-request OPA {@link MaskDirective}s ({@code P10.2-R03}).
     */
    public CollectionExportExecutor wrapCollectionExportExecutor(
            CollectionExportExecutor delegate,
            Class<?> responseType,
            String resourceKey
    ) {
        IntrospectedDtoGovernanceContract contract = dtoIntrospector.introspect(responseType, resourceKey);
        recordIntrospectedContract(contract);
        return new AuthzGovernedCollectionExportExecutor(
                delegate,
                maskingProcessor,
                contract,
                this::currentExportMaskDirectives,
                this::currentExportValueDeniedAttributeIds
        );
    }

    /**
     * Creates an {@link AuthzResourceOperationAvailabilityProvider} backed by this bridge's
     * {@link MetadataResourceAuthorizationSeam} and an optional {@link ResourceStateSnapshotProvider}
     * fallback ({@code Fase P10.4}, {@code P10}, {@code P17}).
     *
     * @param snapshotProviderFallback optional snapshot provider fallback
     * @return new {@link AuthzResourceOperationAvailabilityProvider}
     */
    public AuthzResourceOperationAvailabilityProvider createAvailabilityProvider(
            ResourceStateSnapshotProvider snapshotProviderFallback
    ) {
        return new AuthzResourceOperationAvailabilityProvider(authorizationSeam, snapshotProviderFallback);
    }

    /**
     * Wraps a {@link BulkDomainResourceAdapter} created by
     * {@code AbstractBaseResourceService.bulkDomainAdapter(...)} into an
     * {@link AuthzGovernedBulkDomainResourceAdapter} ({@code Fase P10.5}, {@code P15}, {@code P18}, {@code P19}, {@code P34}).
     *
     * @param delegate underlying bulk domain resource adapter
     * @param <ID> resource identifier type
     * @param <F> filter DTO type
     * @return governed {@link AuthzGovernedBulkDomainResourceAdapter}
     */
    public <ID, F> AuthzGovernedBulkDomainResourceAdapter<ID, F> wrapBulkDomainResourceAdapter(
            BulkDomainResourceAdapter<ID, F> delegate
    ) {
        return new AuthzGovernedBulkDomainResourceAdapter<>(delegate, this, resolveIntrospectedContract(null));
    }

    /**
     * Wraps a {@link BulkDomainResourceAdapter} into an {@link AuthzGovernedBulkDomainResourceAdapter}
     * with governance metadata explicitly introspected from {@code responseType}
     * ({@code Fase P10.5}, {@code P10.6-R01}, {@code P11}, {@code P12}, {@code P15}, {@code P50}).
     */
    public <ID, F> AuthzGovernedBulkDomainResourceAdapter<ID, F> wrapBulkDomainResourceAdapter(
            BulkDomainResourceAdapter<ID, F> delegate,
            Class<?> responseType,
            String resourceKey
    ) {
        return wrapBulkDomainResourceAdapter(delegate, responseType, resourceKey, null);
    }

    /**
     * Wraps a {@link BulkDomainResourceAdapter} into an {@link AuthzGovernedBulkDomainResourceAdapter}
     * with governance metadata explicitly introspected from {@code responseType} and optional
     * {@link AuthzResourceGovernanceSpec} ({@code Fase P10.20-A}).
     */
    public <ID, F> AuthzGovernedBulkDomainResourceAdapter<ID, F> wrapBulkDomainResourceAdapter(
            BulkDomainResourceAdapter<ID, F> delegate,
            Class<?> responseType,
            String resourceKey,
            AuthzResourceGovernanceSpec<?> governanceSpec
    ) {
        IntrospectedDtoGovernanceContract contract = dtoIntrospector.introspect(responseType, resourceKey);
        recordIntrospectedContract(contract);
        return new AuthzGovernedBulkDomainResourceAdapter<>(delegate, this, contract, governanceSpec);
    }

    /**
     * Wraps a host {@link OptionSourceQueryExecutor} (such as {@code CompositeOptionSourceQueryExecutor}
     * or {@code JpaOptionSourceQueryExecutor}) into an {@link AuthzGovernedOptionSourceProvider}
     * using governance metadata automatically introspected from {@code responseType}
     * ({@code Fase P10.5}, {@code P05}, {@code P06}, {@code P07}, {@code P09}, {@code P12}, {@code P50}).
     *
     * @param delegate underlying option-source query executor
     * @param responseType annotated response/entity DTO class
     * @param resourceKey canonical resource key
     * @return governed {@link AuthzGovernedOptionSourceProvider}
     */
    public AuthzGovernedOptionSourceProvider wrapOptionSourceQueryExecutor(
            OptionSourceQueryExecutor delegate,
            Class<?> responseType,
            String resourceKey
    ) {
        return wrapOptionSourceQueryExecutor(delegate, responseType, resourceKey, null);
    }

    /**
     * Wraps a host {@link OptionSourceQueryExecutor} into an {@link AuthzGovernedOptionSourceProvider}
     * with governance metadata introspected from {@code responseType} and optional
     * {@link AuthzResourceGovernanceSpec} ({@code Fase P10.25-A}).
     */
    public AuthzGovernedOptionSourceProvider wrapOptionSourceQueryExecutor(
            OptionSourceQueryExecutor delegate,
            Class<?> responseType,
            String resourceKey,
            AuthzResourceGovernanceSpec<?> governanceSpec
    ) {
        IntrospectedDtoGovernanceContract contract = dtoIntrospector.introspect(responseType, resourceKey);
        recordIntrospectedContract(contract);
        return new AuthzGovernedOptionSourceProvider(delegate, this, maskingProcessor, contract, governanceSpec);
    }

    /**
     * Wraps a host {@link OptionSourceProvider} (such as {@code JpaOptionSourceProvider}) into an
     * {@link AuthzGovernedOptionSourceProvider} using governance metadata automatically introspected
     * from {@code responseType} ({@code Fase P10.5}, {@code P05}, {@code P06}, {@code P07}, {@code P09}, {@code P12}, {@code P50}).
     *
     * @param delegate underlying option-source provider
     * @param responseType annotated response/entity DTO class
     * @param resourceKey canonical resource key
     * @return governed {@link AuthzGovernedOptionSourceProvider}
     */
    public AuthzGovernedOptionSourceProvider wrapOptionSourceProvider(
            OptionSourceProvider delegate,
            Class<?> responseType,
            String resourceKey
    ) {
        return wrapOptionSourceProvider(delegate, responseType, resourceKey, null);
    }

    /**
     * Wraps a host {@link OptionSourceProvider} into an {@link AuthzGovernedOptionSourceProvider}
     * with governance metadata introspected from {@code responseType} and optional
     * {@link AuthzResourceGovernanceSpec} ({@code Fase P10.25-A}).
     */
    public AuthzGovernedOptionSourceProvider wrapOptionSourceProvider(
            OptionSourceProvider delegate,
            Class<?> responseType,
            String resourceKey,
            AuthzResourceGovernanceSpec<?> governanceSpec
    ) {
        IntrospectedDtoGovernanceContract contract = dtoIntrospector.introspect(responseType, resourceKey);
        recordIntrospectedContract(contract);
        return new AuthzGovernedOptionSourceProvider(delegate, this, maskingProcessor, contract, governanceSpec);
    }

    /**
     * Wraps a host {@link StatsQueryExecutor} (such as {@code JpaStatsQueryExecutor}) into an
     * {@link AuthzGovernedStatsQueryExecutor} using governance metadata automatically introspected
     * from {@code responseType} ({@code Fase P10.6}, {@code P05}, {@code P08}, {@code P10},
     * {@code P14}, {@code P46}).
     *
     * @param delegate underlying stats query executor
     * @param responseType annotated response/entity DTO class
     * @param resourceKey canonical resource key
     * @return governed {@link AuthzGovernedStatsQueryExecutor}
     */
    public AuthzGovernedStatsQueryExecutor wrapStatsQueryExecutor(
            StatsQueryExecutor delegate,
            Class<?> responseType,
            String resourceKey
    ) {
        return wrapStatsQueryExecutor(delegate, responseType, resourceKey, null);
    }

    /**
     * Wraps a host {@link StatsQueryExecutor} into an {@link AuthzGovernedStatsQueryExecutor}
     * with governance metadata introspected from {@code responseType} and optional
     * {@link AuthzResourceGovernanceSpec} ({@code Fase P10.20-A}).
     */
    public AuthzGovernedStatsQueryExecutor wrapStatsQueryExecutor(
            StatsQueryExecutor delegate,
            Class<?> responseType,
            String resourceKey,
            AuthzResourceGovernanceSpec<?> governanceSpec
    ) {
        IntrospectedDtoGovernanceContract contract = dtoIntrospector.introspect(responseType, resourceKey);
        recordIntrospectedContract(contract);
        return new AuthzGovernedStatsQueryExecutor(delegate, this, contract, governanceSpec);
    }

    /**
     * Wraps a host {@link ReactiveDeterminationDefinitionProvider} into an
     * {@link AuthzGovernedReactiveDeterminationProvider} using governance metadata automatically
     * introspected from {@code responseType} ({@code Fase P10.6}, {@code P05}, {@code P11},
     * {@code P12}, {@code P13}, {@code P14}, {@code P46}, {@code P47}, {@code P49}, {@code P50},
     * {@code P57}, {@code P62}).
     *
     * @param delegate underlying reactive determination definition provider
     * @param responseType annotated response/entity DTO class
     * @param resourceKey canonical resource key
     * @return governed {@link AuthzGovernedReactiveDeterminationProvider}
     */
    public AuthzGovernedReactiveDeterminationProvider wrapReactiveDeterminationProvider(
            ReactiveDeterminationDefinitionProvider delegate,
            Class<?> responseType,
            String resourceKey
    ) {
        IntrospectedDtoGovernanceContract contract = dtoIntrospector.introspect(responseType, resourceKey);
        recordIntrospectedContract(contract);
        return new AuthzGovernedReactiveDeterminationProvider(delegate, this, contract);
    }

    /**
     * Wraps a host {@link ResourceCommandExecutionProvider} so that any pre-mutation authorization
     * or dual-scope custody rejection ({@link FieldWriteViolationException} or {@link SecurityException})
     * raised at {@code STEP_11} (for example, when replaying a stale HATEOAS link after a policy or
     * custody change) is translated into a canonical {@link ResourceCommandExecutionException} with
     * {@link ResourceCommandOutcome#PERMISSION_DENIED} and sanitized evidence, while preserving
     * {@code ResourceVersionPreconditionException} ({@code 412}/{@code 428}) and
     * {@code PraxisRuleViolationException} ({@code 422}) ({@code Fase P10.4}, {@code P10}, {@code P17}).
     *
     * @param delegate underlying command execution provider
     * @return governed {@link ResourceCommandExecutionProvider}
     */
    public ResourceCommandExecutionProvider wrapCommandExecutionProvider(
            ResourceCommandExecutionProvider delegate
    ) {
        Objects.requireNonNull(delegate, "delegate is required");
        return request -> {
            FrameCheckpoint checkpoint = openFrameScope();
            try {
                return delegate.execute(request);
            } catch (FieldWriteViolationException ex) {
                throw new ResourceCommandExecutionException(
                        ResourceCommandOutcome.PERMISSION_DENIED,
                        ex.getMessage(),
                        Map.of(
                                "reasonCode", ex.getReasonCode(),
                                "forbiddenAttributeIds", ex.getForbiddenAttributeIds()
                        )
                );
            } catch (SecurityException ex) {
                throw new ResourceCommandExecutionException(
                        ResourceCommandOutcome.PERMISSION_DENIED,
                        ex.getMessage() != null ? ex.getMessage() : "Command execution denied by authorization policy.",
                        Map.of("reasonCode", "AUTHZ_COMMAND_SECURITY_DENIED")
                );
            } finally {
                restoreFrameScope(checkpoint);
            }
        };
    }

    /**
     * Returns {@code true} if an {@link AuthorizedQueryScopeContext} is currently bound to the
     * thread (for example, after {@code resolveResourceFilterAccessScope()} in {@code filter(...)},
     * {@code exportCollection(...)}, or the first row of {@code findAllById(...)}).
     *
     * @return {@code true} when a query authorization context is active
     */
    public FrameCheckpoint openFrameScope() {
        return new FrameCheckpoint(
                new ArrayList<>(frameStack.get()),
                new ArrayList<>(exportFrameStack.get()),
                activeExtractedQueryFieldUses.get()
        );
    }

    public void restoreFrameScope(FrameCheckpoint checkpoint) {
        if (checkpoint == null) {
            return;
        }
        Deque<AuthorizationFrame> frames = frameStack.get();
        frames.clear();
        frames.addAll(checkpoint.frames);
        if (frames.isEmpty()) {
            frameStack.remove();
        }

        Deque<ExportMaskFrame> exports = exportFrameStack.get();
        exports.clear();
        exports.addAll(checkpoint.exportFrames);
        if (exports.isEmpty()) {
            exportFrameStack.remove();
        }

        if (checkpoint.extractedFieldUses == null) {
            activeExtractedQueryFieldUses.remove();
        } else {
            activeExtractedQueryFieldUses.set(checkpoint.extractedFieldUses);
        }
    }

    public <T> T executeInReentrancyScope(Supplier<T> action) {
        Objects.requireNonNull(action, "action is required");
        FrameCheckpoint checkpoint = openFrameScope();
        try {
            return action.get();
        } finally {
            restoreFrameScope(checkpoint);
        }
    }

    public void executeInReentrancyScopeVoid(Runnable action) {
        Objects.requireNonNull(action, "action is required");
        FrameCheckpoint checkpoint = openFrameScope();
        try {
            action.run();
        } finally {
            restoreFrameScope(checkpoint);
        }
    }

    private void recordIntrospectedContract(IntrospectedDtoGovernanceContract contract) {
        if (contract != null) {
            this.currentThreadContract.set(contract);
            this.lastIntrospectedContract = contract;
        }
    }

    private IntrospectedDtoGovernanceContract resolveIntrospectedContract(
            IntrospectedDtoGovernanceContract explicitContract
    ) {
        if (explicitContract != null) {
            return explicitContract;
        }
        IntrospectedDtoGovernanceContract threadContract = this.currentThreadContract.get();
        return threadContract != null ? threadContract : this.lastIntrospectedContract;
    }

    private static Object normalizeOwner(Object owner) {
        return owner == null ? DEFAULT_OWNER : owner;
    }

    private QueryFrame currentQueryFrame() {
        for (AuthorizationFrame frame : frameStack.get()) {
            if (frame instanceof QueryFrame qf) {
                return qf;
            }
        }
        return null;
    }

    private MutationFrame currentMutationFrame() {
        for (AuthorizationFrame frame : frameStack.get()) {
            if (frame instanceof MutationFrame mf) {
                return mf;
            }
        }
        return null;
    }

    private void popTopFramesForOwner(Object owner) {
        Object normalized = normalizeOwner(owner);
        Deque<AuthorizationFrame> stack = frameStack.get();
        while (!stack.isEmpty() && stack.peekFirst().owner() == normalized) {
            stack.pollFirst();
        }
        if (stack.isEmpty()) {
            frameStack.remove();
        }
    }

    public boolean hasActiveQueryContext() {
        return currentQueryFrame() != null;
    }

    /**
     * Ensures that an {@link AuthorizedQueryScopeContext} is bound to the current thread before
     * checking row-level entity access in {@code assertEntityAccessAllowed(E)}.
     *
     * <p>When {@code filter(...)}, {@code exportCollection(...)}, or {@code findAllById(...)} calls
     * {@code assertEntitiesAccessAllowed(entities)} across {@code N} rows, or when
     * {@code findEntityForMutation(id)} invokes {@code assertEntityAccessAllowed(entity)} twice,
     * this method runs {@code scopeInitializer} (typically {@code this::resolveResourceFilterAccessScope})
     * at most once per operation instead of triggering {@code N+1} redundant OPA {@code SEARCH}
     * evaluations ({@code P10.4-R03}).</p>
     *
     * @param scopeInitializer callback that resolves and binds the query scope when none is active
     */
    public void ensureActiveQueryContext(Runnable scopeInitializer) {
        ensureActiveQueryContext(null, scopeInitializer);
    }

    /**
     * Owner-aware variant ensuring the top authorization frame on the stack is already a
     * {@link QueryFrame} owned by {@code owner} before triggering {@code scopeInitializer}
     * ({@code P10.4-R03}, reentrant {@code C-02}).
     */
    public void ensureActiveQueryContext(Object owner, Runnable scopeInitializer) {
        Objects.requireNonNull(scopeInitializer, "scopeInitializer is required");
        if (owner == null) {
            if (!hasActiveQueryContext()) {
                scopeInitializer.run();
            }
            return;
        }
        Object normalized = normalizeOwner(owner);
        AuthorizationFrame top = frameStack.get().peekFirst();
        if (!(top instanceof QueryFrame qf && qf.owner() == normalized)) {
            scopeInitializer.run();
        }
    }

    <T> T withQueryFrame(Object owner, Runnable initialize, Supplier<T> action) {
        AuthorizationFrame top = frameStack.get().peekFirst();
        if (top instanceof QueryFrame query && query.owner() == owner) {
            return action.get();
        }
        Supplier<T> initializeAndRun = () -> {
            initialize.run();
            return action.get();
        };
        if (top == null && TransactionSynchronizationManager.isSynchronizationActive()) {
            // Reuse the scope across pre-lock and post-lock checks until transaction cleanup.
            return initializeAndRun.get();
        }
        // A one-off check must release its frames and restore an enclosing operation, even on failure.
        return executeInReentrancyScope(initializeAndRun);
    }

    boolean ownsCurrentMutationFrame(Object owner) {
        return frameStack.get().peekFirst() instanceof MutationFrame mutation && mutation.owner() == owner;
    }

    /** Returns the active per-request OPA {@link MaskDirective}s for collection export, or an empty list. */
    public List<MaskDirective> currentExportMaskDirectives() {
        QueryFrame queryFrame = currentQueryFrame();
        if (queryFrame != null && queryFrame.context().maskDirectives() != null) {
            return queryFrame.context().maskDirectives();
        }
        ExportMaskFrame topExport = exportFrameStack.get().peekFirst();
        return topExport == null || topExport.maskDirectives() == null ? List.of() : topExport.maskDirectives();
    }

    /** Returns the active per-request dynamically value-denied attribute IDs for collection export ({@code Fase P10.17-A}). */
    public Set<String> currentExportValueDeniedAttributeIds() {
        QueryFrame queryFrame = currentQueryFrame();
        if (queryFrame != null && queryFrame.context().valueDeniedAttributeIds() != null) {
            return queryFrame.context().valueDeniedAttributeIds();
        }
        ExportMaskFrame topExport = exportFrameStack.get().peekFirst();
        return topExport == null || topExport.valueDeniedAttributeIds() == null
                ? Set.of()
                : topExport.valueDeniedAttributeIds();
    }

    /**
     * Evaluates OPA {@code SEARCH} authorization, enforces {@code FieldUseQueryGuard}, translates
     * the {@code DataScopePlan} into a real Spring Data JPA {@link ResourceFilterAccessScope}, and
     * binds the resulting {@link AuthorizedQueryScopeContext} for subsequent response masking
     * ({@code P01}, {@code P05..P09}, {@code P17}, {@code P50}).
     *
     * @param decisionPoint canonical decision point descriptor
     * @param factContractDigest SHA-256 digest of the governing {@code FactContract}
     * @param requestHeaderNames raw HTTP request header names (rejected fail-closed if spoofing scope)
     * @param resolvedSubjectAndEnvFacts trusted resolved subject and environment facts
     * @param factStatuses 4-state resolution statuses
     * @param requestedFieldUses requested {@code FILTER}, {@code SORT}, {@code GROUP} attribute IDs
     * @param baselineFieldUseDirectives baseline field-use directives from {@code @DomainGovernance}
     * @param jpaDataScopeAdapter canonical JPQL data scope adapter
     * @param hardScopeJpql mandatory host JPQL hard scope clause
     * @param hardScopeParams mandatory host JPQL hard scope parameters
     * @param criteriaTranslator JPA Criteria translator for {@link ResourceFilterAccessScope}
     * @param hardScope mandatory host {@link ResourceFilterAccessScope}
     * @param <E> JPA entity type
     * @return composed {@link ResourceFilterAccessScope} ready for {@code AbstractBaseQueryResourceService}
     */
    public <E> ResourceFilterAccessScope<E> authorizeAndResolveAccessScope(
            DecisionPointDescriptor decisionPoint,
            String factContractDigest,
            Set<String> requestHeaderNames,
            Map<String, Object> resolvedSubjectAndEnvFacts,
            Map<String, FactResolutionStatus> factStatuses,
            Map<FieldUseCategory, Set<String>> requestedFieldUses,
            List<FieldUseEffectDirective> baselineFieldUseDirectives,
            JpaDataScopeAdapter jpaDataScopeAdapter,
            String hardScopeJpql,
            Map<String, Object> hardScopeParams,
            JpaCriteriaDataScopeTranslator criteriaTranslator,
            ResourceFilterAccessScope<E> hardScope
    ) {
        return authorizeAndResolveAccessScope(
                decisionPoint,
                factContractDigest,
                requestHeaderNames,
                resolvedSubjectAndEnvFacts,
                factStatuses,
                requestedFieldUses,
                baselineFieldUseDirectives,
                jpaDataScopeAdapter,
                hardScopeJpql,
                hardScopeParams,
                criteriaTranslator,
                hardScope,
                null
        );
    }

    /**
     * Owner-aware variant pushing a reentrant {@link QueryFrame} onto the LIFO authorization stack
     * without wiping outer callers' frames.
     */
    public <E> ResourceFilterAccessScope<E> authorizeAndResolveAccessScope(
            DecisionPointDescriptor decisionPoint,
            String factContractDigest,
            Set<String> requestHeaderNames,
            Map<String, Object> resolvedSubjectAndEnvFacts,
            Map<String, FactResolutionStatus> factStatuses,
            Map<FieldUseCategory, Set<String>> requestedFieldUses,
            List<FieldUseEffectDirective> baselineFieldUseDirectives,
            JpaDataScopeAdapter jpaDataScopeAdapter,
            String hardScopeJpql,
            Map<String, Object> hardScopeParams,
            JpaCriteriaDataScopeTranslator criteriaTranslator,
            ResourceFilterAccessScope<E> hardScope,
            Object owner
    ) {
        return authorizeAndResolveAccessScope(
                decisionPoint,
                factContractDigest,
                requestHeaderNames,
                Map.of(),
                null,
                resolvedSubjectAndEnvFacts,
                factStatuses,
                requestedFieldUses,
                baselineFieldUseDirectives,
                jpaDataScopeAdapter,
                hardScopeJpql,
                hardScopeParams,
                criteriaTranslator,
                hardScope,
                owner
        );
    }

    /**
     * Owner-aware variant pushing a reentrant {@link QueryFrame} onto the LIFO authorization stack
     * using validated incoming header values for anti-spoofing verification ({@code P02}, {@code P53}).
     */
    public <E> ResourceFilterAccessScope<E> authorizeAndResolveAccessScope(
            DecisionPointDescriptor decisionPoint,
            String factContractDigest,
            Set<String> requestHeaderNames,
            Map<String, String> requestHeaders,
            String authoritativeTenantId,
            Map<String, Object> resolvedSubjectAndEnvFacts,
            Map<String, FactResolutionStatus> factStatuses,
            Map<FieldUseCategory, Set<String>> requestedFieldUses,
            List<FieldUseEffectDirective> baselineFieldUseDirectives,
            JpaDataScopeAdapter jpaDataScopeAdapter,
            String hardScopeJpql,
            Map<String, Object> hardScopeParams,
            JpaCriteriaDataScopeTranslator criteriaTranslator,
            ResourceFilterAccessScope<E> hardScope,
            Object owner
    ) {
        registerTransactionCleanupIfActive();
        AuthorizedQueryScopeContext queryCtx = authorizationSeam.authorizeAndCompileJpaQueryScope(
                decisionPoint,
                factContractDigest,
                requestHeaderNames,
                requestHeaders,
                authoritativeTenantId,
                resolvedSubjectAndEnvFacts,
                factStatuses,
                requestedFieldUses,
                baselineFieldUseDirectives,
                jpaDataScopeAdapter,
                hardScopeJpql,
                hardScopeParams,
                row -> true
        );
        List<MaskDirective> masks = queryCtx.maskDirectives() == null ? List.of() : queryCtx.maskDirectives();
        Set<String> valueDenied = queryCtx.valueDeniedAttributeIds() == null ? Set.of() : queryCtx.valueDeniedAttributeIds();

        Object normalizedOwner = normalizeOwner(owner);
        if (normalizedOwner == DEFAULT_OWNER) {
            popTopFramesForOwner(DEFAULT_OWNER);
        }
        Deque<AuthorizationFrame> stack = frameStack.get();
        if (normalizedOwner != DEFAULT_OWNER
                && stack.peekFirst() instanceof QueryFrame topQuery
                && topQuery.owner() == normalizedOwner) {
            stack.pollFirst();
        }
        stack.addFirst(new QueryFrame(normalizedOwner, queryCtx));
        exportFrameStack.get().addFirst(new ExportMaskFrame(masks, valueDenied));

        if (queryCtx.dataScopePlan() == null || queryCtx.scopeOutcome() == DataScopeOutcome.NONE) {
            return ResourceFilterAccessScope.denied();
        }
        return criteriaTranslator.toResourceFilterAccessScope(
                queryCtx.dataScopePlan(),
                hardScope
        );
    }

    /**
     * Executes pre-hydration mutation authorization ({@code STEP_11}) before {@code hydrate*} and
     * {@code PraxisRulesEngine} ({@code STEP_12}) and pushes the {@link AuthorizedPreMutationContext}
     * onto the LIFO authorization stack ({@code R-11}, {@code P13}, {@code P14}).
     */
    public AuthorizedPreMutationContext authorizeBeforeHydrationAndRules(
            DecisionPointDescriptor decisionPoint,
            String factContractDigest,
            String operationVerb,
            boolean partialPatch,
            Object rawPayloadOrJson,
            Map<String, String> wirePointerToAttributeIdMap,
            Set<String> technicalConcurrencyPointers,
            Set<String> mandatoryScopeAnchorAttributeIds,
            DualScopeDelegationSpec dualScopeSpec,
            boolean callerMatchesCedente,
            boolean callerMatchesCessionario,
            Map<String, Object> resolvedFacts,
            Map<String, FactResolutionStatus> factStatuses
    ) {
        return authorizeBeforeHydrationAndRules(
                decisionPoint,
                factContractDigest,
                operationVerb,
                partialPatch,
                rawPayloadOrJson,
                wirePointerToAttributeIdMap,
                technicalConcurrencyPointers,
                mandatoryScopeAnchorAttributeIds,
                dualScopeSpec,
                callerMatchesCedente,
                callerMatchesCessionario,
                resolvedFacts,
                factStatuses,
                null
        );
    }

    /**
     * Owner-aware variant pushing a reentrant {@link MutationFrame} onto the LIFO authorization stack
     * without wiping outer callers' frames or the enclosing {@link QueryFrame} during {@code update}.
     */
    public AuthorizedPreMutationContext authorizeBeforeHydrationAndRules(
            DecisionPointDescriptor decisionPoint,
            String factContractDigest,
            String operationVerb,
            boolean partialPatch,
            Object rawPayloadOrJson,
            Map<String, String> wirePointerToAttributeIdMap,
            Set<String> technicalConcurrencyPointers,
            Set<String> mandatoryScopeAnchorAttributeIds,
            DualScopeDelegationSpec dualScopeSpec,
            boolean callerMatchesCedente,
            boolean callerMatchesCessionario,
            Map<String, Object> resolvedFacts,
            Map<String, FactResolutionStatus> factStatuses,
            Object owner
    ) {
        registerTransactionCleanupIfActive();
        String rawJson;
        try {
            rawJson = rawPayloadOrJson instanceof String s
                    ? s
                    : objectMapper.writeValueAsString(rawPayloadOrJson);
        } catch (Exception ex) {
            throw new IllegalArgumentException("Failed to serialize mutation payload for WriteIntent extraction", ex);
        }
        AuthorizedPreMutationContext preCtx = authorizationSeam.authorizePreHydrationMutation(
                decisionPoint,
                factContractDigest,
                operationVerb,
                partialPatch,
                rawJson,
                wirePointerToAttributeIdMap,
                technicalConcurrencyPointers,
                mandatoryScopeAnchorAttributeIds,
                dualScopeSpec,
                callerMatchesCedente,
                callerMatchesCessionario,
                resolvedFacts,
                factStatuses
        );
        Object normalizedOwner = normalizeOwner(owner);
        Deque<AuthorizationFrame> stack = frameStack.get();
        if (stack.peekFirst() instanceof MutationFrame topMutation && topMutation.owner() == normalizedOwner) {
            stack.pollFirst();
        }
        stack.addFirst(new MutationFrame(normalizedOwner, preCtx, false));
        return preCtx;
    }

    /**
     * Marks the top-most mutation frame ready for post-mutation outbox fulfillment and response masking
     * inside {@link AuthzMaskingResourceMapperDecorator#toResponse(Object)}.
     *
     * <p>Invoke from {@code AbstractBaseResourceService.afterCreate(...)} / {@code afterUpdate(...)}.</p>
     */
    public void markPostMutationReadyForOutboxAndMasking() {
        Deque<AuthorizationFrame> stack = frameStack.get();
        if (!(stack.peekFirst() instanceof MutationFrame mf)) {
            throw new IllegalStateException(
                    "No AuthorizedPreMutationContext bound on current thread; authorizeBeforeHydrationAndRules must run in beforeCreate/beforeUpdate");
        }
        stack.pollFirst();
        stack.addFirst(new MutationFrame(mf.owner(), mf.context(), true));
    }

    /**
     * Executes pre-deletion authorization ({@code STEP_11}) before {@code validateDelete} ({@code STEP_12})
     * and enqueues the {@link AuthorizedPreMutationContext} for FIFO outbox fulfillment in
     * {@link #completeAfterDeleteOutbox()} across both single {@code deleteById} and batch
     * {@code deleteAllById} operations ({@code R-07}, {@code R-11}, {@code P17}, {@code P19}).
     */
    public AuthorizedPreMutationContext authorizeBeforeDelete(
            DecisionPointDescriptor decisionPoint,
            String factContractDigest,
            DualScopeDelegationSpec dualScopeSpec,
            boolean callerMatchesCedente,
            boolean callerMatchesCessionario,
            Map<String, Object> resolvedFacts,
            Map<String, FactResolutionStatus> factStatuses
    ) {
        return authorizeBeforeDelete(
                decisionPoint,
                factContractDigest,
                dualScopeSpec,
                callerMatchesCedente,
                callerMatchesCessionario,
                resolvedFacts,
                factStatuses,
                null
        );
    }

    /**
     * Owner-aware variant isolating FIFO deletion queues per owning service across reentrant
     * {@code ServiceA -> ServiceB} deletes.
     */
    public AuthorizedPreMutationContext authorizeBeforeDelete(
            DecisionPointDescriptor decisionPoint,
            String factContractDigest,
            DualScopeDelegationSpec dualScopeSpec,
            boolean callerMatchesCedente,
            boolean callerMatchesCessionario,
            Map<String, Object> resolvedFacts,
            Map<String, FactResolutionStatus> factStatuses,
            Object owner
    ) {
        registerTransactionCleanupIfActive();
        Object normalizedOwner = normalizeOwner(owner);
        popTopFramesForOwner(normalizedOwner);

        AuthorizedPreMutationContext preCtx = authorizationSeam.authorizePreHydrationMutation(
                decisionPoint,
                factContractDigest,
                "DELETE",
                false,
                "{}",
                Map.of(),
                Set.of(),
                Set.of(),
                dualScopeSpec,
                callerMatchesCedente,
                callerMatchesCessionario,
                resolvedFacts,
                factStatuses
        );
        pendingDeleteContextsByOwner.get()
                .computeIfAbsent(normalizedOwner, ignored -> new ArrayDeque<>())
                .addLast(preCtx);
        return preCtx;
    }

    /**
     * Fulfills {@code BEFORE_COMMIT_OUTBOX} obligations ({@code JdbcTransactionalAuditOutbox}) inside
     * {@code AbstractBaseResourceService.afterDelete(ID, E)} for the next admitted deletion in FIFO
     * order ({@code STEP_14}, {@code CC10}, {@code P19}, {@code P22}).
     */
    public void completeAfterDeleteOutbox() {
        completeAfterDeleteOutbox(null);
    }

    /**
     * Owner-aware variant fulfilling the next pending delete outbox for {@code owner} in FIFO order.
     */
    public void completeAfterDeleteOutbox(Object owner) {
        Object normalizedOwner = normalizeOwner(owner);
        Map<Object, Deque<AuthorizedPreMutationContext>> byOwner = pendingDeleteContextsByOwner.get();
        Deque<AuthorizedPreMutationContext> queue = byOwner.get(normalizedOwner);
        AuthorizedPreMutationContext preCtx = queue == null ? null : queue.pollFirst();
        if (preCtx == null) {
            throw new IllegalStateException(
                    "No pending delete AuthorizedPreMutationContext on current thread; authorizeBeforeDelete must run in beforeDelete");
        }
        if (queue.isEmpty()) {
            byOwner.remove(normalizedOwner);
            if (byOwner.isEmpty()) {
                pendingDeleteContextsByOwner.remove();
            }
            popTopFramesForOwner(normalizedOwner);
        }
        authorizationSeam.completePostDeleteOutbox(preCtx);
    }

    /**
     * Internal callback invoked by {@link AuthzMaskingResourceMapperDecorator#toResponse(Object)}
     * to apply post-mutation outbox + masking or query response masking without mutating JPA entities.
     */
    public <R> R maskMapperResponseIfReady(
            R rawResponse,
            Class<R> responseType,
            List<DtoFieldSchemaMetadata> fieldSchemas
    ) {
        return maskMapperResponseIfReady(null, rawResponse, responseType, fieldSchemas, null);
    }

    /**
     * Entity-aware variant supporting opt-in per-record contextual {@code TARGET} masking
     * ({@code P12}) while strictly honoring the top LIFO {@link AuthorizationFrame}.
     */
    public <E, R> R maskMapperResponseIfReady(
            E entity,
            R rawResponse,
            Class<R> responseType,
            List<DtoFieldSchemaMetadata> fieldSchemas,
            Function<E, TargetReadProjectionEvaluation> targetEvalResolver
    ) {
        if (rawResponse == null) {
            return null;
        }
        if (isInternalPreMutationDraftCall()) {
            // Internal AbstractBaseResourceService draft/custom-field/bulk projection (P13, P14)
            return rawResponse;
        }
        Deque<AuthorizationFrame> stack = frameStack.get();
        AuthorizationFrame top = stack.peekFirst();
        if (top instanceof MutationFrame mf) {
            if (!mf.readyForMasking()) {
                // Pre-mutation draft validation (STEP_12) sees raw unmasked values (P13, P14)
                return rawResponse;
            }
            stack.pollFirst();
            if (stack.isEmpty()) {
                frameStack.remove();
            }
            DetachedDtoMaskingResult masked = authorizationSeam.completePostMutationAndMask(
                    mf.context(),
                    rawResponse,
                    fieldSchemas
            );
            return maskedProjectionMapper.convertValue(masked.detachedProjection(), responseType);
        }
        if (top instanceof QueryFrame qf) {
            AuthorizedQueryScopeContext queryCtx = qf.context();
            if (queryCtx.scopeOutcome() == DataScopeOutcome.NONE) {
                throw new AuthzAccessDeniedException(
                        "AUTHZ_SCOPE_NONE",
                        "Fail-closed: access denied by DataScopeOutcome.NONE during query projection");
            }
            if (targetEvalResolver != null && entity != null) {
                TargetReadProjectionEvaluation targetEval = targetEvalResolver.apply(entity);
                if (targetEval != null) {
                    Set<String> mergedDenied = new LinkedHashSet<>(queryCtx.valueDeniedAttributeIds());
                    mergedDenied.addAll(targetEval.valueDeniedAttributeIds());
                    List<MaskDirective> mergedMasks = new ArrayList<>(queryCtx.maskDirectives());
                    mergedMasks.addAll(targetEval.maskDirectives());
                    DetachedDtoMaskingResult masked = maskingProcessor.projectAndMask(
                            rawResponse,
                            fieldSchemas,
                            mergedDenied,
                            mergedMasks
                    );
                    return maskedProjectionMapper.convertValue(masked.detachedProjection(), responseType);
                }
            }
            List<DetachedDtoMaskingResult> maskedList = authorizationSeam.projectAndMaskQueryResults(
                    queryCtx,
                    List.of(rawResponse),
                    fieldSchemas
            );
            return maskedProjectionMapper.convertValue(maskedList.getFirst().detachedProjection(), responseType);
        }
        throw new IllegalStateException(
                "Fail-closed: ResourceMapper.toResponse invoked without an active AuthorizedQueryScopeContext or AuthorizedPreMutationContext (P11, P12, P20)");
    }

    private static boolean isInternalPreMutationDraftCall() {
        return STACK_WALKER.walk(frames -> frames.anyMatch(frame -> {
            Class<?> declaring = frame.getDeclaringClass();
            if (!AbstractBaseResourceService.class.isAssignableFrom(declaring)) {
                return false;
            }
            String method = frame.getMethodName();
            return "prepareCreateValidationDraft".equals(method)
                    || "prepareUpdateValidationDraft".equals(method)
                    || "prepareDomainMutationValidation".equals(method)
                    || method.startsWith("lambda$prepareDomainMutationValidation$")
                    || "toBulkUpdate".equals(method);
        }));
    }

    private void registerTransactionCleanupIfActive() {
        if (!TransactionSynchronizationManager.isSynchronizationActive()) {
            return;
        }
        if (TransactionSynchronizationManager.hasResource(TX_CLEANUP_KEY)) {
            return;
        }
        TransactionSynchronizationManager.bindResource(TX_CLEANUP_KEY, Boolean.TRUE);
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override
            public void afterCompletion(int status) {
                try {
                    clearContext();
                } finally {
                    TransactionSynchronizationManager.unbindResourceIfPossible(TX_CLEANUP_KEY);
                }
            }
        });
    }

    /**
     * Completes a query/mutation response batch in {@code AbstractBaseQueryResourceService.enrichResponses(List)}
     * and clears thread-local query/mutation contexts while keeping export mask directives until transaction end.
     */
    public void completeBatchEnrichResponses() {
        completeBatchEnrichResponses(null);
    }

    /**
     * Owner-aware variant popping consecutive top frames owned by {@code owner} while preserving
     * outer callers' frames and export mask directives.
     */
    public void completeBatchEnrichResponses(Object owner) {
        popTopFramesForOwner(owner);
    }

    /**
     * Clears any active query, mutation, or pending-delete thread-local contexts when a mutation
     * or command aborts with an exception ({@code P10.10-R02}).
     */
    public void clearMutationAndQueryContextsOnFailure() {
        clearMutationAndQueryContextsOnFailure(null);
    }

    /**
     * Owner-aware variant clearing consecutive top frames and pending delete queues only for
     * {@code owner}, never wiping outer callers' frames.
     */
    public void clearMutationAndQueryContextsOnFailure(Object owner) {
        Object normalizedOwner = normalizeOwner(owner);
        popTopFramesForOwner(normalizedOwner);
        Map<Object, Deque<AuthorizedPreMutationContext>> byOwner = pendingDeleteContextsByOwner.get();
        byOwner.remove(normalizedOwner);
        if (byOwner.isEmpty()) {
            pendingDeleteContextsByOwner.remove();
        }
    }

    /**
     * Fulfills {@code BEFORE_COMMIT_OUTBOX} obligations ({@code JdbcTransactionalAuditOutbox}) inside
     * the active {@code @Transactional} boundary and returns the masked detached {@code ResponseDTO}
     * ({@code STEP_14}, {@code STEP_15}, {@code P19}, {@code P22}).
     */
    public <ResponseDTO> ResponseDTO completePostMutationOutboxAndMask(
            ResponseDTO responseDto,
            Class<ResponseDTO> responseType,
            List<DtoFieldSchemaMetadata> fieldSchemas
    ) {
        Deque<AuthorizationFrame> stack = frameStack.get();
        if (!(stack.peekFirst() instanceof MutationFrame mf)) {
            throw new IllegalStateException(
                    "No AuthorizedPreMutationContext bound on current thread; authorizeBeforeHydrationAndRules must run before mutation");
        }
        stack.pollFirst();
        if (stack.isEmpty()) {
            frameStack.remove();
        }
        DetachedDtoMaskingResult masked = authorizationSeam.completePostMutationAndMask(
                mf.context(),
                responseDto,
                fieldSchemas
        );
        return maskedProjectionMapper.convertValue(masked.detachedProjection(), responseType);
    }

    /**
     * Masks a list of materialized {@code ResponseDTO} instances using the active
     * {@link AuthorizedQueryScopeContext} without mutating managed JPA entities, failing closed
     * if no query authorization context is bound ({@code P11}, {@code P12}, {@code P20}).
     */
    public <ResponseDTO> List<ResponseDTO> maskQueryResponseDtos(
            List<ResponseDTO> responses,
            Class<ResponseDTO> responseType,
            List<DtoFieldSchemaMetadata> fieldSchemas
    ) {
        Deque<AuthorizationFrame> stack = frameStack.get();
        QueryFrame qf = stack.peekFirst() instanceof QueryFrame topQuery ? topQuery : currentQueryFrame();
        try {
            if (qf == null) {
                throw new IllegalStateException(
                        "No AuthorizedQueryScopeContext bound on current thread; authorizeAndResolveAccessScope must run before maskQueryResponseDtos");
            }
            if (responses == null || responses.isEmpty()) {
                return List.of();
            }
            List<DetachedDtoMaskingResult> maskedList = authorizationSeam.projectAndMaskQueryResults(
                    qf.context(),
                    responses,
                    fieldSchemas
            );
            List<ResponseDTO> converted = new ArrayList<>(maskedList.size());
            for (DetachedDtoMaskingResult m : maskedList) {
                converted.add(maskedProjectionMapper.convertValue(m.detachedProjection(), responseType));
            }
            return List.copyOf(converted);
        } finally {
            if (qf != null && stack.peekFirst() == qf) {
                stack.pollFirst();
                if (stack.isEmpty()) {
                    frameStack.remove();
                }
            }
        }
    }

    /** Returns the currently bound {@link AuthorizedQueryScopeContext} on this thread, or {@code null}. */
    AuthorizedQueryScopeContext currentQueryScopeContext() {
        QueryFrame qf = currentQueryFrame();
        return qf == null ? null : qf.context();
    }

    /** Restores a previously resolved {@link AuthorizedQueryScopeContext} on the current thread ({@code P10.16-R02}). */
    void restoreQueryScopeContext(AuthorizedQueryScopeContext queryCtx) {
        restoreQueryScopeContext(null, queryCtx);
    }

    /** Owner-aware variant ensuring {@code queryCtx} is on top of the LIFO frame stack. */
    void restoreQueryScopeContext(Object owner, AuthorizedQueryScopeContext queryCtx) {
        if (queryCtx == null) {
            return;
        }
        Object normalizedOwner = normalizeOwner(owner);
        Deque<AuthorizationFrame> stack = frameStack.get();
        if (stack.peekFirst() instanceof QueryFrame qf && qf.context() == queryCtx && qf.owner() == normalizedOwner) {
            return;
        }
        stack.addFirst(new QueryFrame(normalizedOwner, queryCtx));
    }

    /** Clears only the per-item mutation context while preserving any underlying query scope frame ({@code P10.16-R02}). */
    void clearPerItemMutationContext() {
        Deque<AuthorizationFrame> stack = frameStack.get();
        if (stack.peekFirst() instanceof MutationFrame) {
            stack.pollFirst();
            if (stack.isEmpty()) {
                frameStack.remove();
            }
        }
    }

    /**
     * Evaluates collection-level {@code SEARCH} admission and {@code DataScopePlan} for a custom
     * bulk action {@link DecisionPointDescriptor} ({@code P10.16-R02}).
     */
    AuthorizedQueryScopeContext evaluateBulkActionSearchScope(
            DecisionPointDescriptor actionDecisionPoint,
            String factContractDigest,
            Set<String> incomingHeaderNames,
            Map<String, String> incomingHeaders,
            String authoritativeTenantId,
            Map<String, Object> resolvedSubjectFacts,
            Map<String, FactResolutionStatus> factStatuses,
            JpaDataScopeAdapter jpaDataScopeAdapter,
            String hardScopeJpql,
            Map<String, Object> hardScopeParams
    ) {
        return authorizationSeam.authorizeAndCompileJpaQueryScope(
                actionDecisionPoint,
                factContractDigest,
                incomingHeaderNames == null ? Set.of() : incomingHeaderNames,
                incomingHeaders == null ? Map.of() : incomingHeaders,
                authoritativeTenantId,
                resolvedSubjectFacts,
                factStatuses,
                Map.of(),
                List.of(),
                jpaDataScopeAdapter,
                hardScopeJpql,
                hardScopeParams,
                row -> true
        );
    }

    /**
     * Evaluates live {@code TARGET} authorization via {@link MetadataResourceAuthorizationSeam}
     * for non-persistent reactive determinations and AI context projections, returning the live
     * OPA {@link MaskDirective}s and dynamically value-denied attributes ({@code Fase P10.6},
     * {@code P10.6-R05}).
     */
    TargetReadProjectionEvaluation authorizeTargetEntityProjection(
            DecisionPointDescriptor decisionPoint,
            String factContractDigest,
            Map<String, Object> trustedTargetFacts,
            Map<String, FactResolutionStatus> trustedFactStatuses
    ) {
        return authorizationSeam.evaluateTargetReadProjection(
                decisionPoint,
                factContractDigest,
                trustedTargetFacts,
                trustedFactStatuses
        );
    }

    /**
     * Evaluates live {@code TARGET} authorization via {@link MetadataResourceAuthorizationSeam}
     * for non-persistent reactive determinations and AI context projections ({@code Fase P10.6}).
     */
    void assertTargetEntityAccess(
            DecisionPointDescriptor decisionPoint,
            String factContractDigest,
            Map<String, Object> trustedTargetFacts,
            Map<String, FactResolutionStatus> trustedFactStatuses
    ) {
        authorizeTargetEntityProjection(
                decisionPoint,
                factContractDigest,
                trustedTargetFacts,
                trustedFactStatuses
        );
    }

    /**
     * Sanitizes and masks {@code Candidate.facts()} produced by {@code BulkDomainResourceAdapter.evaluate(...)}
     * before returning the candidate to the bulk proposal evaluation layer, while leaving
     * {@code Candidate.plan()} untouched for internal server-side confirmation ({@code P10.6-R01},
     * {@code P11}, {@code P12}, {@code P15}, {@code P50}).
     */
    JsonNode sanitizeBulkCandidateFactsNode(
            JsonNode rawFactsNode,
            IntrospectedDtoGovernanceContract explicitContract
    ) {
        if (rawFactsNode == null || !rawFactsNode.isObject()) {
            return rawFactsNode;
        }
        IntrospectedDtoGovernanceContract contract = resolveIntrospectedContract(explicitContract);
        if (contract == null) {
            return rawFactsNode;
        }
        MutationFrame mutationFrame = currentMutationFrame();
        AuthorizedPreMutationContext preCtx = mutationFrame == null ? null : mutationFrame.context();
        QueryFrame queryFrame = currentQueryFrame();
        AuthorizedQueryScopeContext queryCtx = queryFrame == null ? null : queryFrame.context();

        Set<String> deniedAttributes = new LinkedHashSet<>();
        for (FieldUseEffectDirective dir : contract.baselineFieldUseDirectives()) {
            if (dir.category() == FieldUseCategory.VALUE && dir.effect() == RuleEffect.DENY) {
                deniedAttributes.add(dir.attributeId());
            }
        }
        if (preCtx != null && preCtx.valueDeniedAttributeIds() != null) {
            deniedAttributes.addAll(preCtx.valueDeniedAttributeIds());
        } else if (queryCtx != null && queryCtx.valueDeniedAttributeIds() != null) {
            deniedAttributes.addAll(queryCtx.valueDeniedAttributeIds());
        }

        List<MaskDirective> maskDirectives;
        if (preCtx != null && preCtx.maskDirectives() != null) {
            maskDirectives = preCtx.maskDirectives();
        } else if (queryCtx != null && queryCtx.maskDirectives() != null) {
            maskDirectives = queryCtx.maskDirectives();
        } else {
            maskDirectives = currentExportMaskDirectives();
        }

        if (rawFactsNode.has("resource") && rawFactsNode.get("resource").isObject()) {
            ObjectNode copy = ((ObjectNode) rawFactsNode).deepCopy();
            copy.set("resource", sanitizeBulkResourceObjectNode((ObjectNode) rawFactsNode.get("resource"), contract, deniedAttributes, maskDirectives));
            return copy;
        }
        return sanitizeBulkResourceObjectNode((ObjectNode) rawFactsNode, contract, deniedAttributes, maskDirectives);
    }

    @SuppressWarnings("unchecked")
    private ObjectNode sanitizeBulkResourceObjectNode(
            ObjectNode resourceNode,
            IntrospectedDtoGovernanceContract contract,
            Set<String> deniedAttributes,
            List<MaskDirective> maskDirectives
    ) {
        Map<String, Object> rawMap = objectMapper.convertValue(resourceNode, Map.class);
        DetachedDtoMaskingResult masked = maskingProcessor.projectAndMask(
                rawMap,
                contract.fieldSchemas(),
                deniedAttributes,
                maskDirectives
        );
        Map<String, Object> sanitizedMap = new LinkedHashMap<>(rawMap);
        for (DtoFieldSchemaMetadata schema : contract.fieldSchemas()) {
            String wireName = schema.wireFieldName();
            if (rawMap.containsKey(wireName)) {
                if (masked.detachedProjection().containsKey(wireName)) {
                    sanitizedMap.put(wireName, masked.detachedProjection().get(wireName));
                } else {
                    sanitizedMap.remove(wireName);
                }
            }
        }
        return objectMapper.valueToTree(sanitizedMap);
    }

    /**
     * Fulfills {@code BEFORE_COMMIT_OUTBOX} obligations when a mutation completed {@code afterUpdate}
     * without disclosing a response DTO (for example, the prepared confirmation fast path in
     * {@code AbstractBaseResourceService.bulkDomainAdapter.update(...)}) ({@code Fase P10.5}, {@code P19}).
     */
    void completePendingMutationOutboxIfNotDisclosed() {
        Deque<AuthorizationFrame> stack = frameStack.get();
        if (stack.peekFirst() instanceof MutationFrame mf && mf.readyForMasking()) {
            stack.pollFirst();
            if (stack.isEmpty()) {
                frameStack.remove();
            }
            authorizationSeam.completePostDeleteOutbox(mf.context());
        }
    }

    /**
     * Clears transient default-owner query/mutation contexts and extracted field uses while
     * preserving outer service frames, export mask directives, and pending delete queues.
     */
    void clearTransientRequestContexts() {
        popTopFramesForOwner(DEFAULT_OWNER);
        activeExtractedQueryFieldUses.remove();
    }

    /**
     * Binds automatically extracted {@link FieldUseCategory#FILTER} and {@link FieldUseCategory#SORT}
     * uses for the duration of {@code action} with deterministic {@code finally} cleanup
     * ({@code Fase P10.15-A}).
     */
    public <T> T executeWithExtractedQueryFieldUses(
            Map<FieldUseCategory, Set<String>> extractedUses,
            java.util.function.Supplier<T> action
    ) {
        Objects.requireNonNull(action, "action is required");
        if (extractedUses == null || extractedUses.isEmpty()) {
            return action.get();
        }
        Map<FieldUseCategory, Set<String>> previous = activeExtractedQueryFieldUses.get();
        activeExtractedQueryFieldUses.set(mergeFieldUseMaps(previous, extractedUses));
        try {
            return action.get();
        } finally {
            if (previous == null) {
                activeExtractedQueryFieldUses.remove();
            } else {
                activeExtractedQueryFieldUses.set(previous);
            }
        }
    }

    /**
     * Merges caller-supplied {@code requestedQueryFieldUses} with any runtime-extracted
     * {@code FILTER}/{@code SORT} uses bound on the current thread ({@code Fase P10.15-A}).
     */
    public Map<FieldUseCategory, Set<String>> mergeWithExtractedQueryFieldUses(
            Map<FieldUseCategory, Set<String>> callerUses
    ) {
        Map<FieldUseCategory, Set<String>> extracted = activeExtractedQueryFieldUses.get();
        return mergeFieldUseMaps(callerUses, extracted);
    }

    private static Map<FieldUseCategory, Set<String>> mergeFieldUseMaps(
            Map<FieldUseCategory, Set<String>> first,
            Map<FieldUseCategory, Set<String>> second
    ) {
        if ((first == null || first.isEmpty()) && (second == null || second.isEmpty())) {
            return Map.of();
        }
        if (first == null || first.isEmpty()) {
            return second;
        }
        if (second == null || second.isEmpty()) {
            return first;
        }
        Map<FieldUseCategory, Set<String>> merged = new LinkedHashMap<>();
        for (Map.Entry<FieldUseCategory, Set<String>> e : first.entrySet()) {
            if (e.getKey() != null && e.getValue() != null && !e.getValue().isEmpty()) {
                merged.put(e.getKey(), new LinkedHashSet<>(e.getValue()));
            }
        }
        for (Map.Entry<FieldUseCategory, Set<String>> e : second.entrySet()) {
            if (e.getKey() != null && e.getValue() != null && !e.getValue().isEmpty()) {
                merged.computeIfAbsent(e.getKey(), k -> new LinkedHashSet<>()).addAll(e.getValue());
            }
        }
        Map<FieldUseCategory, Set<String>> immutable = new LinkedHashMap<>();
        for (Map.Entry<FieldUseCategory, Set<String>> e : merged.entrySet()) {
            immutable.put(e.getKey(), Set.copyOf(e.getValue()));
        }
        return Map.copyOf(immutable);
    }

    /** Returns {@code true} if a pre-mutation context is currently bound on this thread. */
    public boolean hasActiveMutationContext() {
        return currentMutationFrame() != null;
    }

    /** Clears any thread-local query or mutation authorization context. */
    public void clearContext() {
        frameStack.remove();
        exportFrameStack.remove();
        pendingDeleteContextsByOwner.remove();
        activeExtractedQueryFieldUses.remove();
        currentThreadContract.remove();
    }
}
