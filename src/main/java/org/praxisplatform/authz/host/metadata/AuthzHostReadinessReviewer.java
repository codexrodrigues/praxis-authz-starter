package org.praxisplatform.authz.host.metadata;

import java.beans.Introspector;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.RecordComponent;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import org.praxisplatform.authz.catalog.FieldLineageCatalogEntry;
import org.praxisplatform.authz.compatibility.HostRuntimePolicyCoordinates;
import org.praxisplatform.authz.contracts.decisionpoint.DecisionPointDescriptor;
import org.praxisplatform.authz.contracts.decisionpoint.EnforcementCapability;
import org.praxisplatform.authz.contracts.decisionpoint.FieldUseCategory;
import org.praxisplatform.authz.contracts.envelope.FieldUseEffectDirective;
import org.praxisplatform.authz.contracts.envelope.RuleEffect;
import org.praxisplatform.authz.contracts.policy.DualScopeDelegationSpec;
import org.praxisplatform.authz.enforcement.jpa.QueryAdapterFieldBinding;
import org.praxisplatform.authz.host.metadata.MetadataDtoGovernanceIntrospector.IntrospectedDtoGovernanceContract;
import org.praxisplatform.authz.seams.RuntimeDecisionPointRegistry;
import org.praxisplatform.authz.seams.RuntimeDecisionPointRegistry.RegisteredDecisionPointContext;
import org.praxisplatform.uischema.determination.ReactiveDeterminationDefinition;
import org.praxisplatform.uischema.determination.ReactiveDeterminationInputBinding;
import org.praxisplatform.uischema.determination.ReactiveDeterminationOutputBinding;
import org.praxisplatform.uischema.filter.annotation.Filterable;
import org.praxisplatform.uischema.service.base.AbstractBaseQueryResourceService;
import org.praxisplatform.uischema.stats.StatsFieldDescriptor;
import org.praxisplatform.uischema.stats.StatsFieldRegistry;
import org.springframework.aop.support.AopUtils;
import org.springframework.core.ResolvableType;
import org.springframework.core.annotation.AnnotatedElementUtils;
import org.springframework.util.ClassUtils;

/**
 * Architectural and semantic readiness reviewer for governed Praxis host resources
 * ({@code Fase P10.12}, {@code CC03}, {@code CC05..CC09}, {@code P01..P22}, {@code P39}, {@code P46..P50}).
 *
 * <p>Designed to be executed in host JUnit readiness gates (alongside {@code SemanticMetadataReviewer})
 * or at startup diagnostics to catch drift across:</p>
 * <ul>
 *   <li><b>{@code AUTHZ-HOST-001}:</b> Declarative {@link AuthzResourceGovernanceSpec} adoption and
 *       resource identity completeness ({@code resourceKey}, {@code decisionPoint}, {@code factContractDigest});</li>
 *   <li><b>{@code AUTHZ-HOST-002}:</b> {@code ResponseDTO} governance introspection coverage and absence
 *       of duplicate {@code attributeId} collisions across distinct JSON pointers;</li>
 *   <li><b>{@code AUTHZ-HOST-003}:</b> {@code CreateDTO}/{@code UpdateDTO} lineage inheritance and
 *       presence of all {@link AuthzResourceGovernanceSpec#mandatoryScopeAnchorAttributeIds()} on both
 *       {@code ResponseDTO} and {@code CreateDTO};</li>
 *   <li><b>{@code AUTHZ-HOST-004}:</b> {@link DualScopeDelegationSpec} custody rule completeness
 *       ({@code Cedente} and {@code Cessionário}), disjoint write partitions, and DTO attribute mapping;</li>
 *   <li><b>{@code AUTHZ-HOST-005}:</b> {@link AuthzResourceGovernanceSpec#operationModifiedAttributes()}
 *       non-empty declarations and attribute mapping coherence against introspected DTO contracts;</li>
 *   <li><b>{@code AUTHZ-HOST-006}:</b> JPA entity property path validity for {@code tenantFieldName},
 *       {@code stateFieldName}, {@code cedenteEntityFieldPath}, {@code cessionarioEntityFieldPath}, and
 *       all {@link QueryAdapterFieldBinding#nativeJpaPath()} bindings (including nested and {@code 1:N}
 *       collection paths);</li>
 *   <li><b>{@code AUTHZ-HOST-007}:</b> {@link RuntimeDecisionPointRegistry} admission and
 *       {@code FactContract} digest parity for the primary resource decision point and all custom
 *       action/surface decision points;</li>
 *   <li><b>{@code AUTHZ-HOST-008}:</b> Audit of {@link ReactiveDeterminationDefinition} bindings
 *       referencing {@code VALUE + DENY} attributes ({@link Severity#ERROR}) or binding
 *       {@code LGPD_SENSITIVE_DATA} / {@code aiAllowed = false} attributes as determination
 *       inputs/sources ({@link Severity#WARNING}, which risks feeding masked UI placeholders into
 *       server-side calculations);</li>
 *   <li><b>{@code AUTHZ-HOST-009}:</b> PAP semantic catalog field lineage and governance coherence
 *       ({@code P44..P50}, {@code P57}, {@code P58}, {@code P64}) across {@code ResponseDTO},
 *       {@code CreateDTO}, and {@code UpdateDTO} (explicit governance declaration, absence of
 *       contradictory sensitivity/AI-usage classifications per {@code attributeId}, and absence of
 *       unapproved derived governance widening);</li>
 *   <li><b>{@code AUTHZ-HOST-010}:</b> {@link HostRuntimePolicyCoordinates} binding coverage,
 *       custom action {@code FIELD_WRITE} target attribute declarations, and bulk action
 *       {@code EvaluationMode.SEARCH} + {@code QueryableProjectionRef} completeness;</li>
 *   <li><b>{@code AUTHZ-HOST-011}:</b> {@link StatsFieldRegistry} entity property path validity
 *       ({@code field}, {@code keyPropertyPath}, {@code labelPropertyPath}) and prohibition of
 *       {@code VALUE + DENY} ({@code SECRET} / {@code CREDENTIAL}) attributes in analytics descriptors;</li>
 *   <li><b>{@code AUTHZ-HOST-012}:</b> Prohibition of {@code VALUE + DENY} ({@code SECRET} /
 *       {@code CREDENTIAL}) attributes in {@link Filterable} predicates on {@code FilterDTO}
 *       (preventing side-channel oracle inference);</li>
 *   <li><b>{@code AUTHZ-HOST-013}:</b> {@link org.praxisplatform.uischema.exporting.CollectionExportField}
 *       allowlist property path validity on {@code ResponseDTO}, advisory detection of
 *       {@code exportable = false} fields, and prohibition of {@code VALUE + DENY} ({@code SECRET} /
 *       {@code CREDENTIAL}) attributes in collection exports;</li>
 *   <li><b>{@code AUTHZ-HOST-014}:</b> {@link org.praxisplatform.uischema.options.OptionSourceRegistry},
 *       {@link org.praxisplatform.uischema.options.EntityLookupDescriptor}, and
 *       {@link org.praxisplatform.uischema.options.LookupFilteringDescriptor} property path validity
 *       (including {@code dependencyFilterMap}, {@code availableFilters}, {@code sortOptions}, and
 *       {@code quickFilterFields}) and prohibition of {@code VALUE + DENY} ({@code SECRET} /
 *       {@code CREDENTIAL}) attributes in lookup projection, selection policy, and filtering paths
 *       ({@code Fase P10.23-A}, {@code Fase P10.24-A}).</li>
 * </ul>
 */
public final class AuthzHostReadinessReviewer {

    /** Severity level of a readiness finding. */
    public enum Severity {
        /** Blocking structural or semantic defect that causes fail-closed runtime rejections or drift. */
        ERROR,
        /** Non-blocking architectural warning or advisory governance observation. */
        WARNING
    }

    /**
     * Individual readiness finding produced by {@link AuthzHostReadinessReviewer}.
     *
     * @param ruleCode canonical rule code (e.g. {@code "AUTHZ-HOST-003-MISSING-MANDATORY-SCOPE-ANCHOR"})
     * @param severity {@link Severity#ERROR} or {@link Severity#WARNING}
     * @param resourceKey governed resource key (or {@code "<unknown>"})
     * @param serviceClassName simple or canonical name of the reviewed service/spec
     * @param targetElement offending attribute ID, property path, or decision point key
     * @param message detailed human-readable explanation of the finding
     * @param remediationHint actionable remediation guidance
     */
    public record ReadinessIssue(
            String ruleCode,
            Severity severity,
            String resourceKey,
            String serviceClassName,
            String targetElement,
            String message,
            String remediationHint
    ) {
        public ReadinessIssue {
            Objects.requireNonNull(ruleCode, "ruleCode is required");
            Objects.requireNonNull(severity, "severity is required");
            resourceKey = (resourceKey == null || resourceKey.isBlank()) ? "<unknown>" : resourceKey;
            serviceClassName = (serviceClassName == null || serviceClassName.isBlank()) ? "<unknown>" : serviceClassName;
            targetElement = (targetElement == null || targetElement.isBlank()) ? "<resource>" : targetElement;
            Objects.requireNonNull(message, "message is required");
            Objects.requireNonNull(remediationHint, "remediationHint is required");
        }
    }

    /**
     * Aggregated readiness report across one or more governed services or specifications.
     *
     * @param reviewedServiceCount number of services/specs audited
     * @param issues immutable ordered list of findings
     */
    public record ReadinessReport(
            int reviewedServiceCount,
            List<ReadinessIssue> issues
    ) {
        public ReadinessReport {
            issues = issues == null ? List.of() : List.copyOf(issues);
        }

        /** Returns all blocking {@link Severity#ERROR} findings. */
        public List<ReadinessIssue> errors() {
            return issues.stream().filter(i -> i.severity() == Severity.ERROR).toList();
        }

        /** Returns all advisory {@link Severity#WARNING} findings. */
        public List<ReadinessIssue> warnings() {
            return issues.stream().filter(i -> i.severity() == Severity.WARNING).toList();
        }

        /** Returns {@code true} when zero {@link Severity#ERROR} findings were detected. */
        public boolean isReady() {
            return errors().isEmpty();
        }

        /** Returns {@code true} when zero errors and zero warnings were detected. */
        public boolean isClean() {
            return issues.isEmpty();
        }

        /**
         * Asserts that {@link #isReady()} is {@code true}, throwing an {@link IllegalStateException}
         * with a formatted diagnostic summary if any {@link Severity#ERROR} exists.
         */
        public void assertReady() {
            List<ReadinessIssue> errs = errors();
            if (!errs.isEmpty()) {
                throw new IllegalStateException(formatDiagnosticSummary(
                        "AUTHZ_HOST_READINESS_FAILED: " + errs.size() + " blocking error(s) across "
                                + reviewedServiceCount + " governed service(s):",
                        errs
                ));
            }
        }

        /**
         * Asserts that {@link #isClean()} is {@code true}, throwing an {@link IllegalStateException}
         * if any {@link Severity#ERROR} or {@link Severity#WARNING} exists.
         */
        public void assertZeroIssues() {
            if (!issues.isEmpty()) {
                throw new IllegalStateException(formatDiagnosticSummary(
                        "AUTHZ_HOST_READINESS_STRICT_FAILED: " + issues.size() + " issue(s) across "
                                + reviewedServiceCount + " governed service(s):",
                        issues
                ));
            }
        }

        private static String formatDiagnosticSummary(String header, List<ReadinessIssue> items) {
            StringBuilder sb = new StringBuilder(header).append('\n');
            for (ReadinessIssue issue : items) {
                sb.append("  - [").append(issue.severity()).append("] ")
                        .append(issue.ruleCode())
                        .append(" (resource=").append(issue.resourceKey())
                        .append(", service=").append(issue.serviceClassName())
                        .append(", target=").append(issue.targetElement()).append("): ")
                        .append(issue.message())
                        .append(" | Remediation: ").append(issue.remediationHint())
                        .append('\n');
            }
            return sb.toString();
        }
    }

    private final MetadataDtoGovernanceIntrospector dtoIntrospector;
    private final RuntimeDecisionPointRegistry decisionPointRegistry;
    private final HostRuntimePolicyCoordinates coordinates;

    /**
     * Creates a reviewer with a default {@link MetadataDtoGovernanceIntrospector} and no
     * {@link RuntimeDecisionPointRegistry} check.
     */
    public AuthzHostReadinessReviewer() {
        this(new MetadataDtoGovernanceIntrospector(), null, null);
    }

    /**
     * Creates a reviewer bound to the given {@link MetadataDtoGovernanceIntrospector} and optional
     * {@link RuntimeDecisionPointRegistry}.
     *
     * @param dtoIntrospector DTO governance introspector
     * @param decisionPointRegistry optional runtime decision point registry for {@code AUTHZ-HOST-007}
     */
    public AuthzHostReadinessReviewer(
            MetadataDtoGovernanceIntrospector dtoIntrospector,
            RuntimeDecisionPointRegistry decisionPointRegistry
    ) {
        this(dtoIntrospector, decisionPointRegistry, null);
    }

    /**
     * Creates a reviewer bound to the given {@link MetadataDtoGovernanceIntrospector}, optional
     * {@link RuntimeDecisionPointRegistry}, and optional {@link HostRuntimePolicyCoordinates}
     * ({@code Fase P10.15-E}).
     *
     * @param dtoIntrospector DTO governance introspector
     * @param decisionPointRegistry optional runtime decision point registry for {@code AUTHZ-HOST-007}
     * @param coordinates optional host runtime policy coordinates for {@code AUTHZ-HOST-010}
     */
    public AuthzHostReadinessReviewer(
            MetadataDtoGovernanceIntrospector dtoIntrospector,
            RuntimeDecisionPointRegistry decisionPointRegistry,
            HostRuntimePolicyCoordinates coordinates
    ) {
        this.dtoIntrospector = Objects.requireNonNull(dtoIntrospector, "dtoIntrospector is required");
        this.decisionPointRegistry = decisionPointRegistry;
        this.coordinates = coordinates;
    }

    /**
     * Reviews all supplied read-only and mutable governed resource services and returns a consolidated
     * {@link ReadinessReport}.
     */
    public ReadinessReport reviewAll(
            Collection<? extends AbstractAuthzGovernedReadOnlyResourceService<?, ?, ?, ?>> readOnlyServices,
            Collection<? extends AbstractAuthzGovernedResourceService<?, ?, ?, ?, ?, ?>> mutableServices
    ) {
        List<ReadinessIssue> allIssues = new ArrayList<>();
        int count = 0;
        if (readOnlyServices != null) {
            for (AbstractAuthzGovernedReadOnlyResourceService<?, ?, ?, ?> ro : readOnlyServices) {
                if (ro != null) {
                    count++;
                    allIssues.addAll(reviewReadOnlyService(ro).issues());
                }
            }
        }
        if (mutableServices != null) {
            for (AbstractAuthzGovernedResourceService<?, ?, ?, ?, ?, ?> mut : mutableServices) {
                if (mut != null) {
                    count++;
                    allIssues.addAll(reviewMutableService(mut).issues());
                }
            }
        }
        return new ReadinessReport(count, allIssues);
    }

    /**
     * Reviews a single governed read-only resource service.
     */
    public ReadinessReport reviewReadOnlyService(
            AbstractAuthzGovernedReadOnlyResourceService<?, ?, ?, ?> service
    ) {
        Objects.requireNonNull(service, "service is required");
        Class<?> targetServiceClass = AopUtils.getTargetClass(service);
        String serviceName = targetServiceClass.getSimpleName();
        String resourceKey = safeResolveResourceKey(service::resolveResourceKey);
        ResolvableType queryType = ResolvableType.forClass(targetServiceClass)
                .as(AbstractBaseQueryResourceService.class);
        Class<?> entityClass = queryType.getGeneric(0).resolve(Object.class);
        Class<?> filterDtoClass = queryType.getGeneric(3).resolve(Object.class);
        Class<?> responseType = service.getResponseType();

        List<ReadinessIssue> issues = new ArrayList<>();
        reviewCommonServiceAndSpec(
                serviceName,
                resourceKey,
                service.getDecisionPoint(),
                service.getFactContractDigest(),
                service.getGovernanceSpec(),
                entityClass,
                responseType,
                filterDtoClass,
                null,
                null,
                Set.of(),
                service.defineReactiveDeterminations(),
                service.defineRawStatsFieldRegistry(),
                service.defineRawExportFields(),
                service.getDeclaredOptionSourceRegistry(),
                issues
        );
        return new ReadinessReport(1, issues);
    }

    /**
     * Reviews a single governed mutable resource service.
     */
    public ReadinessReport reviewMutableService(
            AbstractAuthzGovernedResourceService<?, ?, ?, ?, ?, ?> service
    ) {
        Objects.requireNonNull(service, "service is required");
        Class<?> targetServiceClass = AopUtils.getTargetClass(service);
        String serviceName = targetServiceClass.getSimpleName();
        String resourceKey = safeResolveResourceKey(service::resolveResourceKey);
        ResolvableType mutableType = ResolvableType.forClass(targetServiceClass)
                .as(AbstractAuthzGovernedResourceService.class);
        Class<?> entityClass = mutableType.getGeneric(0).resolve(Object.class);
        Class<?> responseType = service.getResponseType();
        Class<?> filterDtoClass = mutableType.getGeneric(3).resolve(Object.class);
        Class<?> createDtoClass = mutableType.getGeneric(4).resolve(Object.class);
        Class<?> updateDtoClass = mutableType.getGeneric(5).resolve(Object.class);

        List<ReadinessIssue> issues = new ArrayList<>();
        reviewCommonServiceAndSpec(
                serviceName,
                resourceKey,
                service.getDecisionPoint(),
                service.getFactContractDigest(),
                service.getGovernanceSpec(),
                entityClass,
                responseType,
                filterDtoClass,
                createDtoClass,
                updateDtoClass,
                service.resolveMandatoryScopeAnchorAttributeIds(),
                service.defineReactiveDeterminations(),
                service.defineRawStatsFieldRegistry(),
                service.defineRawExportFields(),
                service.getDeclaredOptionSourceRegistry(),
                issues
        );
        return new ReadinessReport(1, issues);
    }

    /**
     * Reviews a standalone {@link AuthzResourceGovernanceSpec} against its entity and DTO classes
     * without requiring a Spring service instance.
     */
    public ReadinessReport reviewGovernanceSpec(
            AuthzResourceGovernanceSpec<?> spec,
            Class<?> entityClass,
            Class<?> responseDtoClass,
            Class<?> createDtoClass,
            Class<?> updateDtoClass
    ) {
        return reviewGovernanceSpec(spec, entityClass, responseDtoClass, null, createDtoClass, updateDtoClass, null, null, null);
    }

    /**
     * Reviews a standalone {@link AuthzResourceGovernanceSpec} against its entity, {@code ResponseDTO},
     * {@code FilterDTO}, {@code CreateDTO}, and {@code UpdateDTO} classes ({@code Fase P10.15-R04}).
     */
    public ReadinessReport reviewGovernanceSpec(
            AuthzResourceGovernanceSpec<?> spec,
            Class<?> entityClass,
            Class<?> responseDtoClass,
            Class<?> filterDtoClass,
            Class<?> createDtoClass,
            Class<?> updateDtoClass
    ) {
        return reviewGovernanceSpec(
                spec,
                entityClass,
                responseDtoClass,
                filterDtoClass,
                createDtoClass,
                updateDtoClass,
                null,
                null,
                null
        );
    }

    /**
     * Reviews a standalone {@link AuthzResourceGovernanceSpec} against its entity, {@code ResponseDTO},
     * {@code FilterDTO}, {@code CreateDTO}, {@code UpdateDTO}, and raw {@link StatsFieldRegistry}
     * ({@code Fase P10.21-A}).
     */
    public ReadinessReport reviewGovernanceSpec(
            AuthzResourceGovernanceSpec<?> spec,
            Class<?> entityClass,
            Class<?> responseDtoClass,
            Class<?> filterDtoClass,
            Class<?> createDtoClass,
            Class<?> updateDtoClass,
            StatsFieldRegistry rawStatsRegistry
    ) {
        return reviewGovernanceSpec(
                spec,
                entityClass,
                responseDtoClass,
                filterDtoClass,
                createDtoClass,
                updateDtoClass,
                rawStatsRegistry,
                null,
                null
        );
    }

    /**
     * Reviews a standalone {@link AuthzResourceGovernanceSpec} against its entity, {@code ResponseDTO},
     * {@code FilterDTO}, {@code CreateDTO}, {@code UpdateDTO}, raw {@link StatsFieldRegistry}, and
     * raw {@link org.praxisplatform.uischema.exporting.CollectionExportField} allowlist
     * ({@code Fase P10.22-A}).
     */
    public ReadinessReport reviewGovernanceSpec(
            AuthzResourceGovernanceSpec<?> spec,
            Class<?> entityClass,
            Class<?> responseDtoClass,
            Class<?> filterDtoClass,
            Class<?> createDtoClass,
            Class<?> updateDtoClass,
            StatsFieldRegistry rawStatsRegistry,
            List<org.praxisplatform.uischema.exporting.CollectionExportField> rawExportFields
    ) {
        return reviewGovernanceSpec(
                spec,
                entityClass,
                responseDtoClass,
                filterDtoClass,
                createDtoClass,
                updateDtoClass,
                rawStatsRegistry,
                rawExportFields,
                null
        );
    }

    /**
     * Reviews a standalone {@link AuthzResourceGovernanceSpec} against its entity, {@code ResponseDTO},
     * {@code FilterDTO}, {@code CreateDTO}, {@code UpdateDTO}, raw {@link StatsFieldRegistry},
     * raw {@link org.praxisplatform.uischema.exporting.CollectionExportField} allowlist, and
     * declared {@link org.praxisplatform.uischema.options.OptionSourceRegistry}
     * ({@code Fase P10.23-A}).
     */
    public ReadinessReport reviewGovernanceSpec(
            AuthzResourceGovernanceSpec<?> spec,
            Class<?> entityClass,
            Class<?> responseDtoClass,
            Class<?> filterDtoClass,
            Class<?> createDtoClass,
            Class<?> updateDtoClass,
            StatsFieldRegistry rawStatsRegistry,
            List<org.praxisplatform.uischema.exporting.CollectionExportField> rawExportFields,
            org.praxisplatform.uischema.options.OptionSourceRegistry optionSourceRegistry
    ) {
        Objects.requireNonNull(spec, "spec is required");
        Objects.requireNonNull(responseDtoClass, "responseDtoClass is required");
        List<ReadinessIssue> issues = new ArrayList<>();
        reviewCommonServiceAndSpec(
                "AuthzResourceGovernanceSpec[" + spec.resourceKey() + "]",
                spec.resourceKey(),
                spec.decisionPoint(),
                spec.factContractDigest(),
                spec,
                entityClass != null ? entityClass : Object.class,
                responseDtoClass,
                filterDtoClass,
                createDtoClass,
                updateDtoClass,
                spec.mandatoryScopeAnchorAttributeIds(),
                List.of(),
                rawStatsRegistry,
                rawExportFields,
                optionSourceRegistry,
                issues
        );
        return new ReadinessReport(1, issues);
    }

    private void reviewCommonServiceAndSpec(
            String serviceName,
            String resourceKey,
            DecisionPointDescriptor decisionPoint,
            String factContractDigest,
            AuthzResourceGovernanceSpec<?> spec,
            Class<?> entityClass,
            Class<?> responseType,
            Class<?> filterDtoClass,
            Class<?> createDtoClass,
            Class<?> updateDtoClass,
            Set<String> effectiveMandatoryScopeAnchors,
            Collection<ReactiveDeterminationDefinition> rawDeterminations,
            StatsFieldRegistry rawStatsRegistry,
            List<org.praxisplatform.uischema.exporting.CollectionExportField> rawExportFields,
            org.praxisplatform.uischema.options.OptionSourceRegistry optionSourceRegistry,
            List<ReadinessIssue> issues
    ) {
        // AUTHZ-HOST-001: Resource identity & declarative spec adoption
        if (resourceKey == null || resourceKey.isBlank() || "<unknown>".equals(resourceKey)) {
            issues.add(new ReadinessIssue(
                    "AUTHZ-HOST-001-BLANK-RESOURCE-KEY",
                    Severity.ERROR,
                    resourceKey,
                    serviceName,
                    "resourceKey",
                    "Governed service resolved a null or blank resourceKey.",
                    "Annotate the service/controller with @ApiResource or configure AuthzResourceGovernanceSpec.builder(resourceKey)."
            ));
            return;
        }
        if (spec == null) {
            issues.add(new ReadinessIssue(
                    "AUTHZ-HOST-001-MANUAL-OVERRIDE-MODE",
                    Severity.WARNING,
                    resourceKey,
                    serviceName,
                    serviceName,
                    "Service uses legacy manual override constructor instead of declarative AuthzResourceGovernanceSpec.",
                    "Migrate to the 6-argument constructor accepting AuthzResourceGovernanceSpec<E> and AuthzCallerContextProvider."
            ));
        }
        if (decisionPoint == null) {
            issues.add(new ReadinessIssue(
                    "AUTHZ-HOST-001-MISSING-DECISION-POINT",
                    Severity.ERROR,
                    resourceKey,
                    serviceName,
                    "decisionPoint",
                    "Governed service resolved a null DecisionPointDescriptor.",
                    "Configure .decisionPoint(blueprint.decisionPoint()) on AuthzResourceGovernanceSpec.builder(resourceKey)."
            ));
        }
        if (factContractDigest == null || factContractDigest.isBlank()) {
            issues.add(new ReadinessIssue(
                    "AUTHZ-HOST-001-BLANK-FACT-CONTRACT-DIGEST",
                    Severity.ERROR,
                    resourceKey,
                    serviceName,
                    "factContractDigest",
                    "Governed service resolved a null or blank factContractDigest.",
                    "Configure .factContractDigest(blueprint.factContract().factContractDigest()) or .decisionPoint(dp) with a non-blank FactContractRef."
            ));
        }

        // AUTHZ-HOST-002: ResponseDTO governance introspection & duplicate attributeId check
        IntrospectedDtoGovernanceContract responseContract = dtoIntrospector.introspect(responseType, resourceKey);
        if (responseContract.fieldSchemas().isEmpty()
                && responseType != Object.class
                && !Map.class.isAssignableFrom(responseType)) {
            issues.add(new ReadinessIssue(
                    "AUTHZ-HOST-002-EMPTY-RESPONSE-SCHEMA",
                    Severity.ERROR,
                    resourceKey,
                    serviceName,
                    responseType.getSimpleName(),
                    "ResponseDTO '" + responseType.getSimpleName() + "' produced zero introspected properties.",
                    "Declare record components, fields, or getters with @DomainLineage / @DomainGovernance on ResponseDTO."
            ));
        }

        Map<String, String> attrIdToFirstPointer = new LinkedHashMap<>();
        for (Map.Entry<String, String> entry : responseContract.wirePointerToAttributeIdMap().entrySet()) {
            String pointer = entry.getKey();
            String attrId = entry.getValue();
            String previousPointer = attrIdToFirstPointer.putIfAbsent(attrId, pointer);
            if (previousPointer != null && !previousPointer.equals(pointer)) {
                issues.add(new ReadinessIssue(
                        "AUTHZ-HOST-002-DUPLICATE-ATTRIBUTE-ID",
                        Severity.ERROR,
                        resourceKey,
                        serviceName,
                        attrId,
                        "ResponseDTO '" + responseType.getSimpleName() + "' maps both '" + previousPointer
                                + "' and '" + pointer + "' to the same canonical attributeId '" + attrId + "'.",
                        "Assign distinct @DomainLineage(attributeId = ...) values to distinct DTO properties."
                ));
            }
        }

        Set<String> allKnownDtoAttributeIds = new LinkedHashSet<>(responseContract.wirePointerToAttributeIdMap().values());
        IntrospectedDtoGovernanceContract createContract = null;
        if (createDtoClass != null && createDtoClass != Object.class && !Map.class.isAssignableFrom(createDtoClass)) {
            createContract = dtoIntrospector.introspectWriteDto(createDtoClass, responseType, resourceKey);
            allKnownDtoAttributeIds.addAll(createContract.wirePointerToAttributeIdMap().values());
        }
        IntrospectedDtoGovernanceContract updateContract = null;
        if (updateDtoClass != null && updateDtoClass != Object.class && !Map.class.isAssignableFrom(updateDtoClass)) {
            updateContract = dtoIntrospector.introspectWriteDto(updateDtoClass, responseType, resourceKey);
            allKnownDtoAttributeIds.addAll(updateContract.wirePointerToAttributeIdMap().values());
        }

        // AUTHZ-HOST-003: Mandatory scope anchors on ResponseDTO and CreateDTO
        Set<String> anchors = effectiveMandatoryScopeAnchors != null ? effectiveMandatoryScopeAnchors : Set.of();
        Set<String> responseAttrIds = new LinkedHashSet<>(responseContract.wirePointerToAttributeIdMap().values());
        for (String anchorAttrId : anchors) {
            if (!responseAttrIds.contains(anchorAttrId)) {
                issues.add(new ReadinessIssue(
                        "AUTHZ-HOST-003-MISSING-MANDATORY-SCOPE-ANCHOR",
                        Severity.ERROR,
                        resourceKey,
                        serviceName,
                        anchorAttrId,
                        "Mandatory scope anchor '" + anchorAttrId + "' is not mapped on ResponseDTO '"
                                + responseType.getSimpleName() + "'.",
                        "Expose the scope anchor property on ResponseDTO with @DomainLineage(attributeId = \"" + anchorAttrId + "\")."
                ));
            }
            if (createContract != null) {
                // Verify CreateDTO itself declares a property mapped to anchorAttrId
                boolean presentInCreateDtoFields = createContract.fieldSchemas().stream()
                        .anyMatch(f -> anchorAttrId.equals(f.attributeId()));
                if (!presentInCreateDtoFields) {
                    issues.add(new ReadinessIssue(
                            "AUTHZ-HOST-003-MISSING-MANDATORY-SCOPE-ANCHOR",
                            Severity.ERROR,
                            resourceKey,
                            serviceName,
                            anchorAttrId,
                            "Mandatory scope anchor '" + anchorAttrId + "' is missing from CreateDTO '"
                                    + createDtoClass.getSimpleName() + "', which will cause create() to fail closed with AUTHZ_SCOPE_ANCHOR_CLEAR_FORBIDDEN.",
                            "Include the scope anchor property on CreateDTO (matching ResponseDTO property name or annotated with @DomainLineage)."
                    ));
                }
            }
        }

        if (spec != null) {
            // AUTHZ-HOST-004: DualScopeDelegationSpec coherence
            DualScopeDelegationSpec dualScope = spec.dualScopeDelegationSpec();
            if (dualScope != null) {
                if (!spec.hasDeclarativeCedenteCustody() || !spec.hasDeclarativeCessionarioCustody()) {
                    issues.add(new ReadinessIssue(
                            "AUTHZ-HOST-004-MISSING-DECLARATIVE-CUSTODY-RULES",
                            Severity.ERROR,
                            resourceKey,
                            serviceName,
                            "dualScopeDelegationSpec",
                            "DualScopeDelegationSpec is configured on AuthzResourceGovernanceSpec, but declarative Cedente or Cessionário custody rules are missing.",
                            "Configure both .cedenteCustody(...) and .cessionarioCustody(...) on AuthzResourceGovernanceSpec.builder(...)."
                    ));
                }

                Set<String> cedenteAttrs = dualScope.cedenteExclusiveWriteAttributes() != null
                        ? dualScope.cedenteExclusiveWriteAttributes()
                        : Set.of();
                Set<String> cessionarioAttrs = dualScope.cessionarioAllowedWriteAttributes() != null
                        ? dualScope.cessionarioAllowedWriteAttributes()
                        : Set.of();

                for (String attr : cedenteAttrs) {
                    if (cessionarioAttrs.contains(attr)) {
                        issues.add(new ReadinessIssue(
                                "AUTHZ-HOST-004-OVERLAPPING-DUAL-SCOPE-PARTITIONS",
                                Severity.ERROR,
                                resourceKey,
                                serviceName,
                                attr,
                                "Attribute '" + attr + "' is declared in both cedenteExclusiveWriteAttributes and cessionarioAllowedWriteAttributes.",
                                "Partition Cedente-exclusive and Cessionário-allowed write attributes into disjoint sets."
                        ));
                    }
                    if (!allKnownDtoAttributeIds.contains(attr)) {
                        issues.add(new ReadinessIssue(
                                "AUTHZ-HOST-004-UNMAPPED-DUAL-SCOPE-ATTRIBUTE",
                                Severity.ERROR,
                                resourceKey,
                                serviceName,
                                attr,
                                "Cedente-exclusive attribute '" + attr + "' in DualScopeDelegationSpec does not match any property on ResponseDTO/CreateDTO/UpdateDTO.",
                                "Verify @DomainLineage(attributeId = \"" + attr + "\") on the corresponding DTO property."
                        ));
                    }
                }
                for (String attr : cessionarioAttrs) {
                    if (!allKnownDtoAttributeIds.contains(attr)) {
                        issues.add(new ReadinessIssue(
                                "AUTHZ-HOST-004-UNMAPPED-DUAL-SCOPE-ATTRIBUTE",
                                Severity.ERROR,
                                resourceKey,
                                serviceName,
                                attr,
                                "Cessionário-allowed attribute '" + attr + "' in DualScopeDelegationSpec does not match any property on ResponseDTO/CreateDTO/UpdateDTO.",
                                "Verify @DomainLineage(attributeId = \"" + attr + "\") on the corresponding DTO property."
                        ));
                    }
                }
            }

            // AUTHZ-HOST-005: operationModifiedAttributes coherence
            for (Map.Entry<String, Set<String>> opEntry : spec.operationModifiedAttributes().entrySet()) {
                String opId = opEntry.getKey();
                Set<String> opAttrs = opEntry.getValue();
                if (opAttrs == null || opAttrs.isEmpty()) {
                    issues.add(new ReadinessIssue(
                            "AUTHZ-HOST-005-EMPTY-OPERATION-ATTRIBUTES",
                            Severity.WARNING,
                            resourceKey,
                            serviceName,
                            opId,
                            "Operation '" + opId + "' in operationModifiedAttributes has an empty attribute set.",
                            "Declare at least one target attributeId modified by '" + opId + "' or remove the empty entry."
                    ));
                    continue;
                }
                for (String attr : opAttrs) {
                    if (!allKnownDtoAttributeIds.contains(attr)) {
                        issues.add(new ReadinessIssue(
                                "AUTHZ-HOST-005-UNKNOWN-OPERATION-ATTRIBUTE",
                                Severity.ERROR,
                                resourceKey,
                                serviceName,
                                opId + " -> " + attr,
                                "Operation '" + opId + "' declares modified attributeId '" + attr
                                        + "', which is not mapped on ResponseDTO, CreateDTO, or UpdateDTO.",
                                "Align operationModifiedAttributes(\"" + opId + "\", ...) with the canonical @DomainLineage attributeIds on the resource DTOs."
                        ));
                    }
                }
            }

            // AUTHZ-HOST-006: Entity property paths & QueryAdapterFieldBinding nativeJpaPath validation
            if (entityClass != null && entityClass != Object.class && !Map.class.isAssignableFrom(entityClass)) {
                checkEntityPath(issues, resourceKey, serviceName, entityClass, "tenantFieldName", spec.tenantFieldName());
                if (spec.stateFieldName() != null) {
                    checkEntityPath(issues, resourceKey, serviceName, entityClass, "stateFieldName", spec.stateFieldName());
                }
                if (spec.cedenteEntityFieldPath() != null) {
                    checkEntityPath(issues, resourceKey, serviceName, entityClass, "cedenteEntityFieldPath", spec.cedenteEntityFieldPath());
                }
                if (spec.cessionarioEntityFieldPath() != null) {
                    checkEntityPath(issues, resourceKey, serviceName, entityClass, "cessionarioEntityFieldPath", spec.cessionarioEntityFieldPath());
                }
                for (QueryAdapterFieldBinding binding : spec.fieldBindings()) {
                    String jpaPath = binding.nativeJpaPath();
                    if (!isValidEntityPropertyPath(entityClass, jpaPath)) {
                        issues.add(new ReadinessIssue(
                                "AUTHZ-HOST-006-INVALID-QUERY-BINDING-PATH",
                                Severity.ERROR,
                                resourceKey,
                                serviceName,
                                binding.fieldPath() + " -> " + jpaPath,
                                "QueryAdapterFieldBinding for '" + binding.fieldPath() + "' references JPA path '"
                                        + jpaPath + "' which could not be resolved on entity '" + entityClass.getSimpleName() + "'.",
                                "Fix nativeJpaPath in AuthzResourceGovernanceSpec.fieldBinding(\"" + binding.fieldPath() + "\", ...) to match a valid field/getter on " + entityClass.getSimpleName() + "."
                        ));
                    }
                }
            }
        }
        Set<String> restrictedAttrs = new LinkedHashSet<>();
        Set<String> queryRestrictedAttrs = new LinkedHashSet<>();
        for (FieldUseEffectDirective dir : responseContract.baselineFieldUseDirectives()) {
            if (dir.category() == FieldUseCategory.VALUE && dir.effect() == RuleEffect.DENY) {
                restrictedAttrs.add(dir.attributeId());
            } else if ((dir.category() == FieldUseCategory.FILTER || dir.category() == FieldUseCategory.SORT)
                    && dir.effect() == RuleEffect.DENY) {
                queryRestrictedAttrs.add(dir.attributeId());
            }
        }
        queryRestrictedAttrs.removeAll(restrictedAttrs);
        if (filterDtoClass != null
                && filterDtoClass != Object.class
                && !Map.class.isAssignableFrom(filterDtoClass)) {
            auditFilterDtoEntityPaths(
                    issues,
                    resourceKey,
                    serviceName,
                    entityClass,
                    filterDtoClass,
                    responseContract,
                    spec,
                    restrictedAttrs
            );
        }

        // AUTHZ-HOST-007: RuntimeDecisionPointRegistry admission & FactContract digest parity
        if (decisionPoint != null
                && decisionPoint.factContractRef() != null
                && decisionPoint.factContractRef().factContractDigest() != null
                && factContractDigest != null
                && !factContractDigest.equals(decisionPoint.factContractRef().factContractDigest())) {
            issues.add(new ReadinessIssue(
                    "AUTHZ-HOST-007-FACT-DIGEST-MISMATCH",
                    Severity.ERROR,
                    resourceKey,
                    serviceName,
                    decisionPoint.identity().pointKey(),
                    "Service declares factContractDigest '" + factContractDigest + "', which disagrees with decisionPoint.factContractRef().factContractDigest() '"
                            + decisionPoint.factContractRef().factContractDigest() + "'.",
                    "Omit explicit .factContractDigest(...) so AuthzResourceGovernanceSpec inherits decisionPoint.factContractRef().factContractDigest() automatically, or align both digests."
            ));
        }
        if (decisionPointRegistry != null && decisionPoint != null) {
            verifyDecisionPointInRegistry(issues, resourceKey, serviceName, decisionPoint, factContractDigest);
            if (spec != null) {
                for (DecisionPointDescriptor actionDp : spec.actionDecisionPoints().values()) {
                    String actionExpectedDigest = (actionDp.factContractRef() != null
                                    && actionDp.factContractRef().factContractDigest() != null
                                    && !actionDp.factContractRef().factContractDigest().isBlank())
                            ? actionDp.factContractRef().factContractDigest()
                            : factContractDigest;
                    verifyDecisionPointInRegistry(issues, resourceKey, serviceName, actionDp, actionExpectedDigest);
                }
                for (DecisionPointDescriptor surfaceDp : spec.surfaceDecisionPoints().values()) {
                    String surfaceExpectedDigest = (surfaceDp.factContractRef() != null
                                    && surfaceDp.factContractRef().factContractDigest() != null
                                    && !surfaceDp.factContractRef().factContractDigest().isBlank())
                            ? surfaceDp.factContractRef().factContractDigest()
                            : factContractDigest;
                    verifyDecisionPointInRegistry(issues, resourceKey, serviceName, surfaceDp, surfaceExpectedDigest);
                }
            }
        }

        // AUTHZ-HOST-008: ReactiveDeterminationDefinition value-denied & sensitive-input pointer audit
        if (rawDeterminations != null && !rawDeterminations.isEmpty()) {
            Set<String> sensitiveAttrs = responseContract.aiContextDeniedAttributeIds() != null
                    ? responseContract.aiContextDeniedAttributeIds()
                    : Set.of();
            for (ReactiveDeterminationDefinition rawDef : rawDeterminations) {
                if (rawDef == null) {
                    continue;
                }
                if (rawDef.sourcePaths() != null) {
                    for (String sp : rawDef.sourcePaths()) {
                        checkDeterminationPointer(
                                issues, resourceKey, serviceName, rawDef.id(),
                                "sourcePath", true, sp, responseContract, restrictedAttrs, sensitiveAttrs
                        );
                    }
                }
                if (rawDef.inputs() != null) {
                    for (ReactiveDeterminationInputBinding in : rawDef.inputs()) {
                        if (in != null) {
                            checkDeterminationPointer(
                                    issues, resourceKey, serviceName, rawDef.id(),
                                    "input.fieldPath", true, in.fieldPath(), responseContract, restrictedAttrs, sensitiveAttrs
                            );
                            checkDeterminationPointer(
                                    issues, resourceKey, serviceName, rawDef.id(),
                                    "input.requestPath", true, in.requestPath(), responseContract, restrictedAttrs, sensitiveAttrs
                            );
                        }
                    }
                }
                if (rawDef.outputs() != null) {
                    for (ReactiveDeterminationOutputBinding out : rawDef.outputs()) {
                        if (out != null) {
                            checkDeterminationPointer(
                                    issues, resourceKey, serviceName, rawDef.id(),
                                    "output.responsePath", false, out.responsePath(), responseContract, restrictedAttrs, sensitiveAttrs
                            );
                            checkDeterminationPointer(
                                    issues, resourceKey, serviceName, rawDef.id(),
                                    "output.fieldPath", false, out.fieldPath(), responseContract, restrictedAttrs, sensitiveAttrs
                            );
                        }
                    }
                }
            }
        }

        // AUTHZ-HOST-009: PAP semantic catalog field lineage & governance coherence (Fase P10.13)
        if (responseType != null && responseType != Object.class && !Map.class.isAssignableFrom(responseType)) {
            List<FieldLineageCatalogEntry> lineageEntries = dtoIntrospector.deriveFieldLineageCatalogEntries(
                    resourceKey,
                    responseType,
                    createDtoClass,
                    updateDtoClass
            );
            Map<String, FieldLineageCatalogEntry> firstByAttributeId = new LinkedHashMap<>();
            for (FieldLineageCatalogEntry entry : lineageEntries) {
                if (!entry.explicitGovernanceDeclared()) {
                    issues.add(new ReadinessIssue(
                            "AUTHZ-HOST-009-MISSING-EXPLICIT-GOVERNANCE",
                            Severity.ERROR,
                            resourceKey,
                            serviceName,
                            entry.schemaRef() + "#" + entry.wirePath(),
                            "DTO property '" + entry.wirePath() + "' on '" + entry.schemaRef() + "' ("
                                    + entry.operationRole() + ") lacks explicit @DomainGovernance and does not inherit governance from ResponseDTO or @DomainLineage(sourceClass).",
                            "Annotate the DTO class/property with @DomainGovernance or link it via @DomainLineage to a governed ResponseDTO/entity attribute."
                    ));
                }
                FieldLineageCatalogEntry previous = firstByAttributeId.putIfAbsent(entry.attributeId(), entry);
                if (previous != null) {
                    if (!previous.sensitivityClassification().equals(entry.sensitivityClassification())
                            || !previous.aiUsageMode().equals(entry.aiUsageMode())
                            || !previous.conceptId().equals(entry.conceptId())) {
                        issues.add(new ReadinessIssue(
                                "AUTHZ-HOST-009-CONTRADICTORY-LINEAGE-GOVERNANCE",
                                Severity.ERROR,
                                resourceKey,
                                serviceName,
                                entry.attributeId(),
                                "Canonical attributeId '" + entry.attributeId() + "' declares contradictory governance between '"
                                        + previous.schemaRef() + "' (" + previous.sensitivityClassification() + " / " + previous.aiUsageMode()
                                        + ") and '" + entry.schemaRef() + "' (" + entry.sensitivityClassification() + " / " + entry.aiUsageMode() + ").",
                                "Ensure all DTO roles mapping to '" + entry.attributeId() + "' share identical @DomainGovernance classification and AI usage policy (or omit redundant @DomainGovernance on CreateDTO/UpdateDTO to inherit from ResponseDTO)."
                        ));
                    }
                }
            }
            for (FieldLineageCatalogEntry entry : lineageEntries) {
                for (String upstreamAttrId : entry.upstreamAttributeRefs()) {
                    FieldLineageCatalogEntry upstream = firstByAttributeId.get(upstreamAttrId);
                    if (upstream == null) {
                        continue;
                    }
                    boolean exportWidened = !upstream.exportable() && entry.exportable();
                    boolean aiWidened = "DENIED".equalsIgnoreCase(upstream.aiUsageMode())
                            && !"DENIED".equalsIgnoreCase(entry.aiUsageMode());
                    boolean declassified = sensitivityRank(entry.sensitivityClassification())
                            < sensitivityRank(upstream.sensitivityClassification());
                    if (exportWidened || aiWidened || declassified) {
                        issues.add(new ReadinessIssue(
                                "AUTHZ-HOST-009-DERIVED-GOVERNANCE-WIDENING",
                                Severity.ERROR,
                                resourceKey,
                                serviceName,
                                entry.attributeId() + " <- " + upstreamAttrId,
                                "Derived attribute '" + entry.attributeId() + "' widens exportability, AI usage, or declassifies sensitivity relative to upstream attribute '"
                                        + upstreamAttrId + "'.",
                                "Preserve at least the upstream attribute's @DomainGovernance sensitivity classification, exportable=false, and AI visibility restrictions on derived fields."
                        ));
                    }
                }
            }
        }

        // AUTHZ-HOST-010: HostRuntimePolicyCoordinates binding coverage & custom action attribute audit (Fase P10.15-E)
        if (coordinates != null && decisionPoint != null) {
            verifyDecisionPointInCoordinates(issues, resourceKey, serviceName, decisionPoint);
            if (spec != null) {
                for (DecisionPointDescriptor actionDp : spec.actionDecisionPoints().values()) {
                    verifyDecisionPointInCoordinates(issues, resourceKey, serviceName, actionDp);
                }
                for (DecisionPointDescriptor surfaceDp : spec.surfaceDecisionPoints().values()) {
                    verifyDecisionPointInCoordinates(issues, resourceKey, serviceName, surfaceDp);
                }
            }
        }
        if (spec != null) {
            for (Map.Entry<String, DecisionPointDescriptor> actionEntry : spec.actionDecisionPoints().entrySet()) {
                String actionKey = actionEntry.getKey();
                DecisionPointDescriptor actionDp = actionEntry.getValue();
                if (actionDp.supportedCapabilities().contains(EnforcementCapability.FIELD_WRITE)) {
                    Set<String> declaredAttrs = spec.operationModifiedAttributes().get(actionKey);
                    if (declaredAttrs == null || declaredAttrs.isEmpty()) {
                        issues.add(new ReadinessIssue(
                                "AUTHZ-HOST-010-UNDECLARED-CUSTOM-ACTION-ATTRIBUTES",
                                Severity.WARNING,
                                resourceKey,
                                serviceName,
                                actionKey,
                                "Custom action decision point '" + actionKey + "' (" + actionDp.identity().pointKey()
                                        + ") supports FIELD_WRITE, but no modified attributes are declared in operationModifiedAttributes(\"" + actionKey + "\", ...).",
                                "Declare .operationModifiedAttributes(\"" + actionKey + "\", Set.of(...)) on AuthzResourceGovernanceSpec so pre-availability and DualScope write checks cover the action's target attributes."
                        ));
                    }
                }
                if ((actionDp.evaluationModes().contains(org.praxisplatform.authz.contracts.decisionpoint.EvaluationMode.SEARCH)
                        || actionDp.supportedCapabilities().contains(EnforcementCapability.DATA_SCOPE))
                        && (actionDp.queryProjectionRef() == null
                        || !actionDp.evaluationModes().contains(org.praxisplatform.authz.contracts.decisionpoint.EvaluationMode.SEARCH))) {
                    issues.add(new ReadinessIssue(
                            "AUTHZ-HOST-010-BULK-ACTION-MISSING-QUERY-PROJECTION",
                            Severity.ERROR,
                            resourceKey,
                            serviceName,
                            actionKey,
                            "Collection-scoped bulk action decision point '" + actionKey + "' (" + actionDp.identity().pointKey()
                                    + ") declares SEARCH / DATA_SCOPE without EvaluationMode.SEARCH and a QueryableProjectionRef.",
                            "Register the bulk action via .bulkWorkflowAction(\"" + actionKey + "\", ...) or attach EvaluationMode.SEARCH + QueryableProjectionRef so collection-level availability and cohort selection can compile DataScopePlan."
                    ));
                }
            }
        }

        // AUTHZ-HOST-011: StatsFieldRegistry entity path & value-denied attribute audit (Fase P10.21-A)
        if (rawStatsRegistry != null && !rawStatsRegistry.isEmpty()) {
            auditStatsFieldRegistry(
                    issues,
                    resourceKey,
                    serviceName,
                    entityClass,
                    rawStatsRegistry,
                    responseContract,
                    spec,
                    restrictedAttrs
            );
        }

        // AUTHZ-HOST-013: CollectionExportField allowlist path, non-exportable & value-denied audit (Fase P10.22-A)
        if (rawExportFields != null && !rawExportFields.isEmpty()) {
            auditExportFields(
                    issues,
                    resourceKey,
                    serviceName,
                    responseType,
                    rawExportFields,
                    responseContract,
                    spec,
                    restrictedAttrs
            );
        }

        // AUTHZ-HOST-014: OptionSourceRegistry, EntityLookupDescriptor & LookupFilteringDescriptor path and value/query-denied audit (Fase P10.23-A / P10.24-A / P10.25-A)
        if (optionSourceRegistry != null && !optionSourceRegistry.isEmpty()) {
            auditOptionSourceRegistry(
                    issues,
                    resourceKey,
                    serviceName,
                    entityClass,
                    responseType,
                    filterDtoClass,
                    optionSourceRegistry,
                    responseContract,
                    spec,
                    restrictedAttrs,
                    queryRestrictedAttrs
            );
        }
    }

    private static void auditOptionSourceRegistry(
            List<ReadinessIssue> issues,
            String resourceKey,
            String serviceName,
            Class<?> entityClass,
            Class<?> responseType,
            Class<?> filterDtoClass,
            org.praxisplatform.uischema.options.OptionSourceRegistry optionSourceRegistry,
            IntrospectedDtoGovernanceContract responseContract,
            AuthzResourceGovernanceSpec<?> spec,
            Set<String> restrictedAttrs,
            Set<String> queryRestrictedAttrs
    ) {
        boolean checkEntity = entityClass != null && entityClass != Object.class && !Map.class.isAssignableFrom(entityClass);
        boolean checkDto = responseType != null && responseType != Object.class && !Map.class.isAssignableFrom(responseType);
        boolean checkFilterDto = filterDtoClass != null && filterDtoClass != Object.class && !Map.class.isAssignableFrom(filterDtoClass);
        for (org.praxisplatform.uischema.options.OptionSourceDescriptor descriptor : optionSourceRegistry.descriptors()) {
            if (descriptor == null) {
                continue;
            }
            String sourceKey = descriptor.key() != null ? descriptor.key() : "<unnamed>";
            boolean searchFallsBackToLabel = (descriptor.policy() == null
                    || (descriptor.policy().allowSearch() && !"none".equalsIgnoreCase(descriptor.policy().searchMode())))
                    && (descriptor.entityLookup() == null
                            || descriptor.entityLookup().searchPropertyPaths() == null
                            || descriptor.entityLookup().searchPropertyPaths().isEmpty());
            boolean labelPresent = descriptor.labelPropertyPath() != null && !descriptor.labelPropertyPath().isBlank();
            auditOptionSourcePath(
                    issues, resourceKey, serviceName, sourceKey, "propertyPath", descriptor.propertyPath(),
                    checkEntity, entityClass, checkDto, responseType, false, null,
                    searchFallsBackToLabel && !labelPresent,
                    responseContract, spec, restrictedAttrs, queryRestrictedAttrs
            );
            auditOptionSourcePath(
                    issues, resourceKey, serviceName, sourceKey, "labelPropertyPath", descriptor.labelPropertyPath(),
                    checkEntity, entityClass, checkDto, responseType, false, null,
                    searchFallsBackToLabel && labelPresent,
                    responseContract, spec, restrictedAttrs, queryRestrictedAttrs
            );
            auditOptionSourcePath(
                    issues, resourceKey, serviceName, sourceKey, "valuePropertyPath", descriptor.valuePropertyPath(),
                    checkEntity, entityClass, checkDto, responseType, false, null, false,
                    responseContract, spec, restrictedAttrs, queryRestrictedAttrs
            );
            if (descriptor.policy() != null
                    && descriptor.policy().defaultSort() != null
                    && !descriptor.policy().defaultSort().isBlank()) {
                String policyDefSort = descriptor.policy().defaultSort().trim();
                var effFiltering = descriptor.effectiveFiltering();
                boolean matchesSortOpt = effFiltering != null
                        && effFiltering.sortOptions() != null
                        && effFiltering.sortOptions().stream()
                                .filter(Objects::nonNull)
                                .anyMatch(opt -> policyDefSort.equals(opt.key()));
                if (!"label".equalsIgnoreCase(policyDefSort)
                        && !"id".equalsIgnoreCase(policyDefSort)
                        && !matchesSortOpt) {
                    issues.add(new ReadinessIssue(
                            "AUTHZ-HOST-014-INVALID-OPTION-SOURCE-DEFAULT-SORT",
                            Severity.ERROR,
                            resourceKey,
                            serviceName,
                            sourceKey + ".policy.defaultSort(" + policyDefSort + ")",
                            "OptionSource '" + sourceKey + "' declares OptionSourcePolicy.defaultSort '" + policyDefSort
                                    + "', which is neither 'label'/'id' nor a declared LookupSortOption.key().",
                            "Use 'label' or 'id' in OptionSourcePolicy.defaultSort, or declare '" + policyDefSort
                                    + "' in LookupFilteringDescriptor.sortOptions for '" + sourceKey + "'."
                    ));
                }
            }
            if (descriptor.dependencyFilterMap() != null) {
                for (Map.Entry<String, String> depEntry : descriptor.dependencyFilterMap().entrySet()) {
                    auditOptionSourcePath(
                            issues, resourceKey, serviceName, sourceKey,
                            "dependencyFilterMap[" + depEntry.getKey() + "]",
                            depEntry.getValue(),
                            checkEntity, entityClass, checkDto, responseType, checkFilterDto, filterDtoClass, true,
                            responseContract, spec, restrictedAttrs, queryRestrictedAttrs
                    );
                }
            }
            auditLookupFilteringDescriptor(
                    issues, resourceKey, serviceName, sourceKey, "filtering",
                    descriptor.filtering(),
                    checkEntity, entityClass, checkDto, responseType, checkFilterDto, filterDtoClass,
                    responseContract, spec, restrictedAttrs, queryRestrictedAttrs
            );
            org.praxisplatform.uischema.options.EntityLookupDescriptor lookup = descriptor.entityLookup();
            if (lookup != null) {
                auditOptionSourcePath(
                        issues, resourceKey, serviceName, sourceKey, "entityLookup.codePropertyPath",
                        lookup.codePropertyPath(),
                        checkEntity, entityClass, checkDto, responseType, false, null, false,
                        responseContract, spec, restrictedAttrs, queryRestrictedAttrs
                );
                auditOptionSourcePath(
                        issues, resourceKey, serviceName, sourceKey, "entityLookup.statusPropertyPath",
                        lookup.statusPropertyPath(),
                        checkEntity, entityClass, checkDto, responseType, false, null, false,
                        responseContract, spec, restrictedAttrs, queryRestrictedAttrs
                );
                auditOptionSourcePath(
                        issues, resourceKey, serviceName, sourceKey, "entityLookup.disabledPropertyPath",
                        lookup.disabledPropertyPath(),
                        checkEntity, entityClass, checkDto, responseType, false, null, false,
                        responseContract, spec, restrictedAttrs, queryRestrictedAttrs
                );
                auditOptionSourcePath(
                        issues, resourceKey, serviceName, sourceKey, "entityLookup.disabledReasonPropertyPath",
                        lookup.disabledReasonPropertyPath(),
                        checkEntity, entityClass, checkDto, responseType, false, null, false,
                        responseContract, spec, restrictedAttrs, queryRestrictedAttrs
                );
                if (lookup.descriptionPropertyPaths() != null) {
                    for (String descPath : lookup.descriptionPropertyPaths()) {
                        auditOptionSourcePath(
                                issues, resourceKey, serviceName, sourceKey, "entityLookup.descriptionPropertyPaths",
                                descPath,
                                checkEntity, entityClass, checkDto, responseType, false, null, false,
                                responseContract, spec, restrictedAttrs, queryRestrictedAttrs
                        );
                    }
                }
                if (lookup.searchPropertyPaths() != null) {
                    for (String searchPath : lookup.searchPropertyPaths()) {
                        auditOptionSourcePath(
                                issues, resourceKey, serviceName, sourceKey, "entityLookup.searchPropertyPaths",
                                searchPath,
                                checkEntity, entityClass, checkDto, responseType, checkFilterDto, filterDtoClass, true,
                                responseContract, spec, restrictedAttrs, queryRestrictedAttrs
                        );
                    }
                }
                if (lookup.dependencyFilterMap() != null
                        && !Objects.equals(lookup.dependencyFilterMap(), descriptor.dependencyFilterMap())) {
                    for (Map.Entry<String, String> depEntry : lookup.dependencyFilterMap().entrySet()) {
                        auditOptionSourcePath(
                                issues, resourceKey, serviceName, sourceKey,
                                "entityLookup.dependencyFilterMap[" + depEntry.getKey() + "]",
                                depEntry.getValue(),
                                checkEntity, entityClass, checkDto, responseType, checkFilterDto, filterDtoClass, true,
                                responseContract, spec, restrictedAttrs, queryRestrictedAttrs
                        );
                    }
                }
                if (lookup.filtering() != null && !Objects.equals(lookup.filtering(), descriptor.filtering())) {
                    auditLookupFilteringDescriptor(
                            issues, resourceKey, serviceName, sourceKey, "entityLookup.filtering",
                            lookup.filtering(),
                            checkEntity, entityClass, checkDto, responseType, checkFilterDto, filterDtoClass,
                            responseContract, spec, restrictedAttrs, queryRestrictedAttrs
                    );
                }
                org.praxisplatform.uischema.options.LookupSelectionPolicy selPolicy = lookup.selectionPolicy();
                if (selPolicy != null) {
                    auditOptionSourcePath(
                            issues, resourceKey, serviceName, sourceKey, "selectionPolicy.selectablePropertyPath",
                            selPolicy.selectablePropertyPath(),
                            checkEntity, entityClass, checkDto, responseType, false, null, false,
                            responseContract, spec, restrictedAttrs, queryRestrictedAttrs
                    );
                    auditOptionSourcePath(
                            issues, resourceKey, serviceName, sourceKey, "selectionPolicy.statusPropertyPath",
                            selPolicy.statusPropertyPath(),
                            checkEntity, entityClass, checkDto, responseType, false, null, false,
                            responseContract, spec, restrictedAttrs, queryRestrictedAttrs
                    );
                }
                org.praxisplatform.uischema.options.LookupDisplayDescriptor display = lookup.display();
                if (display != null) {
                    auditOptionSourcePath(
                            issues, resourceKey, serviceName, sourceKey, "display.primaryPropertyPath",
                            display.primaryPropertyPath(),
                            checkEntity, entityClass, checkDto, responseType, false, null, false,
                            responseContract, spec, restrictedAttrs, queryRestrictedAttrs
                    );
                    auditOptionSourcePath(
                            issues, resourceKey, serviceName, sourceKey, "display.avatarPropertyPath",
                            display.avatarPropertyPath(),
                            checkEntity, entityClass, checkDto, responseType, false, null, false,
                            responseContract, spec, restrictedAttrs, queryRestrictedAttrs
                    );
                    if (display.secondaryPropertyPaths() != null) {
                        for (String secPath : display.secondaryPropertyPaths()) {
                            auditOptionSourcePath(
                                    issues, resourceKey, serviceName, sourceKey, "display.secondaryPropertyPaths",
                                    secPath,
                                    checkEntity, entityClass, checkDto, responseType, false, null, false,
                                    responseContract, spec, restrictedAttrs, queryRestrictedAttrs
                            );
                        }
                    }
                    if (display.badgePropertyPaths() != null) {
                        for (String badgePath : display.badgePropertyPaths()) {
                            auditOptionSourcePath(
                                    issues, resourceKey, serviceName, sourceKey, "display.badgePropertyPaths",
                                    badgePath,
                                    checkEntity, entityClass, checkDto, responseType, false, null, false,
                                    responseContract, spec, restrictedAttrs, queryRestrictedAttrs
                            );
                        }
                    }
                    if (display.fields() != null) {
                        for (org.praxisplatform.uischema.options.LookupDisplayFieldDescriptor dispField : display.fields()) {
                            if (dispField != null) {
                                String dispPath = dispField.propertyPath() != null ? dispField.propertyPath() : dispField.key();
                                auditOptionSourcePath(
                                        issues, resourceKey, serviceName, sourceKey, "display.fields[" + dispField.key() + "]",
                                        dispPath,
                                        checkEntity, entityClass, checkDto, responseType, false, null, false,
                                        responseContract, spec, restrictedAttrs, queryRestrictedAttrs
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    private static void auditLookupFilteringDescriptor(
            List<ReadinessIssue> issues,
            String resourceKey,
            String serviceName,
            String sourceKey,
            String prefix,
            org.praxisplatform.uischema.options.LookupFilteringDescriptor filtering,
            boolean checkEntity,
            Class<?> entityClass,
            boolean checkDto,
            Class<?> responseType,
            boolean checkFilterDto,
            Class<?> filterDtoClass,
            IntrospectedDtoGovernanceContract responseContract,
            AuthzResourceGovernanceSpec<?> spec,
            Set<String> restrictedAttrs,
            Set<String> queryRestrictedAttrs
    ) {
        if (filtering == null) {
            return;
        }
        if (filtering.availableFilters() != null) {
            for (org.praxisplatform.uischema.options.LookupFilterDefinition filterDef : filtering.availableFilters()) {
                if (filterDef != null) {
                    auditOptionSourcePath(
                            issues, resourceKey, serviceName, sourceKey,
                            prefix + ".availableFilters[" + filterDef.field() + "]",
                            filterDef.field(),
                            checkEntity, entityClass, checkDto, responseType, checkFilterDto, filterDtoClass, true,
                            responseContract, spec, restrictedAttrs, queryRestrictedAttrs
                    );
                }
            }
        }
        if (filtering.defaultFilters() != null) {
            for (String defaultFilterField : filtering.defaultFilters().keySet()) {
                auditOptionSourcePath(
                        issues, resourceKey, serviceName, sourceKey,
                        prefix + ".defaultFilters[" + defaultFilterField + "]",
                        defaultFilterField,
                        checkEntity, entityClass, checkDto, responseType, checkFilterDto, filterDtoClass, true,
                        responseContract, spec, restrictedAttrs, queryRestrictedAttrs
                );
            }
        }
        if (filtering.sortOptions() != null) {
            for (org.praxisplatform.uischema.options.LookupSortOption sortOpt : filtering.sortOptions()) {
                if (sortOpt != null) {
                    auditOptionSourcePath(
                            issues, resourceKey, serviceName, sourceKey,
                            prefix + ".sortOptions[" + sortOpt.field() + "]",
                            sortOpt.field(),
                            checkEntity, entityClass, checkDto, responseType, false, null, true,
                            responseContract, spec, restrictedAttrs, queryRestrictedAttrs
                    );
                }
            }
        }
        if (filtering.defaultSort() != null && !filtering.defaultSort().isBlank()) {
            String defSortKey = filtering.defaultSort().trim();
            boolean matchesDeclaredSortOption = filtering.sortOptions() != null
                    && filtering.sortOptions().stream()
                            .filter(Objects::nonNull)
                            .anyMatch(opt -> defSortKey.equals(opt.key()));
            if (!matchesDeclaredSortOption) {
                issues.add(new ReadinessIssue(
                        "AUTHZ-HOST-014-INVALID-OPTION-SOURCE-DEFAULT-SORT",
                        Severity.ERROR,
                        resourceKey,
                        serviceName,
                        sourceKey + "." + prefix + ".defaultSort(" + defSortKey + ")",
                        "OptionSource '" + sourceKey + "' declares defaultSort '" + defSortKey
                                + "', which does not match any LookupSortOption.key() in " + prefix + ".sortOptions.",
                        "Align defaultSort with a declared LookupSortOption.key() in " + prefix + ".sortOptions for '" + sourceKey + "'."
                ));
            }
        }
        if (filtering.quickFilterFields() != null) {
            for (String quickField : filtering.quickFilterFields()) {
                auditOptionSourcePath(
                        issues, resourceKey, serviceName, sourceKey,
                        prefix + ".quickFilterFields",
                        quickField,
                        checkEntity, entityClass, checkDto, responseType, checkFilterDto, filterDtoClass, true,
                        responseContract, spec, restrictedAttrs, queryRestrictedAttrs
                );
            }
        }
    }

    private static void auditOptionSourcePath(
            List<ReadinessIssue> issues,
            String resourceKey,
            String serviceName,
            String sourceKey,
            String roleLabel,
            String rawPath,
            boolean checkEntity,
            Class<?> entityClass,
            boolean checkDto,
            Class<?> responseType,
            boolean checkFilterDto,
            Class<?> filterDtoClass,
            boolean isQueryOrSortPath,
            IntrospectedDtoGovernanceContract responseContract,
            AuthzResourceGovernanceSpec<?> spec,
            Set<String> restrictedAttrs,
            Set<String> queryRestrictedAttrs
    ) {
        if (rawPath == null || rawPath.isBlank()) {
            return;
        }
        String path = rawPath.trim();
        String targetLabel = sourceKey + "." + roleLabel + "(" + path + ")";
        if (checkEntity || checkDto || checkFilterDto) {
            boolean validOnEntity = checkEntity && isValidStatsEntityPath(entityClass, path, spec);
            boolean validOnDto = checkDto && isValidEntityPropertyPath(responseType, path);
            boolean validOnFilterDto = checkFilterDto && isValidEntityPropertyPath(filterDtoClass, path);
            if (!validOnEntity && !validOnDto && !validOnFilterDto) {
                issues.add(new ReadinessIssue(
                        "AUTHZ-HOST-014-INVALID-OPTION-SOURCE-PATH",
                        Severity.ERROR,
                        resourceKey,
                        serviceName,
                        targetLabel,
                        "OptionSource '" + sourceKey + "' property path '" + path + "' (" + roleLabel
                                + ") does not resolve on JPA entity, ResponseDTO, or FilterDTO.",
                        "Fix '" + path + "' in OptionSourceDescriptor / EntityLookupDescriptor / LookupFilteringDescriptor for '" + sourceKey + "'."
                ));
            }
        }
        boolean valueDenied = resolvesToValueDeniedAttribute(path, responseContract, spec, restrictedAttrs)
                || (checkFilterDto && isFilterDtoPropertyRestricted(filterDtoClass, path, responseContract, spec, restrictedAttrs));
        if (valueDenied) {
            issues.add(new ReadinessIssue(
                    "AUTHZ-HOST-014-VALUE-DENIED-OPTION-SOURCE-FIELD",
                    Severity.ERROR,
                    resourceKey,
                    serviceName,
                    targetLabel,
                    "OptionSource '" + sourceKey + "' exposes a VALUE-denied attribute (SECRET / CREDENTIAL) via '"
                            + path + "' (" + roleLabel + ").",
                    "Remove '" + path + "' from OptionSourceDescriptor / EntityLookupDescriptor / LookupFilteringDescriptor for '" + sourceKey + "'."
            ));
            return;
        }
        if (isQueryOrSortPath
                && (resolvesToValueDeniedAttribute(path, responseContract, spec, queryRestrictedAttrs)
                        || (checkFilterDto && isFilterDtoPropertyRestricted(filterDtoClass, path, responseContract, spec, queryRestrictedAttrs)))) {
            issues.add(new ReadinessIssue(
                    "AUTHZ-HOST-014-RESTRICTED-OPTION-SOURCE-QUERY-FIELD",
                    Severity.ERROR,
                    resourceKey,
                    serviceName,
                    targetLabel,
                    "OptionSource '" + sourceKey + "' binds query/filter/sort role '" + roleLabel + "' to '"
                            + path + "', which is statically restricted for FILTER/SORT (LGPD_SENSITIVE_DATA / RESTRICTED) and will fail closed at runtime.",
                    "Remove '" + path + "' from lookup filtering/search/sort options in '" + sourceKey + "'."
            ));
        }
    }

    private static boolean isFilterDtoPropertyRestricted(
            Class<?> filterDtoClass,
            String propName,
            IntrospectedDtoGovernanceContract responseContract,
            AuthzResourceGovernanceSpec<?> spec,
            Set<String> targetAttrs
    ) {
        if (filterDtoClass == null || propName == null || propName.isBlank()
                || targetAttrs == null || targetAttrs.isEmpty()) {
            return false;
        }
        List<java.lang.reflect.AnnotatedElement> elements = new ArrayList<>();
        if (filterDtoClass.isRecord() && filterDtoClass.getRecordComponents() != null) {
            for (RecordComponent rc : filterDtoClass.getRecordComponents()) {
                if (propName.equals(rc.getName())) {
                    elements.add(rc);
                    if (rc.getAccessor() != null) {
                        elements.add(rc.getAccessor());
                    }
                }
            }
        }
        for (Class<?> curr = filterDtoClass; curr != null && curr != Object.class; curr = curr.getSuperclass()) {
            try {
                Field f = curr.getDeclaredField(propName);
                elements.add(f);
            } catch (NoSuchFieldException ignored) {
                // continue
            }
            for (Method m : curr.getDeclaredMethods()) {
                if (m.getParameterCount() == 0 && (propName.equals(m.getName()) || isMatchingGetter(m.getName(), propName))) {
                    elements.add(m);
                }
            }
        }
        for (java.lang.reflect.AnnotatedElement el : elements) {
            org.praxisplatform.uischema.annotation.DomainLineage dl =
                    AnnotatedElementUtils.findMergedAnnotation(el, org.praxisplatform.uischema.annotation.DomainLineage.class);
            if (dl != null && dl.attributeId() != null && !dl.attributeId().isBlank()
                    && resolvesToValueDeniedAttribute(dl.attributeId().trim(), responseContract, spec, targetAttrs)) {
                return true;
            }
            Filterable f = AnnotatedElementUtils.findMergedAnnotation(el, Filterable.class);
            if (f != null) {
                if (f.relation() != null && !f.relation().isBlank()
                        && resolvesToValueDeniedAttribute(f.relation().trim(), responseContract, spec, targetAttrs)) {
                    return true;
                }
                if (f.relations() != null) {
                    for (String rel : f.relations()) {
                        if (rel != null && !rel.isBlank()
                                && resolvesToValueDeniedAttribute(rel.trim(), responseContract, spec, targetAttrs)) {
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }

    private static void auditExportFields(
            List<ReadinessIssue> issues,
            String resourceKey,
            String serviceName,
            Class<?> responseType,
            List<org.praxisplatform.uischema.exporting.CollectionExportField> rawExportFields,
            IntrospectedDtoGovernanceContract responseContract,
            AuthzResourceGovernanceSpec<?> spec,
            Set<String> restrictedAttrs
    ) {
        boolean checkDto = responseType != null && responseType != Object.class && !Map.class.isAssignableFrom(responseType);
        Set<String> nonExportable = responseContract != null && responseContract.nonExportableFieldNames() != null
                ? responseContract.nonExportableFieldNames()
                : Set.of();
        for (org.praxisplatform.uischema.exporting.CollectionExportField field : rawExportFields) {
            if (field == null) {
                continue;
            }
            String key = field.key() != null ? field.key().trim() : "";
            String valuePath = (field.valuePath() != null && !field.valuePath().isBlank())
                    ? field.valuePath().trim()
                    : key;
            String labelForTarget = !key.isEmpty() ? key : valuePath;
            if (checkDto && !valuePath.isEmpty() && !isValidEntityPropertyPath(responseType, valuePath)) {
                issues.add(new ReadinessIssue(
                        "AUTHZ-HOST-013-INVALID-EXPORT-FIELD-PATH",
                        Severity.ERROR,
                        resourceKey,
                        serviceName,
                        labelForTarget + " (valuePath=" + valuePath + ")",
                        "CollectionExportField '" + labelForTarget + "' valuePath '" + valuePath
                                + "' does not resolve to a valid property path on ResponseDTO '" + responseType.getSimpleName() + "'.",
                        "Fix key/valuePath in defineRawExportFields() to reference a valid property on " + responseType.getSimpleName() + "."
                ));
            }
            String mappedAttrFromKey = responseContract != null
                    ? responseContract.wirePointerToAttributeIdMap().get("/" + key)
                    : null;
            String mappedAttrFromPath = responseContract != null
                    ? responseContract.wirePointerToAttributeIdMap().get("/" + valuePath)
                    : null;
            if ((!key.isEmpty() && nonExportable.contains(key))
                    || (!valuePath.isEmpty() && nonExportable.contains(valuePath))
                    || (mappedAttrFromKey != null && nonExportable.contains(mappedAttrFromKey))
                    || (mappedAttrFromPath != null && nonExportable.contains(mappedAttrFromPath))) {
                issues.add(new ReadinessIssue(
                        "AUTHZ-HOST-013-NON-EXPORTABLE-FIELD-IN-EXPORT-ALLOWLIST",
                        Severity.WARNING,
                        resourceKey,
                        serviceName,
                        labelForTarget,
                        "CollectionExportField '" + labelForTarget + "' is declared in defineRawExportFields(), "
                                + "but is governed with @DomainGovernance(exportable = false) on ResponseDTO '"
                                + (responseType != null ? responseType.getSimpleName() : "") + "'.",
                        "Remove '" + labelForTarget + "' from defineRawExportFields() or allow export in @DomainGovernance."
                ));
            }
            if (resolvesToValueDeniedAttribute(key, responseContract, spec, restrictedAttrs)
                    || resolvesToValueDeniedAttribute(valuePath, responseContract, spec, restrictedAttrs)) {
                issues.add(new ReadinessIssue(
                        "AUTHZ-HOST-013-VALUE-DENIED-EXPORT-FIELD",
                        Severity.ERROR,
                        resourceKey,
                        serviceName,
                        labelForTarget,
                        "CollectionExportField '" + labelForTarget + "' exposes a VALUE-denied attribute (SECRET / CREDENTIAL) in collection export.",
                        "Remove '" + labelForTarget + "' from defineRawExportFields() and mark it @DomainGovernance(exportable = false)."
                ));
            }
        }
    }

    private static void auditStatsFieldRegistry(
            List<ReadinessIssue> issues,
            String resourceKey,
            String serviceName,
            Class<?> entityClass,
            StatsFieldRegistry rawStatsRegistry,
            IntrospectedDtoGovernanceContract responseContract,
            AuthzResourceGovernanceSpec<?> spec,
            Set<String> restrictedAttrs
    ) {
        boolean checkEntity = entityClass != null && entityClass != Object.class && !Map.class.isAssignableFrom(entityClass);
        for (StatsFieldDescriptor desc : rawStatsRegistry.descriptors()) {
            if (desc == null || desc.field() == null || desc.field().isBlank()) {
                continue;
            }
            String field = desc.field().trim();
            if (checkEntity) {
                if (!isValidStatsEntityPath(entityClass, field, spec)) {
                    issues.add(new ReadinessIssue(
                            "AUTHZ-HOST-011-INVALID-STATS-ENTITY-PATH",
                            Severity.ERROR,
                            resourceKey,
                            serviceName,
                            field,
                            "StatsFieldDescriptor for '" + field + "' does not resolve to a valid JPA property path on entity '"
                                    + entityClass.getSimpleName() + "' or in AuthzResourceGovernanceSpec.fieldBindings().",
                            "Update defineRawStatsFieldRegistry() or add a QueryAdapterFieldBinding in AuthzResourceGovernanceSpec for '"
                                    + field + "'."
                    ));
                }
                if (desc.keyPropertyPath() != null && !desc.keyPropertyPath().isBlank()
                        && !isValidStatsEntityPath(entityClass, desc.keyPropertyPath().trim(), spec)) {
                    issues.add(new ReadinessIssue(
                            "AUTHZ-HOST-011-INVALID-STATS-ENTITY-PATH",
                            Severity.ERROR,
                            resourceKey,
                            serviceName,
                            field + " (keyPropertyPath=" + desc.keyPropertyPath().trim() + ")",
                            "StatsFieldDescriptor '" + field + "' keyPropertyPath '" + desc.keyPropertyPath().trim()
                                    + "' does not resolve to a valid JPA property path on entity '" + entityClass.getSimpleName() + "'.",
                            "Fix keyPropertyPath in defineRawStatsFieldRegistry() for '" + field + "'."
                    ));
                }
                if (desc.labelPropertyPath() != null && !desc.labelPropertyPath().isBlank()
                        && !isValidStatsEntityPath(entityClass, desc.labelPropertyPath().trim(), spec)) {
                    issues.add(new ReadinessIssue(
                            "AUTHZ-HOST-011-INVALID-STATS-ENTITY-PATH",
                            Severity.ERROR,
                            resourceKey,
                            serviceName,
                            field + " (labelPropertyPath=" + desc.labelPropertyPath().trim() + ")",
                            "StatsFieldDescriptor '" + field + "' labelPropertyPath '" + desc.labelPropertyPath().trim()
                                    + "' does not resolve to a valid JPA property path on entity '" + entityClass.getSimpleName() + "'.",
                            "Fix labelPropertyPath in defineRawStatsFieldRegistry() for '" + field + "'."
                    ));
                }
            }
            if (resolvesToValueDeniedAttribute(field, responseContract, spec, restrictedAttrs)
                    || resolvesToValueDeniedAttribute(desc.keyPropertyPath(), responseContract, spec, restrictedAttrs)
                    || resolvesToValueDeniedAttribute(desc.labelPropertyPath(), responseContract, spec, restrictedAttrs)) {
                issues.add(new ReadinessIssue(
                        "AUTHZ-HOST-011-VALUE-DENIED-STATS-FIELD",
                        Severity.ERROR,
                        resourceKey,
                        serviceName,
                        field,
                        "StatsFieldDescriptor '" + field + "' exposes a VALUE-denied attribute (SECRET / CREDENTIAL) in analytics group-by/metrics.",
                        "Remove '" + field + "' from defineRawStatsFieldRegistry() so secret/credential attributes cannot be aggregated or grouped."
                ));
            }
        }
    }

    private static boolean isValidStatsEntityPath(
            Class<?> entityClass,
            String path,
            AuthzResourceGovernanceSpec<?> spec
    ) {
        if (isValidEntityPropertyPath(entityClass, path)) {
            return true;
        }
        if (spec != null && spec.fieldBindings() != null) {
            for (QueryAdapterFieldBinding binding : spec.fieldBindings()) {
                if ((path.equals(binding.fieldPath())
                                || path.equals(binding.attributeId())
                                || ("resource." + path).equals(binding.fieldPath()))
                        && isValidEntityPropertyPath(entityClass, binding.nativeJpaPath())) {
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean resolvesToValueDeniedAttribute(
            String rawPath,
            IntrospectedDtoGovernanceContract responseContract,
            AuthzResourceGovernanceSpec<?> spec,
            Set<String> restrictedAttrs
    ) {
        if (rawPath == null || rawPath.isBlank() || restrictedAttrs == null || restrictedAttrs.isEmpty()) {
            return false;
        }
        String clean = rawPath.trim();
        if (clean.startsWith("/")) {
            clean = clean.substring(1);
        }
        if (clean.startsWith("e.")) {
            clean = clean.substring(2);
        }
        if (restrictedAttrs.contains(clean)) {
            return true;
        }
        if (responseContract != null) {
            String mapped = responseContract.wirePointerToAttributeIdMap().get("/" + clean);
            if (mapped != null && restrictedAttrs.contains(mapped)) {
                return true;
            }
        }
        int lastSep = Math.max(clean.lastIndexOf('.'), clean.lastIndexOf('/'));
        if (lastSep >= 0 && lastSep + 1 < clean.length()) {
            String leaf = clean.substring(lastSep + 1);
            if (restrictedAttrs.contains(leaf)) {
                return true;
            }
            if (responseContract != null) {
                String leafMapped = responseContract.wirePointerToAttributeIdMap().get("/" + leaf);
                if (leafMapped != null && restrictedAttrs.contains(leafMapped)) {
                    return true;
                }
            }
        }
        if (spec != null && spec.fieldBindings() != null) {
            for (QueryAdapterFieldBinding binding : spec.fieldBindings()) {
                if (clean.equals(binding.fieldPath())
                        || clean.equals(binding.nativeJpaPath())
                        || clean.equals(binding.attributeId())
                        || ("resource." + clean).equals(binding.fieldPath())) {
                    if (restrictedAttrs.contains(binding.attributeId())
                            || restrictedAttrs.contains(binding.fieldPath())) {
                        return true;
                    }
                    if (responseContract != null) {
                        String boundMapped = responseContract.wirePointerToAttributeIdMap().get("/" + binding.fieldPath());
                        if (boundMapped != null && restrictedAttrs.contains(boundMapped)) {
                            return true;
                        }
                        String attrMapped = responseContract.wirePointerToAttributeIdMap().get("/" + binding.attributeId());
                        if (attrMapped != null && restrictedAttrs.contains(attrMapped)) {
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }

    private void verifyDecisionPointInCoordinates(
            List<ReadinessIssue> issues,
            String resourceKey,
            String serviceName,
            DecisionPointDescriptor dp
    ) {
        String pointKey = dp.identity().pointKey();
        boolean inBindingsMap = coordinates.bindingsByPointKey().containsKey(pointKey);
        boolean inHostManifest = coordinates.hostManifest().decisionPointBindings().stream()
                .anyMatch(e -> pointKey.equals(e.pointKey()));
        boolean inImpactBaseline = coordinates.impactBaseline().impactedPointKeys().contains(pointKey);
        if (!inBindingsMap || !inHostManifest || !inImpactBaseline) {
            issues.add(new ReadinessIssue(
                    "AUTHZ-HOST-010-MISSING-COORDINATES-BINDING",
                    Severity.ERROR,
                    resourceKey,
                    serviceName,
                    pointKey,
                    "Decision point '" + pointKey + "' is missing from HostRuntimePolicyCoordinates (bindingsByPointKey="
                            + inBindingsMap + ", hostManifest=" + inHostManifest + ", impactBaseline=" + inImpactBaseline + ").",
                    "Include the governed resource or service in AuthzHostPolicyBootstrapBuilder so all primary, action, and surface decision points are bound in HostRuntimePolicyCoordinates."
            ));
        }
    }

    private static int sensitivityRank(String classification) {
        if (classification == null) {
            return 0;
        }
        return switch (classification.trim().toUpperCase()) {
            case "SECRET", "HEALTH_SENSITIVE", "SENSITIVE_PERSONAL" -> 4;
            case "PII_RESTRICTED", "FINANCIAL_RESTRICTED", "RESTRICTED" -> 3;
            case "OPERATIONAL_INTERNAL", "INTERNAL" -> 2;
            default -> 1;
        };
    }

    private static void checkDeterminationPointer(
            List<ReadinessIssue> issues,
            String resourceKey,
            String serviceName,
            String determinationId,
            String role,
            boolean isInputOrSource,
            String jsonPointer,
            IntrospectedDtoGovernanceContract responseContract,
            Set<String> restrictedAttrs,
            Set<String> sensitiveAttrs
    ) {
        if (jsonPointer == null || jsonPointer.isBlank()) {
            return;
        }
        String mappedAttr = responseContract.wirePointerToAttributeIdMap().get(jsonPointer);
        String fieldName = jsonPointer.startsWith("/") ? jsonPointer.substring(1) : jsonPointer;
        int lastSlash = jsonPointer.lastIndexOf('/');
        String leafName = lastSlash >= 0 ? jsonPointer.substring(lastSlash + 1) : fieldName;
        String leafMappedAttr = responseContract.wirePointerToAttributeIdMap().get("/" + leafName);
        if ((mappedAttr != null && restrictedAttrs.contains(mappedAttr))
                || (leafMappedAttr != null && restrictedAttrs.contains(leafMappedAttr))
                || restrictedAttrs.contains(fieldName)
                || restrictedAttrs.contains(leafName)) {
            issues.add(new ReadinessIssue(
                    "AUTHZ-HOST-008-RESTRICTED-DETERMINATION-BINDING",
                    Severity.ERROR,
                    resourceKey,
                    serviceName,
                    determinationId + " -> " + jsonPointer,
                    "Reactive determination '" + determinationId + "' binds " + role + " '" + jsonPointer
                            + "' to a VALUE-denied attribute.",
                    "Remove VALUE-denied fields (SECRET / CREDENTIAL) from defineReactiveDeterminations() bindings."
            ));
            return;
        }
        if (isInputOrSource
                && ((mappedAttr != null && sensitiveAttrs.contains(mappedAttr))
                        || (leafMappedAttr != null && sensitiveAttrs.contains(leafMappedAttr))
                        || sensitiveAttrs.contains(fieldName)
                        || sensitiveAttrs.contains(leafName))) {
            issues.add(new ReadinessIssue(
                    "AUTHZ-HOST-008-SENSITIVE-DETERMINATION-INPUT",
                    Severity.WARNING,
                    resourceKey,
                    serviceName,
                    determinationId + " -> " + jsonPointer,
                    "Reactive determination '" + determinationId + "' binds " + role + " '" + jsonPointer
                            + "' to an LGPD-sensitive / maskable attribute, risking client-side masked placeholder strings ('***') being sent as determination inputs.",
                    "Avoid using masked/sensitive fields as client-side determination inputs; resolve sensitive inputs server-side via evaluateGovernedItemDetermination."
            ));
        }
    }

    private void verifyDecisionPointInRegistry(
            List<ReadinessIssue> issues,
            String resourceKey,
            String serviceName,
            DecisionPointDescriptor dp,
            String expectedFactDigest
    ) {
        String pointKey = dp.identity().pointKey();
        Optional<RegisteredDecisionPointContext> registered = decisionPointRegistry.findRegisteredPoint(pointKey);
        if (registered.isEmpty()) {
            issues.add(new ReadinessIssue(
                    "AUTHZ-HOST-007-UNREGISTERED-DECISION-POINT",
                    Severity.ERROR,
                    resourceKey,
                    serviceName,
                    pointKey,
                    "Decision point '" + pointKey + "' is not registered in RuntimeDecisionPointRegistry.",
                    "Register a MethodBindingAdmissionRecord for '" + pointKey + "' in the host's authorization blueprint."
            ));
            return;
        }
        String registeredDigest = registered.get().factContract().factContractDigest();
        if (expectedFactDigest != null && !expectedFactDigest.equals(registeredDigest)) {
            issues.add(new ReadinessIssue(
                    "AUTHZ-HOST-007-FACT-DIGEST-MISMATCH",
                    Severity.ERROR,
                    resourceKey,
                    serviceName,
                    pointKey,
                    "Service expects FactContract digest '" + expectedFactDigest + "' for decision point '"
                            + pointKey + "', but RuntimeDecisionPointRegistry has '" + registeredDigest + "'.",
                    "Synchronize the service's factContractDigest with the admitted FactContract in HostRuntimePolicyCoordinates."
            ));
        }
    }

    private static void checkEntityPath(
            List<ReadinessIssue> issues,
            String resourceKey,
            String serviceName,
            Class<?> entityClass,
            String configProperty,
            String propertyPath
    ) {
        if (!isValidEntityPropertyPath(entityClass, propertyPath)) {
            issues.add(new ReadinessIssue(
                    "AUTHZ-HOST-006-INVALID-ENTITY-FIELD-PATH",
                    Severity.ERROR,
                    resourceKey,
                    serviceName,
                    configProperty + "=" + propertyPath,
                    "Configured " + configProperty + " '" + propertyPath + "' does not resolve to a field or getter on entity '"
                            + entityClass.getSimpleName() + "'.",
                    "Update " + configProperty + " in AuthzResourceGovernanceSpec to match a valid property on " + entityClass.getSimpleName() + "."
            ));
        }
    }

    private static void auditFilterDtoEntityPaths(
            List<ReadinessIssue> issues,
            String resourceKey,
            String serviceName,
            Class<?> entityClass,
            Class<?> filterDtoClass,
            IntrospectedDtoGovernanceContract responseContract,
            AuthzResourceGovernanceSpec<?> spec,
            Set<String> restrictedAttrs
    ) {
        Map<String, Filterable> filterablesByProperty = new LinkedHashMap<>();
        Map<String, List<java.lang.reflect.AnnotatedElement>> elementsByProperty = new LinkedHashMap<>();
        if (filterDtoClass.isRecord() && filterDtoClass.getRecordComponents() != null) {
            for (RecordComponent rc : filterDtoClass.getRecordComponents()) {
                List<java.lang.reflect.AnnotatedElement> els =
                        elementsByProperty.computeIfAbsent(rc.getName(), k -> new ArrayList<>());
                els.add(rc);
                if (rc.getAccessor() != null) {
                    els.add(rc.getAccessor());
                }
                Filterable f = AnnotatedElementUtils.findMergedAnnotation(rc, Filterable.class);
                if (f == null && rc.getAccessor() != null) {
                    f = AnnotatedElementUtils.findMergedAnnotation(rc.getAccessor(), Filterable.class);
                }
                if (f != null) {
                    filterablesByProperty.putIfAbsent(rc.getName(), f);
                }
            }
        }
        for (Class<?> curr = filterDtoClass; curr != null && curr != Object.class; curr = curr.getSuperclass()) {
            for (Field field : curr.getDeclaredFields()) {
                if (java.lang.reflect.Modifier.isStatic(field.getModifiers()) || field.isSynthetic()) {
                    continue;
                }
                elementsByProperty.computeIfAbsent(field.getName(), k -> new ArrayList<>()).add(field);
                Filterable f = AnnotatedElementUtils.findMergedAnnotation(field, Filterable.class);
                if (f != null) {
                    filterablesByProperty.putIfAbsent(field.getName(), f);
                }
            }
            for (Method method : curr.getDeclaredMethods()) {
                if (method.getParameterCount() != 0 || java.lang.reflect.Modifier.isStatic(method.getModifiers())) {
                    continue;
                }
                String mName = method.getName();
                String propName = (mName.startsWith("get") && mName.length() > 3 && Character.isUpperCase(mName.charAt(3)))
                        ? Introspector.decapitalize(mName.substring(3))
                        : mName;
                elementsByProperty.computeIfAbsent(propName, k -> new ArrayList<>()).add(method);
                Filterable f = AnnotatedElementUtils.findMergedAnnotation(method, Filterable.class);
                if (f != null) {
                    filterablesByProperty.putIfAbsent(propName, f);
                }
            }
        }

        boolean checkEntity = entityClass != null && entityClass != Object.class && !Map.class.isAssignableFrom(entityClass);
        for (Map.Entry<String, Filterable> entry : filterablesByProperty.entrySet()) {
            String propName = entry.getKey();
            Filterable filterable = entry.getValue();
            List<String> candidateEntityPaths = new ArrayList<>();
            if (filterable.relations() != null && filterable.relations().length > 0) {
                for (String rel : filterable.relations()) {
                    if (rel != null && !rel.isBlank()) {
                        candidateEntityPaths.add(rel.trim());
                    }
                }
            } else if (filterable.relation() != null && !filterable.relation().isBlank()) {
                candidateEntityPaths.add(filterable.relation().trim());
            } else {
                candidateEntityPaths.add(propName);
            }
            boolean valueDenied = resolvesToValueDeniedAttribute(propName, responseContract, spec, restrictedAttrs);
            for (java.lang.reflect.AnnotatedElement el : elementsByProperty.getOrDefault(propName, List.of())) {
                org.praxisplatform.uischema.annotation.DomainLineage dl =
                        AnnotatedElementUtils.findMergedAnnotation(el, org.praxisplatform.uischema.annotation.DomainLineage.class);
                if (dl != null && dl.attributeId() != null && !dl.attributeId().isBlank()
                        && resolvesToValueDeniedAttribute(dl.attributeId().trim(), responseContract, spec, restrictedAttrs)) {
                    valueDenied = true;
                }
                org.praxisplatform.uischema.annotation.DomainGovernance dg =
                        AnnotatedElementUtils.findMergedAnnotation(el, org.praxisplatform.uischema.annotation.DomainGovernance.class);
                if (dg != null && dg.dataCategory() == org.praxisplatform.uischema.annotation.DomainDataCategory.CREDENTIAL) {
                    valueDenied = true;
                }
            }
            for (String entityPath : candidateEntityPaths) {
                if (checkEntity && !isValidEntityPropertyPath(entityClass, entityPath)) {
                    issues.add(new ReadinessIssue(
                            "AUTHZ-HOST-006-INVALID-FILTERABLE-ENTITY-PATH",
                            Severity.ERROR,
                            resourceKey,
                            serviceName,
                            filterDtoClass.getSimpleName() + "." + propName + " -> " + entityPath,
                            "@Filterable property '" + propName + "' on '" + filterDtoClass.getSimpleName()
                                    + "' references JPA entity path '" + entityPath
                                    + "' which does not exist on entity '" + entityClass.getSimpleName() + "'.",
                            "Fix @Filterable(relation/relations = ...) on " + filterDtoClass.getSimpleName() + "."
                                    + propName + " to reference a valid property path on " + entityClass.getSimpleName() + "."
                    ));
                }
                if (resolvesToValueDeniedAttribute(entityPath, responseContract, spec, restrictedAttrs)) {
                    valueDenied = true;
                }
            }
            if (valueDenied) {
                issues.add(new ReadinessIssue(
                        "AUTHZ-HOST-012-VALUE-DENIED-FILTERABLE-FIELD",
                        Severity.ERROR,
                        resourceKey,
                        serviceName,
                        filterDtoClass.getSimpleName() + "." + propName,
                        "@Filterable property '" + propName + "' on '" + filterDtoClass.getSimpleName()
                                + "' exposes a VALUE-denied attribute (SECRET / CREDENTIAL) to filter predicates, enabling side-channel oracle inference.",
                        "Remove @Filterable from '" + propName + "' on " + filterDtoClass.getSimpleName()
                                + " or reclassify the attribute if filtering is legitimately permitted by domain governance."
                ));
            }
        }
    }

    static boolean isValidEntityPropertyPath(Class<?> rootEntityClass, String rawPath) {
        if (rootEntityClass == null || rawPath == null || rawPath.isBlank()) {
            return false;
        }
        String cleanPath = rawPath.trim();
        if (cleanPath.startsWith("e.")) {
            cleanPath = cleanPath.substring(2);
        }
        if (cleanPath.isEmpty()) {
            return false;
        }
        String[] segments = cleanPath.split("\\.");
        Class<?> currentClass = rootEntityClass;
        for (String segment : segments) {
            if (currentClass == null || currentClass == Object.class || Map.class.isAssignableFrom(currentClass)) {
                return true;
            }
            Class<?> nextType = resolveSinglePropertySegmentType(currentClass, segment);
            if (nextType == null) {
                return false;
            }
            currentClass = nextType;
        }
        return true;
    }

    private static Class<?> resolveSinglePropertySegmentType(Class<?> ownerClass, String propertyName) {
        if (ownerClass.isRecord() && ownerClass.getRecordComponents() != null) {
            for (RecordComponent rc : ownerClass.getRecordComponents()) {
                if (propertyName.equals(rc.getName())) {
                    return unwrapCollectionElementType(
                            ResolvableType.forMethodReturnType(rc.getAccessor(), ownerClass),
                            rc.getType()
                    );
                }
            }
        }
        for (Class<?> curr = ownerClass; curr != null && curr != Object.class; curr = curr.getSuperclass()) {
            try {
                Field f = curr.getDeclaredField(propertyName);
                return unwrapCollectionElementType(ResolvableType.forField(f, ownerClass), f.getType());
            } catch (NoSuchFieldException ignored) {
                // continue
            }
            for (Method m : curr.getDeclaredMethods()) {
                if (m.getParameterCount() != 0 || m.getReturnType() == void.class) {
                    continue;
                }
                String mName = m.getName();
                if (propertyName.equals(mName) || isMatchingGetter(mName, propertyName)) {
                    return unwrapCollectionElementType(
                            ResolvableType.forMethodReturnType(m, ownerClass),
                            m.getReturnType()
                    );
                }
            }
        }
        for (Class<?> iface : ClassUtils.getAllInterfacesForClass(ownerClass)) {
            for (Method m : iface.getDeclaredMethods()) {
                if (m.getParameterCount() != 0 || m.getReturnType() == void.class) {
                    continue;
                }
                String mName = m.getName();
                if (propertyName.equals(mName) || isMatchingGetter(mName, propertyName)) {
                    return unwrapCollectionElementType(
                            ResolvableType.forMethodReturnType(m, ownerClass),
                            m.getReturnType()
                    );
                }
            }
        }
        return null;
    }

    private static boolean isMatchingGetter(String methodName, String propertyName) {
        if (methodName.startsWith("get") && methodName.length() > 3 && Character.isUpperCase(methodName.charAt(3))) {
            return propertyName.equals(Introspector.decapitalize(methodName.substring(3)));
        }
        if (methodName.startsWith("is") && methodName.length() > 2 && Character.isUpperCase(methodName.charAt(2))) {
            return propertyName.equals(Introspector.decapitalize(methodName.substring(2)));
        }
        return false;
    }

    private static Class<?> unwrapCollectionElementType(ResolvableType resolvableType, Class<?> rawType) {
        if (rawType != null && Collection.class.isAssignableFrom(rawType)) {
            Class<?> elem = resolvableType.asCollection().getGeneric(0).resolve();
            return elem != null ? elem : Object.class;
        }
        return rawType;
    }

    private static String safeResolveResourceKey( java.util.function.Supplier<String> supplier) {
        try {
            return supplier.get();
        } catch (RuntimeException ex) {
            return "<unknown>";
        }
    }
}
