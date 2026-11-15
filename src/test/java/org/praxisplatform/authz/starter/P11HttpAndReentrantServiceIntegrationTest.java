package org.praxisplatform.authz.starter;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EntityManager;
import jakarta.persistence.FetchType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Root;
import java.lang.reflect.Field;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Properties;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Predicate;
import org.hibernate.jpa.HibernatePersistenceProvider;
import org.junit.jupiter.api.Test;
import org.praxisplatform.authz.contracts.binding.WriteIntent;
import org.praxisplatform.authz.contracts.context.FactValueType;
import org.praxisplatform.authz.contracts.context.ProviderInputProjection;
import org.praxisplatform.authz.contracts.context.ResolvedFactValue;
import org.praxisplatform.authz.contracts.datascope.ComparisonPredicateIr;
import org.praxisplatform.authz.contracts.datascope.DataScopeOutcome;
import org.praxisplatform.authz.contracts.datascope.DataScopePlan;
import org.praxisplatform.authz.contracts.datascope.LiteralOperandIr;
import org.praxisplatform.authz.contracts.datascope.LogicalPredicateIr;
import org.praxisplatform.authz.contracts.datascope.NullabilityPredicateIr;
import org.praxisplatform.authz.contracts.datascope.PushdownMode;
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
import org.praxisplatform.authz.contracts.envelope.FieldUseEffectDirective;
import org.praxisplatform.authz.contracts.envelope.FieldWriteEffectDirective;
import org.praxisplatform.authz.contracts.envelope.GateOutcome;
import org.praxisplatform.authz.contracts.envelope.MaskDirective;
import org.praxisplatform.authz.contracts.envelope.ObligationDirective;
import org.praxisplatform.authz.contracts.envelope.ProviderEvaluationEnvelope;
import org.praxisplatform.authz.contracts.envelope.RuleEffect;
import org.praxisplatform.authz.enforcement.fielduse.FieldUseQueryGuard;
import org.praxisplatform.authz.enforcement.jpa.JpaDataScopeAdapter;
import org.praxisplatform.authz.enforcement.jpa.QueryAdapterFieldBinding;
import org.praxisplatform.authz.enforcement.jpa.RelationTraversalStrategy;
import org.praxisplatform.authz.enforcement.masking.DetachedDtoMaskingProcessor;
import org.praxisplatform.authz.contracts.obligation.DefaultObligationHandlerRegistry;
import org.praxisplatform.authz.enforcement.obligation.ObligationBarrierCoordinator;
import org.praxisplatform.authz.enforcement.pipeline.AuthorizationProviderPort;
import org.praxisplatform.authz.enforcement.writeintent.DtoWriteIntentExtractor;
import org.praxisplatform.authz.enforcement.writeintent.FieldWriteAuthorizer;
import org.praxisplatform.authz.host.metadata.AbstractAuthzGovernedResourceService;
import org.praxisplatform.authz.host.metadata.AuthzCallerContext;
import org.praxisplatform.authz.host.metadata.AuthzCallerContextFilter;
import org.praxisplatform.authz.host.metadata.AuthzCallerContextHttpResolver;
import org.praxisplatform.authz.host.metadata.AuthzCallerContextProvider;
import org.praxisplatform.authz.host.metadata.AuthzGovernedResourceServiceSupport;
import org.praxisplatform.authz.host.metadata.AuthzResourceGovernanceSpec;
import org.praxisplatform.authz.host.metadata.JpaCriteriaDataScopeTranslator;
import org.praxisplatform.authz.host.metadata.MetadataDtoGovernanceIntrospector;
import org.praxisplatform.authz.host.metadata.PraxisAuthzExceptionHandler;
import org.praxisplatform.authz.host.metadata.ThreadLocalAuthzCallerContextProvider;
import org.praxisplatform.authz.outbox.JdbcTransactionalAuditOutbox;
import org.praxisplatform.authz.seams.MetadataResourceAuthorizationSeam;
import org.praxisplatform.uischema.annotation.DomainClassification;
import org.praxisplatform.uischema.annotation.DomainDataCategory;
import org.praxisplatform.uischema.annotation.DomainGovernance;
import org.praxisplatform.uischema.annotation.DomainLineage;
import org.praxisplatform.uischema.stats.StatsProperties;
import org.praxisplatform.uischema.filter.annotation.Filterable;
import org.praxisplatform.uischema.filter.dto.GenericFilterDTO;
import org.praxisplatform.uischema.mapper.base.ResourceMapper;
import org.praxisplatform.uischema.repository.base.BaseCrudRepository;
import org.praxisplatform.uischema.service.base.AbstractBaseQueryResourceService;
import org.praxisplatform.uischema.service.base.ResourceFilterAccessScope;
import org.praxisplatform.uischema.stats.DistributionMode;
import org.praxisplatform.uischema.stats.StatsBucketOrder;
import org.praxisplatform.uischema.stats.StatsFieldDescriptor;
import org.praxisplatform.uischema.stats.StatsFieldRegistry;
import org.praxisplatform.uischema.stats.StatsMetric;
import org.praxisplatform.uischema.stats.StatsSupportMode;
import org.praxisplatform.uischema.stats.dto.DistributionStatsRequest;
import org.praxisplatform.uischema.stats.dto.DistributionStatsResponse;
import org.praxisplatform.uischema.stats.dto.StatsMetricRequest;
import org.praxisplatform.uischema.stats.service.jpa.JpaStatsQueryExecutor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.jpa.repository.support.JpaRepositoryFactory;
import org.springframework.http.MediaType;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.orm.jpa.SharedEntityManagerCreator;
import org.springframework.orm.jpa.vendor.HibernateJpaVendorAdapter;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * End-to-end integration test suite for Phase {@code P11} and Phase {@code P12} ({@code C-01..C-05}):
 * <ol>
 *   <li>Real {@code MockMvc} + {@link AuthzCallerContextFilter} + {@link PraxisAuthzExceptionHandler}
 *       HTTP status mappings ({@code 200}, {@code 401}, {@code 403}, {@code 503}) including
 *       {@link DistributionMode#HISTOGRAM} {@code AGGREGATE} guard and {@link DataScopeOutcome#NONE};</li>
 *   <li>Reentrant {@code ServiceA -> ServiceB} nested invocation inside {@code onAfterCreate} and
 *       {@code onAfterDelete} preserving per-resource {@code FrameCheckpoint}, masking, and audit outbox;</li>
 *   <li>Opt-in {@code P12} per-row contextual {@code TARGET} masking during {@code filter(...)} and
 *       {@code findById(...)} without cross-row leakage;</li>
 *   <li>Real H2 JPA execution of {@link JpaCriteriaDataScopeTranslator} Kleene 3VL {@code NOT EXISTS}
 *       for negated {@link NullabilityPredicateIr} under {@link RelationTraversalStrategy#CORRELATED_EXISTS_SUBQUERY}
 *       and {@code caseInsensitive} {@code GT/GTE/LT/LTE} comparisons.</li>
 * </ol>
 */
class P11HttpAndReentrantServiceIntegrationTest {

    // -------------------------------------------------------------------------
    // Isolated P11 JPA Entities & Spring Data Repositories
    // -------------------------------------------------------------------------

    @Entity(name = "P11CaseEntity")
    @Table(name = "p11_case_records")
    static class P11CaseEntity {
        @Id
        Long id;

        @Column(name = "tenant_id", nullable = false)
        String tenantId;

        @Column(name = "setor_id", nullable = false)
        Long setorId;

        @Column(name = "status", nullable = false)
        String status;

        @Column(name = "risk_tier", nullable = false)
        String riskTier;

        @Column(name = "dias_afastamento", nullable = false)
        Long diasAfastamento;

        @Column(name = "public_summary")
        String publicSummary;

        @Column(name = "secret_note")
        String secretNote;

        protected P11CaseEntity() {}

        P11CaseEntity(
                Long id,
                String tenantId,
                Long setorId,
                String status,
                String riskTier,
                Long diasAfastamento,
                String publicSummary,
                String secretNote
        ) {
            this.id = id;
            this.tenantId = tenantId;
            this.setorId = setorId;
            this.status = status;
            this.riskTier = riskTier;
            this.diasAfastamento = diasAfastamento;
            this.publicSummary = publicSummary;
            this.secretNote = secretNote;
        }
    }

    @Entity(name = "P11AuditNoteEntity")
    @Table(name = "p11_audit_notes")
    static class P11AuditNoteEntity {
        @Id
        Long id;

        @Column(name = "tenant_id", nullable = false)
        String tenantId;

        @Column(name = "setor_id", nullable = false)
        Long setorId;

        @Column(name = "title", nullable = false)
        String title;

        @Column(name = "confidential_memo")
        String confidentialMemo;

        protected P11AuditNoteEntity() {}

        P11AuditNoteEntity(Long id, String tenantId, Long setorId, String title, String confidentialMemo) {
            this.id = id;
            this.tenantId = tenantId;
            this.setorId = setorId;
            this.title = title;
            this.confidentialMemo = confidentialMemo;
        }
    }

    @Entity(name = "P11EmployeeEntity")
    @Table(name = "p11_employees")
    static class P11EmployeeEntity {
        @Id
        Long id;

        @Column(name = "tenant_id", nullable = false)
        String tenantId;

        @Column(name = "code", nullable = false)
        String code;

        @OneToMany(mappedBy = "employee", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
        List<P11DependentEntity> dependents = new ArrayList<>();

        protected P11EmployeeEntity() {}

        P11EmployeeEntity(Long id, String tenantId, String code) {
            this.id = id;
            this.tenantId = tenantId;
            this.code = code;
        }

        void addDependent(Long depId, String memo) {
            dependents.add(new P11DependentEntity(depId, this, memo));
        }
    }

    @Entity(name = "P11DependentEntity")
    @Table(name = "p11_dependents")
    static class P11DependentEntity {
        @Id
        Long id;

        @ManyToOne(fetch = FetchType.LAZY)
        @JoinColumn(name = "employee_id", nullable = false)
        P11EmployeeEntity employee;

        @Column(name = "memo")
        String memo;

        protected P11DependentEntity() {}

        P11DependentEntity(Long id, P11EmployeeEntity employee, String memo) {
            this.id = id;
            this.employee = employee;
            this.memo = memo;
        }
    }

    interface P11CaseRepository extends BaseCrudRepository<P11CaseEntity, Long> {}

    interface P11AuditNoteRepository extends BaseCrudRepository<P11AuditNoteEntity, Long> {}

    // -------------------------------------------------------------------------
    // Governed DTOs
    // -------------------------------------------------------------------------

    @DomainGovernance(
            classification = DomainClassification.INTERNAL,
            dataCategory = DomainDataCategory.OPERATIONAL,
            reason = "P11 governed case response representation"
    )
    public record P11CaseResponseDto(
            @DomainLineage(attributeId = "p11.cases.id") @Schema(nullable = false) Long id,
            @DomainLineage(attributeId = "p11.cases.tenant_id") @Schema(nullable = false) String tenantId,
            @DomainLineage(attributeId = "p11.cases.setor_id") @Schema(nullable = false) Long setorId,
            @DomainLineage(attributeId = "p11.cases.status") @Schema(nullable = false) String status,
            @DomainLineage(attributeId = "p11.cases.risk_tier") @Schema(nullable = false) String riskTier,
            @DomainLineage(attributeId = "p11.cases.dias_afastamento") @Schema(nullable = false) Long diasAfastamento,
            @DomainLineage(attributeId = "p11.cases.public_summary") @Schema(nullable = true) String publicSummary,
            @DomainLineage(attributeId = "p11.cases.secret_note")
            @DomainGovernance(classification = DomainClassification.CONFIDENTIAL, dataCategory = DomainDataCategory.OPERATIONAL, reason = "Restricted note")
            @Schema(nullable = true)
            String secretNote
    ) {}

    public record P11CaseCreateDto(
            @DomainLineage(attributeId = "p11.cases.id") Long id,
            @DomainLineage(attributeId = "p11.cases.tenant_id") String tenantId,
            @DomainLineage(attributeId = "p11.cases.setor_id") Long setorId,
            @DomainLineage(attributeId = "p11.cases.status") String status,
            @DomainLineage(attributeId = "p11.cases.risk_tier") String riskTier,
            @DomainLineage(attributeId = "p11.cases.dias_afastamento") Long diasAfastamento,
            @DomainLineage(attributeId = "p11.cases.public_summary") String publicSummary,
            @DomainLineage(attributeId = "p11.cases.secret_note") String secretNote
    ) {}

    public record P11CaseUpdateDto(
            @DomainLineage(attributeId = "p11.cases.status") String status,
            @DomainLineage(attributeId = "p11.cases.public_summary") String publicSummary
    ) {}

    public static class P11CaseFilterDto implements GenericFilterDTO {
        @Filterable
        private String status;

        @Filterable
        private String secretNote;

        public String getStatus() {
            return status;
        }

        public void setStatus(String status) {
            this.status = status;
        }

        public String getSecretNote() {
            return secretNote;
        }

        public void setSecretNote(String secretNote) {
            this.secretNote = secretNote;
        }
    }

    @DomainGovernance(
            classification = DomainClassification.INTERNAL,
            dataCategory = DomainDataCategory.OPERATIONAL,
            reason = "P11 governed note response representation"
    )
    public record P11AuditNoteResponseDto(
            @DomainLineage(attributeId = "p11.notes.id") @Schema(nullable = false) Long id,
            @DomainLineage(attributeId = "p11.notes.tenant_id") @Schema(nullable = false) String tenantId,
            @DomainLineage(attributeId = "p11.notes.setor_id") @Schema(nullable = false) Long setorId,
            @DomainLineage(attributeId = "p11.notes.title") @Schema(nullable = false) String title,
            @DomainLineage(attributeId = "p11.notes.confidential_memo")
            @DomainGovernance(classification = DomainClassification.CONFIDENTIAL, dataCategory = DomainDataCategory.OPERATIONAL, reason = "Confidential memo")
            @Schema(nullable = true)
            String confidentialMemo
    ) {}

    public record P11AuditNoteUpdateDto(
            @DomainLineage(attributeId = "p11.notes.title") String title
    ) {}

    public static class P11AuditNoteFilterDto implements GenericFilterDTO {
        @Filterable
        private String title;

        public String getTitle() {
            return title;
        }

        public void setTitle(String title) {
            this.title = title;
        }
    }

    // -------------------------------------------------------------------------
    // Controllable AuthorizationProviderPort for HTTP, Reentrant & P12 tests
    // -------------------------------------------------------------------------

    enum ProviderTestMode {
        NORMAL,
        GATE_DENY_TARGET,
        GATE_DENY_SEARCH,
        SCOPE_NONE,
        DENY_FILTER_SECRET_NOTE,
        DENY_HISTOGRAM_AGGREGATE,
        DENY_FIELD_WRITE_STATUS,
        TECHNICAL_ERROR,
        INCONCLUSIVE,
        TARGET_INCONCLUSIVE,
        P12_PER_ROW_CONTEXTUAL_MASK
    }

    static final class ControllableAuthorizationProvider implements AuthorizationProviderPort {
        final AtomicReference<ProviderTestMode> mode = new AtomicReference<>(ProviderTestMode.NORMAL);
        final AtomicInteger evaluateTargetCalls = new AtomicInteger(0);
        final AtomicInteger evaluateSearchCalls = new AtomicInteger(0);
        final String caseDpKey;
        final String caseQpId;
        final String caseQpDigest;
        final String noteDpKey;
        final String noteQpId;
        final String noteQpDigest;

        ControllableAuthorizationProvider(
                String caseDpKey,
                String caseQpId,
                String caseQpDigest,
                String noteDpKey,
                String noteQpId,
                String noteQpDigest
        ) {
            this.caseDpKey = caseDpKey;
            this.caseQpId = caseQpId;
            this.caseQpDigest = caseQpDigest;
            this.noteDpKey = noteDpKey;
            this.noteQpId = noteQpId;
            this.noteQpDigest = noteQpDigest;
        }

        @Override
        public ProviderEvaluationEnvelope evaluateTarget(ProviderInputProjection input, WriteIntent writeIntent) {
            evaluateTargetCalls.incrementAndGet();
            ProviderTestMode current = mode.get();
            if (current == ProviderTestMode.TECHNICAL_ERROR) {
                return envelope(input, EvaluationMode.TARGET, GateOutcome.TECHNICAL_ERROR,
                        List.of(), List.of(), List.of(), List.of());
            }
            if (current == ProviderTestMode.INCONCLUSIVE || current == ProviderTestMode.TARGET_INCONCLUSIVE) {
                return envelope(input, EvaluationMode.TARGET, GateOutcome.INCONCLUSIVE,
                        List.of(), List.of(), List.of(), List.of());
            }
            if (current == ProviderTestMode.GATE_DENY_TARGET && caseDpKey.equals(input.decisionPointKey())) {
                return envelope(input, EvaluationMode.TARGET, GateOutcome.DENY,
                        List.of(), List.of(), List.of(), List.of());
            }

            boolean isNote = noteDpKey.equals(input.decisionPointKey());
            if (isNote) {
                return envelope(
                        input,
                        EvaluationMode.TARGET,
                        GateOutcome.ALLOW,
                        List.of(),
                        List.of(),
                        List.of(new MaskDirective("p11.notes.confidential_memo", "REDACT_CONSTANT",
                                Map.of("replacement", "***NOTE-MASKED***"))),
                        List.of(new ObligationDirective("DURABLE_AUDIT_EVIDENCE", "ON_PERMIT",
                                "BEFORE_COMMIT_OUTBOX", Map.of("resource", "p11.notes")))
                );
            }

            List<FieldWriteEffectDirective> writeEffects = current == ProviderTestMode.DENY_FIELD_WRITE_STATUS
                    ? List.of(new FieldWriteEffectDirective("p11.cases.status", RuleEffect.DENY))
                    : List.of();

            List<MaskDirective> masks = new ArrayList<>();
            if (current == ProviderTestMode.P12_PER_ROW_CONTEXTUAL_MASK) {
                masks.add(new MaskDirective("p11.cases.public_summary", "REDACT_CONSTANT",
                        Map.of("replacement", "***SEARCH-MASK***")));
                Object riskTier = input.projectedInput().get("resource.riskTier");
                if ("HIGH".equals(riskTier)) {
                    masks.add(new MaskDirective("p11.cases.secret_note", "REDACT_CONSTANT",
                            Map.of("replacement", "***HIGH-RISK-TARGET-MASK***")));
                }
            } else {
                masks.add(new MaskDirective("p11.cases.secret_note", "REDACT_CONSTANT",
                        Map.of("replacement", "***CASE-MASKED***")));
            }

            return envelope(
                    input,
                    EvaluationMode.TARGET,
                    GateOutcome.ALLOW,
                    List.of(),
                    writeEffects,
                    masks,
                    List.of(new ObligationDirective("DURABLE_AUDIT_EVIDENCE", "ON_PERMIT",
                            "BEFORE_COMMIT_OUTBOX", Map.of("resource", "p11.cases")))
            );
        }

        @Override
        public SearchProviderEvaluationResult evaluateSearch(ProviderInputProjection input) {
            evaluateSearchCalls.incrementAndGet();
            ProviderTestMode current = mode.get();
            boolean isNote = noteDpKey.equals(input.decisionPointKey());
            String resourceKey = isNote ? "p11.notes" : "p11.cases";
            String qpId = isNote ? noteQpId : caseQpId;
            String qpDigest = isNote ? noteQpDigest : caseQpDigest;

            if (current == ProviderTestMode.TECHNICAL_ERROR) {
                ProviderEvaluationEnvelope env = envelope(input, EvaluationMode.SEARCH, GateOutcome.TECHNICAL_ERROR,
                        List.of(), List.of(), List.of(), List.of());
                return new SearchProviderEvaluationResult(env, nonePlan(input, resourceKey, qpId, qpDigest));
            }
            if (current == ProviderTestMode.INCONCLUSIVE) {
                ProviderEvaluationEnvelope env = envelope(input, EvaluationMode.SEARCH, GateOutcome.INCONCLUSIVE,
                        List.of(), List.of(), List.of(), List.of());
                return new SearchProviderEvaluationResult(env, nonePlan(input, resourceKey, qpId, qpDigest));
            }
            if (current == ProviderTestMode.GATE_DENY_SEARCH && !isNote) {
                ProviderEvaluationEnvelope env = envelope(input, EvaluationMode.SEARCH, GateOutcome.DENY,
                        List.of(), List.of(), List.of(), List.of());
                return new SearchProviderEvaluationResult(env, nonePlan(input, resourceKey, qpId, qpDigest));
            }
            if (current == ProviderTestMode.SCOPE_NONE && !isNote) {
                ProviderEvaluationEnvelope env = envelope(input, EvaluationMode.SEARCH, GateOutcome.ALLOW,
                        List.of(), List.of(), List.of(), List.of());
                return new SearchProviderEvaluationResult(env, nonePlan(input, resourceKey, qpId, qpDigest));
            }

            List<FieldUseEffectDirective> fieldUseEffects = new ArrayList<>();
            if (current == ProviderTestMode.DENY_FILTER_SECRET_NOTE && !isNote) {
                fieldUseEffects.add(new FieldUseEffectDirective("p11.cases.secret_note", FieldUseCategory.FILTER, RuleEffect.DENY));
            }
            if (current == ProviderTestMode.DENY_HISTOGRAM_AGGREGATE && !isNote) {
                fieldUseEffects.add(new FieldUseEffectDirective("p11.cases.dias_afastamento", FieldUseCategory.AGGREGATE, RuleEffect.DENY));
            }

            List<MaskDirective> masks = isNote
                    ? List.of(new MaskDirective("p11.notes.confidential_memo", "REDACT_CONSTANT",
                            Map.of("replacement", "***NOTE-MASKED***")))
                    : (current == ProviderTestMode.P12_PER_ROW_CONTEXTUAL_MASK
                            ? List.of(new MaskDirective("p11.cases.public_summary", "REDACT_CONSTANT",
                                    Map.of("replacement", "***SEARCH-MASK***")))
                            : List.of(new MaskDirective("p11.cases.secret_note", "REDACT_CONSTANT",
                                    Map.of("replacement", "***CASE-MASKED***"))));

            DataScopePlan filterPlan = new DataScopePlan(
                    DataScopePlan.FORMAT_V1,
                    "plan-" + resourceKey,
                    input.decisionPointKey(),
                    resourceKey,
                    "rev-p11-1",
                    digest("policy-" + resourceKey),
                    input.factContractDigest(),
                    qpId,
                    qpDigest,
                    DataScopeOutcome.FILTER,
                    PushdownMode.FULL_PUSHDOWN,
                    new ComparisonPredicateIr(
                            SearchPredicateOperator.EQ,
                            "resource.setorId",
                            isNote ? "p11.notes.setor_id" : "p11.cases.setor_id",
                            FactValueType.INT64,
                            new LiteralOperandIr(100L),
                            false
                    )
            );

            ProviderEvaluationEnvelope env = envelope(
                    input,
                    EvaluationMode.SEARCH,
                    GateOutcome.ALLOW,
                    fieldUseEffects,
                    List.of(),
                    masks,
                    List.of(new ObligationDirective("DURABLE_AUDIT_EVIDENCE", "ON_PERMIT",
                            "BEFORE_COMMIT_OUTBOX", Map.of("resource", resourceKey)))
            );
            return new SearchProviderEvaluationResult(env, filterPlan);
        }

        private static DataScopePlan nonePlan(
                ProviderInputProjection input,
                String resourceKey,
                String qpId,
                String qpDigest
        ) {
            return new DataScopePlan(
                    DataScopePlan.FORMAT_V1,
                    "plan-none-" + resourceKey,
                    input.decisionPointKey(),
                    resourceKey,
                    "rev-p11-1",
                    digest("policy-" + resourceKey),
                    input.factContractDigest(),
                    qpId,
                    qpDigest,
                    DataScopeOutcome.NONE,
                    PushdownMode.FULL_PUSHDOWN,
                    null
            );
        }

        private static ProviderEvaluationEnvelope envelope(
                ProviderInputProjection input,
                EvaluationMode mode,
                GateOutcome outcome,
                List<FieldUseEffectDirective> fieldUseEffects,
                List<FieldWriteEffectDirective> fieldWriteEffects,
                List<MaskDirective> masks,
                List<ObligationDirective> obligations
        ) {
            return new ProviderEvaluationEnvelope(
                    ProviderEvaluationEnvelope.SCHEMA_VERSION_V1,
                    "OPA_REGO_V1",
                    "eval-" + UUID.randomUUID(),
                    input.decisionPointKey(),
                    mode,
                    "praxis.authorization-combining/v1",
                    "rev-p11-1",
                    digest("policy-" + input.decisionPointKey()),
                    input.factContractDigest(),
                    outcome,
                    fieldUseEffects,
                    fieldWriteEffects,
                    masks,
                    obligations,
                    List.of(),
                    List.of(),
                    List.of(),
                    Instant.now(),
                    15L
            );
        }
    }

    // -------------------------------------------------------------------------
    // Governed Services & Thin REST Controller for MockMvc
    // -------------------------------------------------------------------------

    static class P11CaseGovernedService extends AbstractAuthzGovernedResourceService<
            P11CaseEntity, P11CaseResponseDto, Long, P11CaseFilterDto, P11CaseCreateDto, P11CaseUpdateDto> {

        private final EntityManager em;
        private P11AuditNoteGovernedService reentrantNoteService;
        private Long reentrantFindNoteId;
        private Long reentrantUpdateNoteId;
        private Long reentrantDeleteNoteId;
        private final AtomicReference<P11AuditNoteResponseDto> noteObservedDuringAfterCreate = new AtomicReference<>();
        private final AtomicReference<String> noteTitleObservedDuringAfterDelete = new AtomicReference<>();
        private boolean enableContextualPerRowMasking;

        P11CaseGovernedService(
                BaseCrudRepository<P11CaseEntity, Long> repository,
                AuthzGovernedResourceServiceSupport serviceSupport,
                AuthzResourceGovernanceSpec<P11CaseEntity> governanceSpec,
                AuthzCallerContextProvider callerContextProvider,
                EntityManager em
        ) {
            super(repository, P11CaseEntity.class, P11CaseResponseDto.class, serviceSupport, governanceSpec, callerContextProvider);
            this.em = em;
        }

        void configureReentrantHooks(
                P11AuditNoteGovernedService noteService,
                Long findNoteId,
                Long updateNoteId,
                Long deleteNoteId
        ) {
            this.reentrantNoteService = noteService;
            this.reentrantFindNoteId = findNoteId;
            this.reentrantUpdateNoteId = updateNoteId;
            this.reentrantDeleteNoteId = deleteNoteId;
        }

        void setContextualPerRowMasking(boolean enabled) {
            this.enableContextualPerRowMasking = enabled;
        }

        @Override
        protected boolean requiresRecordContextualSearchMasking() {
            return enableContextualPerRowMasking;
        }

        @Override
        public EntityManager getEntityManager() {
            return em;
        }

        @Override
        protected StatsFieldRegistry defineRawStatsFieldRegistry() {
            return StatsFieldRegistry.of(List.of(
                    StatsFieldDescriptor.numericHistogramMeasureField("diasAfastamento", "diasAfastamento")
            ));
        }

        @Override
        protected Map<String, Object> extractEntityTargetFacts(P11CaseEntity entity) {
            return Map.of(
                    "resource.id", entity.id,
                    "resource.tenantId", entity.tenantId,
                    "resource.setorId", entity.setorId,
                    "resource.riskTier", entity.riskTier
            );
        }

        @Override
        protected void onAfterCreate(P11CaseCreateDto dto, P11CaseEntity saved) {
            if (reentrantNoteService != null && reentrantFindNoteId != null) {
                noteObservedDuringAfterCreate.set(reentrantNoteService.findById(reentrantFindNoteId).body());
            }
        }

        @Override
        protected void onAfterDelete(Long id, P11CaseEntity entity) {
            if (reentrantNoteService != null && reentrantUpdateNoteId != null) {
                P11AuditNoteResponseDto updatedNote = reentrantNoteService.update(
                        reentrantUpdateNoteId,
                        new P11AuditNoteUpdateDto("updated-during-after-delete")
                );
                noteTitleObservedDuringAfterDelete.set(updatedNote.title());
            }
            if (reentrantNoteService != null && reentrantDeleteNoteId != null) {
                reentrantNoteService.deleteById(reentrantDeleteNoteId);
            }
        }

        @Override
        protected ResourceMapper<P11CaseEntity, P11CaseResponseDto, P11CaseCreateDto, P11CaseUpdateDto, Long> getRawResourceMapper() {
            return new ResourceMapper<>() {
                @Override
                public P11CaseResponseDto toResponse(P11CaseEntity e) {
                    return new P11CaseResponseDto(
                            e.id, e.tenantId, e.setorId, e.status, e.riskTier,
                            e.diasAfastamento, e.publicSummary, e.secretNote
                    );
                }

                @Override
                public P11CaseEntity newEntity(P11CaseCreateDto dto) {
                    return new P11CaseEntity(
                            dto.id(), dto.tenantId(), dto.setorId(), dto.status(),
                            dto.riskTier(), dto.diasAfastamento(), dto.publicSummary(), dto.secretNote()
                    );
                }

                @Override
                public void applyUpdate(P11CaseEntity entity, P11CaseUpdateDto dto) {
                    if (dto.status() != null) {
                        entity.status = dto.status();
                    }
                    if (dto.publicSummary() != null) {
                        entity.publicSummary = dto.publicSummary();
                    }
                }

                @Override
                public Long extractId(P11CaseEntity entity) {
                    return entity.id;
                }
            };
        }
    }

    static class P11AuditNoteGovernedService extends AbstractAuthzGovernedResourceService<
            P11AuditNoteEntity, P11AuditNoteResponseDto, Long, P11AuditNoteFilterDto, Object, P11AuditNoteUpdateDto> {

        private final EntityManager em;

        P11AuditNoteGovernedService(
                BaseCrudRepository<P11AuditNoteEntity, Long> repository,
                AuthzGovernedResourceServiceSupport serviceSupport,
                AuthzResourceGovernanceSpec<P11AuditNoteEntity> governanceSpec,
                AuthzCallerContextProvider callerContextProvider,
                EntityManager em
        ) {
            super(repository, P11AuditNoteEntity.class, P11AuditNoteResponseDto.class, serviceSupport, governanceSpec, callerContextProvider);
            this.em = em;
        }

        @Override
        public EntityManager getEntityManager() {
            return em;
        }

        @Override
        protected Map<String, Object> extractEntityTargetFacts(P11AuditNoteEntity entity) {
            return Map.of(
                    "resource.id", entity.id,
                    "resource.tenantId", entity.tenantId,
                    "resource.setorId", entity.setorId
            );
        }

        @Override
        protected ResourceMapper<P11AuditNoteEntity, P11AuditNoteResponseDto, Object, P11AuditNoteUpdateDto, Long> getRawResourceMapper() {
            return new ResourceMapper<>() {
                @Override
                public P11AuditNoteResponseDto toResponse(P11AuditNoteEntity e) {
                    return new P11AuditNoteResponseDto(e.id, e.tenantId, e.setorId, e.title, e.confidentialMemo);
                }

                @Override
                public P11AuditNoteEntity newEntity(Object dto) {
                    throw new UnsupportedOperationException();
                }

                @Override
                public void applyUpdate(P11AuditNoteEntity entity, P11AuditNoteUpdateDto dto) {
                    if (dto.title() != null) {
                        entity.title = dto.title();
                    }
                }

                @Override
                public Long extractId(P11AuditNoteEntity entity) {
                    return entity.id;
                }
            };
        }
    }

    @RestController
    @RequestMapping("/api/p11/cases")
    static class P11CaseTestController {
        private final P11CaseGovernedService service;
        private final TransactionTemplate txTemplate;

        P11CaseTestController(P11CaseGovernedService service, TransactionTemplate txTemplate) {
            this.service = service;
            this.txTemplate = txTemplate;
        }

        @GetMapping("/{id}")
        public P11CaseResponseDto getById(@PathVariable("id") Long id) {
            return txTemplate.execute(status -> service.findById(id).body());
        }

        @PostMapping("/filter")
        public Page<P11CaseResponseDto> filter(@RequestBody P11CaseFilterDto filter) {
            return txTemplate.execute(status -> service.filter(filter, PageRequest.of(0, 20), List.of()));
        }

        @PatchMapping("/{id}")
        public P11CaseResponseDto patch(@PathVariable("id") Long id, @RequestBody P11CaseUpdateDto dto) {
            return txTemplate.execute(status -> service.update(id, dto));
        }

        @PostMapping("/stats/distribution")
        public DistributionStatsResponse distribution(@RequestBody DistributionStatsRequest<P11CaseFilterDto> req) {
            return txTemplate.execute(status -> service.distributionStats(req));
        }

        @GetMapping("/auth-check")
        public Map<String, String> authCheck() {
            throw new SecurityException("AUTHZ_CALLER_CONTEXT_MISSING: synthetic controller guard check");
        }
    }

    // -------------------------------------------------------------------------
    // Shared Persistence & Infrastructure Harness
    // -------------------------------------------------------------------------

    private record Harness(
            LocalContainerEntityManagerFactoryBean emfBean,
            EntityManager sharedEm,
            TransactionTemplate txTemplate,
            JdbcTransactionalAuditOutbox jdbcOutbox,
            AuthzGovernedResourceServiceSupport serviceSupport,
            ThreadLocalAuthzCallerContextProvider callerContextProvider,
            ControllableAuthorizationProvider provider,
            P11CaseRepository caseRepo,
            P11AuditNoteRepository noteRepo,
            P11CaseGovernedService caseService,
            P11AuditNoteGovernedService noteService,
            ObjectMapper objectMapper
    ) {}

    private static Harness createHarness() {
        String dbName = "p11_" + UUID.randomUUID().toString().replace("-", "");
        DriverManagerDataSource dataSource = new DriverManagerDataSource(
                "jdbc:h2:mem:" + dbName + ";DB_CLOSE_DELAY=-1;MODE=PostgreSQL",
                "sa",
                ""
        );
        LocalContainerEntityManagerFactoryBean emfBean = new LocalContainerEntityManagerFactoryBean();
        emfBean.setDataSource(dataSource);
        emfBean.setPackagesToScan(P11HttpAndReentrantServiceIntegrationTest.class.getPackageName());
        emfBean.setPersistenceProviderClass(HibernatePersistenceProvider.class);
        emfBean.setJpaVendorAdapter(new HibernateJpaVendorAdapter());
        Properties jpaProps = new Properties();
        jpaProps.setProperty("hibernate.hbm2ddl.auto", "create-drop");
        jpaProps.setProperty("hibernate.dialect", "org.hibernate.dialect.H2Dialect");
        emfBean.setJpaProperties(jpaProps);
        emfBean.afterPropertiesSet();

        JpaTransactionManager txManager = new JpaTransactionManager(Objects.requireNonNull(emfBean.getObject()));
        TransactionTemplate txTemplate = new TransactionTemplate(txManager);
        EntityManager sharedEm = SharedEntityManagerCreator.createSharedEntityManager(emfBean.getObject());
        JdbcTemplate jdbcTemplate = new JdbcTemplate(dataSource);
        JdbcTransactionalAuditOutbox jdbcOutbox = new JdbcTransactionalAuditOutbox(
                jdbcTemplate, "praxis_authz_audit_outbox", true, true
        );

        String caseFcDigest = digest("fc-p11-cases");
        String caseQpId = "qp-p11-cases";
        String caseQpDigest = digest(caseQpId);
        DecisionPointDescriptor caseDp = buildDecisionPoint(
                "p11-service", "p11.cases", "/api/p11/cases/filter", "fc-p11-cases", caseFcDigest, caseQpId, caseQpDigest
        );
        QueryableResourceProjection caseProjection = new QueryableResourceProjection(
                QueryableResourceProjection.SCHEMA_VERSION_V1,
                caseQpId,
                "p11.cases",
                caseQpDigest,
                Map.of(
                        "resource.setorId",
                        new QueryableFieldDescriptor(
                                "resource.setorId", "p11.cases.setor_id", FactValueType.INT64,
                                Set.of(SearchPredicateOperator.EQ, SearchPredicateOperator.IN), true
                        )
                )
        );

        String noteFcDigest = digest("fc-p11-notes");
        String noteQpId = "qp-p11-notes";
        String noteQpDigest = digest(noteQpId);
        DecisionPointDescriptor noteDp = buildDecisionPoint(
                "p11-service", "p11.notes", "/api/p11/notes/filter", "fc-p11-notes", noteFcDigest, noteQpId, noteQpDigest
        );
        QueryableResourceProjection noteProjection = new QueryableResourceProjection(
                QueryableResourceProjection.SCHEMA_VERSION_V1,
                noteQpId,
                "p11.notes",
                noteQpDigest,
                Map.of(
                        "resource.setorId",
                        new QueryableFieldDescriptor(
                                "resource.setorId", "p11.notes.setor_id", FactValueType.INT64,
                                Set.of(SearchPredicateOperator.EQ, SearchPredicateOperator.IN), true
                        )
                )
        );

        ControllableAuthorizationProvider provider = new ControllableAuthorizationProvider(
                caseDp.identity().pointKey(), caseQpId, caseQpDigest,
                noteDp.identity().pointKey(), noteQpId, noteQpDigest
        );

        DetachedDtoMaskingProcessor maskingProcessor = new DetachedDtoMaskingProcessor();
        MetadataResourceAuthorizationSeam seam = new MetadataResourceAuthorizationSeam(
                provider,
                new FieldUseQueryGuard(),
                new DtoWriteIntentExtractor(),
                new FieldWriteAuthorizer(),
                maskingProcessor,
                new ObligationBarrierCoordinator(new DefaultObligationHandlerRegistry(), jdbcOutbox),
                null
        );
        MetadataDtoGovernanceIntrospector introspector = new MetadataDtoGovernanceIntrospector();
        AuthzGovernedResourceServiceSupport serviceSupport =
                new AuthzGovernedResourceServiceSupport(seam, maskingProcessor, introspector);
        ThreadLocalAuthzCallerContextProvider callerContextProvider = new ThreadLocalAuthzCallerContextProvider();

        JpaRepositoryFactory repoFactory = new JpaRepositoryFactory(sharedEm);
        P11CaseRepository caseRepo = repoFactory.getRepository(P11CaseRepository.class);
        P11AuditNoteRepository noteRepo = repoFactory.getRepository(P11AuditNoteRepository.class);

        AuthzResourceGovernanceSpec<P11CaseEntity> caseSpec = AuthzResourceGovernanceSpec
                .<P11CaseEntity>builder("p11.cases")
                .decisionPoint(caseDp)
                .factContractDigest(caseFcDigest)
                .queryAdapter(caseProjection, List.of(new QueryAdapterFieldBinding(
                        "p11.cases", "resource.setorId", "p11.cases.setor_id",
                        "setorId", RelationTraversalStrategy.INNER_JOIN_SCALAR, true
                )))
                .tenantField("tenantId")
                .mandatoryScopeAnchorAttributeIds(Set.of("p11.cases.id", "p11.cases.tenant_id", "p11.cases.setor_id"))
                .build();

        AuthzResourceGovernanceSpec<P11AuditNoteEntity> noteSpec = AuthzResourceGovernanceSpec
                .<P11AuditNoteEntity>builder("p11.notes")
                .decisionPoint(noteDp)
                .factContractDigest(noteFcDigest)
                .queryAdapter(noteProjection, List.of(new QueryAdapterFieldBinding(
                        "p11.notes", "resource.setorId", "p11.notes.setor_id",
                        "setorId", RelationTraversalStrategy.INNER_JOIN_SCALAR, true
                )))
                .tenantField("tenantId")
                .mandatoryScopeAnchorAttributeIds(Set.of("p11.notes.id", "p11.notes.tenant_id", "p11.notes.setor_id"))
                .build();

        P11CaseGovernedService caseService = new P11CaseGovernedService(
                caseRepo, serviceSupport, caseSpec, callerContextProvider, sharedEm
        );
        caseService.configureGovernedQueryInfrastructure(
                null,
                null,
                new JpaStatsQueryExecutor(),
                new StatsProperties(true, 20, 100, StatsSupportMode.AUTO)
        );

        P11AuditNoteGovernedService noteService = new P11AuditNoteGovernedService(
                noteRepo, serviceSupport, noteSpec, callerContextProvider, sharedEm
        );

        try {
            Field emField = AbstractBaseQueryResourceService.class.getDeclaredField("entityManager");
            emField.setAccessible(true);
            emField.set(caseService, sharedEm);
            emField.set(noteService, sharedEm);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("Failed to inject PersistenceContext entityManager into test services", e);
        }

        ObjectMapper objectMapper = new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);

        return new Harness(
                emfBean, sharedEm, txTemplate, jdbcOutbox, serviceSupport, callerContextProvider,
                provider, caseRepo, noteRepo, caseService, noteService, objectMapper
        );
    }

    // -------------------------------------------------------------------------
    // Tests
    // -------------------------------------------------------------------------

    @Test
    void mockMvcEndToEndEnforcesHttpFilterExceptionMappingAuditAndHistogramAggregateGuard() throws Exception {
        Harness h = createHarness();
        try {
            h.txTemplate.executeWithoutResult(status -> {
                h.caseRepo.save(new P11CaseEntity(1L, "tenant-a", 100L, "OPEN", "LOW", 5L, "summary-1", "raw-secret-1"));
                h.caseRepo.save(new P11CaseEntity(2L, "tenant-a", 999L, "OPEN", "LOW", 15L, "summary-2", "raw-secret-2"));
                h.caseRepo.save(new P11CaseEntity(3L, "tenant-b", 100L, "OPEN", "LOW", 25L, "summary-3", "raw-secret-3"));
            });

            AuthzCallerContextHttpResolver resolver = req -> {
                String auth = req.getHeader("Authorization");
                if (auth == null || !auth.startsWith("Bearer tenant:")) {
                    return Optional.empty();
                }
                String tenant = auth.substring("Bearer tenant:".length()).trim();
                return Optional.of(AuthzCallerContext.of(
                        tenant,
                        Map.of("subject.principalId", "usr-1", "subject.organizationUnitIds", List.of(100L))
                ));
            };
            PraxisAuthzExceptionHandler exceptionHandler = new PraxisAuthzExceptionHandler();
            AuthzCallerContextFilter filter = new AuthzCallerContextFilter(
                    resolver, h.callerContextProvider, exceptionHandler, h.objectMapper
            );

            MockMvc mockMvc = MockMvcBuilders
                    .standaloneSetup(new P11CaseTestController(h.caseService, h.txTemplate))
                    .setControllerAdvice(exceptionHandler)
                    .setMessageConverters(new MappingJackson2HttpMessageConverter(h.objectMapper))
                    .addFilters(filter)
                    .build();

            // 1. 200 GET /{id}, POST /filter, and permitted PATCH /{id} (masked response, tenant + sector isolation, mutation outbox committed)
            mockMvc.perform(get("/api/p11/cases/1")
                            .header("Authorization", "Bearer tenant:tenant-a"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.id").value(1))
                    .andExpect(jsonPath("$.secretNote").value("***CASE-MASKED***"));
            assertTrue(h.jdbcOutbox.listCommittedEntries().isEmpty(),
                    "Read-only GET /{id} should not commit BEFORE_COMMIT_OUTBOX entries");

            mockMvc.perform(post("/api/p11/cases/filter")
                            .header("Authorization", "Bearer tenant:tenant-a")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{}"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.totalElements").value(1))
                    .andExpect(jsonPath("$.content[0].id").value(1))
                    .andExpect(jsonPath("$.content[0].secretNote").value("***CASE-MASKED***"));

            mockMvc.perform(patch("/api/p11/cases/1")
                            .header("Authorization", "Bearer tenant:tenant-a")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"publicSummary\":\"summary-1-updated\"}"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.publicSummary").value("summary-1-updated"))
                    .andExpect(jsonPath("$.secretNote").value("***CASE-MASKED***"));
            assertEquals(1, h.jdbcOutbox.listCommittedEntries().size(),
                    "PATCH /{id} mutation must commit BEFORE_COMMIT_OUTBOX entry atomically");

            // 2. 401 when caller context is missing (via service AND via controller SecurityException prefix)
            mockMvc.perform(get("/api/p11/cases/1"))
                    .andExpect(status().isUnauthorized())
                    .andExpect(jsonPath("$.errors[0].code").value("AUTHZ_CALLER_CONTEXT_MISSING"));

            mockMvc.perform(get("/api/p11/cases/auth-check"))
                    .andExpect(status().isUnauthorized());

            // 3. 403 UntrustedHeaderSpoofingException at HTTP filter boundary (prefix spoof AND X-Tenant-Id conflict)
            mockMvc.perform(get("/api/p11/cases/1")
                            .header("X-Praxis-Authz-Roles", "SUPER_ADMIN"))
                    .andExpect(status().isForbidden())
                    .andExpect(jsonPath("$.errors[0].code").value("AUTHZ_HEADER_SPOOFING"));

            mockMvc.perform(get("/api/p11/cases/1")
                            .header("Authorization", "Bearer tenant:tenant-a")
                            .header("X-Tenant-Id", "tenant-evil"))
                    .andExpect(status().isForbidden())
                    .andExpect(jsonPath("$.errors[0].code").value("AUTHZ_HEADER_SPOOFING"));

            // 4. 403 AuthzAccessDeniedException on GateOutcome.DENY (TARGET on PATCH & SEARCH on GET/filter) + fail-closed DataScopeOutcome.NONE
            h.provider.mode.set(ProviderTestMode.GATE_DENY_TARGET);
            mockMvc.perform(patch("/api/p11/cases/1")
                            .header("Authorization", "Bearer tenant:tenant-a")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"publicSummary\":\"denied-by-target\"}"))
                    .andExpect(status().isForbidden())
                    .andExpect(jsonPath("$.errors[0].code").value("AUTHZ_MUTATION_SEAM_DENIED"));

            h.provider.mode.set(ProviderTestMode.GATE_DENY_SEARCH);
            mockMvc.perform(get("/api/p11/cases/1")
                            .header("Authorization", "Bearer tenant:tenant-a"))
                    .andExpect(status().isForbidden())
                    .andExpect(jsonPath("$.errors[0].code").value("AUTHZ_QUERY_SEAM_DENIED"));
            mockMvc.perform(post("/api/p11/cases/filter")
                            .header("Authorization", "Bearer tenant:tenant-a")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{}"))
                    .andExpect(status().isForbidden())
                    .andExpect(jsonPath("$.errors[0].code").value("AUTHZ_QUERY_SEAM_DENIED"));

            h.provider.mode.set(ProviderTestMode.SCOPE_NONE);
            MvcResult noneRes = mockMvc.perform(post("/api/p11/cases/filter")
                            .header("Authorization", "Bearer tenant:tenant-a")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{}"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.totalElements").value(0))
                    .andReturn();
            assertEquals("0", h.objectMapper.readTree(noneRes.getResponse().getContentAsString()).get("totalElements").asText());

            // 5. 403 FieldUseViolationException on FILTER + HISTOGRAM AGGREGATE (after confirming HISTOGRAM 200 under NORMAL)
            h.provider.mode.set(ProviderTestMode.NORMAL);
            String histogramReqJson = h.objectMapper.writeValueAsString(new DistributionStatsRequest<>(
                    new P11CaseFilterDto(),
                    "diasAfastamento",
                    DistributionMode.HISTOGRAM,
                    new StatsMetricRequest(StatsMetric.COUNT, null),
                    10,
                    null,
                    10,
                    StatsBucketOrder.KEY_ASC
            ));
            mockMvc.perform(post("/api/p11/cases/stats/distribution")
                            .header("Authorization", "Bearer tenant:tenant-a")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(histogramReqJson))
                    .andExpect(status().isOk());

            h.provider.mode.set(ProviderTestMode.DENY_FILTER_SECRET_NOTE);
            mockMvc.perform(post("/api/p11/cases/filter")
                            .header("Authorization", "Bearer tenant:tenant-a")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"secretNote\":\"raw-secret-1\"}"))
                    .andExpect(status().isForbidden())
                    .andExpect(jsonPath("$.errors[0].code").value("AUTHZ_FIELD_USE_DENIED"));

            h.provider.mode.set(ProviderTestMode.DENY_HISTOGRAM_AGGREGATE);
            MvcResult histDenyRes = mockMvc.perform(post("/api/p11/cases/stats/distribution")
                            .header("Authorization", "Bearer tenant:tenant-a")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(histogramReqJson))
                    .andExpect(status().isForbidden())
                    .andExpect(jsonPath("$.errors[0].code").value("AUTHZ_FIELD_USE_DENIED"))
                    .andExpect(jsonPath("$.errors[0].fieldUseCategory").value("AGGREGATE"))
                    .andReturn();
            String histDenyBody = histDenyRes.getResponse().getContentAsString();
            assertTrue(histDenyBody.contains("AGGREGATE"), "HISTOGRAM field-use denial must report AGGREGATE category");
            assertTrue(histDenyBody.contains("p11.cases.dias_afastamento"));

            // 6. 403 FieldWriteViolationException on PATCH /{id}
            h.provider.mode.set(ProviderTestMode.DENY_FIELD_WRITE_STATUS);
            mockMvc.perform(patch("/api/p11/cases/1")
                            .header("Authorization", "Bearer tenant:tenant-a")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"status\":\"CLOSED\"}"))
                    .andExpect(status().isForbidden())
                    .andExpect(jsonPath("$.errors[0].code").value("AUTHZ_FIELD_WRITE_DENIED"));
            P11CaseEntity untouched = h.txTemplate.execute(s -> h.sharedEm.find(P11CaseEntity.class, 1L));
            assertEquals("OPEN", Objects.requireNonNull(untouched).status);

            // 7. 503 AuthzProviderUnavailableException on TECHNICAL_ERROR & INCONCLUSIVE
            h.provider.mode.set(ProviderTestMode.TECHNICAL_ERROR);
            mockMvc.perform(get("/api/p11/cases/1")
                            .header("Authorization", "Bearer tenant:tenant-a"))
                    .andExpect(status().isServiceUnavailable())
                    .andExpect(jsonPath("$.errors[0].code").value("AUTHZ_QUERY_SEAM_DENIED"))
                    .andExpect(jsonPath("$.errors[0].gateOutcome").value("TECHNICAL_ERROR"));

            h.provider.mode.set(ProviderTestMode.INCONCLUSIVE);
            mockMvc.perform(post("/api/p11/cases/filter")
                            .header("Authorization", "Bearer tenant:tenant-a")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{}"))
                    .andExpect(status().isServiceUnavailable())
                    .andExpect(jsonPath("$.errors[0].code").value("AUTHZ_QUERY_SEAM_DENIED"))
                    .andExpect(jsonPath("$.errors[0].gateOutcome").value("INCONCLUSIVE"));

            h.provider.mode.set(ProviderTestMode.TARGET_INCONCLUSIVE);
            mockMvc.perform(patch("/api/p11/cases/1")
                            .header("Authorization", "Bearer tenant:tenant-a")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content("{\"status\":\"CLOSED\"}"))
                    .andExpect(status().isServiceUnavailable())
                    .andExpect(jsonPath("$.errors[0].code").value("AUTHZ_MUTATION_SEAM_DENIED"))
                    .andExpect(jsonPath("$.errors[0].gateOutcome").value("INCONCLUSIVE"));

            assertFalse(h.serviceSupport.hasActiveQueryContext());
            assertTrue(h.callerContextProvider.currentCallerContextOptional().isEmpty());
        } finally {
            h.emfBean.destroy();
        }
    }

    @Test
    void reentrantServiceAToServiceBPreservesIndependentScopesMasksAndAuditOutbox() {
        Harness h = createHarness();
        try {
            h.txTemplate.executeWithoutResult(status -> {
                h.noteRepo.save(new P11AuditNoteEntity(10L, "tenant-a", 100L, "initial-title-10", "raw-memo-10"));
                h.noteRepo.save(new P11AuditNoteEntity(11L, "tenant-a", 100L, "initial-title-11", "raw-memo-11"));
            });
            h.caseService.configureReentrantHooks(h.noteService, 10L, 10L, 11L);

            AuthzCallerContext caller = AuthzCallerContext.of(
                    "tenant-a",
                    Map.of("subject.principalId", "usr-reentrant", "subject.organizationUnitIds", List.of(100L))
            );

            h.callerContextProvider.runWithContext(caller, () -> {
                // 1. Create on CaseService triggers reentrant NoteService.findById inside onAfterCreate
                var created = h.txTemplate.execute(status ->
                        h.caseService.create(new P11CaseCreateDto(
                                50L, "tenant-a", 100L, "OPEN", "LOW", 7L, "case-summary-50", "raw-case-secret-50"
                        ))
                );
                assertNotNull(created);
                assertEquals("***CASE-MASKED***", created.body().secretNote(),
                        "Outer ServiceA.create must restore its own FrameCheckpoint and mask its response");
                P11AuditNoteResponseDto innerNote = h.caseService.noteObservedDuringAfterCreate.get();
                assertNotNull(innerNote);
                assertEquals("***NOTE-MASKED***", innerNote.confidentialMemo(),
                        "Inner ServiceB.findById inside ServiceA.onAfterCreate must apply ServiceB mask");
                assertEquals(1, h.jdbcOutbox.listCommittedEntries().size(),
                        "Create ServiceA mutation must fulfill its audit outbox entry");
                assertFalse(h.serviceSupport.hasActiveQueryContext());

                // 2. Delete on CaseService triggers reentrant NoteService.update + NoteService.deleteById inside onAfterDelete
                h.txTemplate.executeWithoutResult(status -> h.caseService.deleteById(50L));
                assertEquals("updated-during-after-delete", h.caseService.noteTitleObservedDuringAfterDelete.get());
                assertEquals(4, h.jdbcOutbox.listCommittedEntries().size(),
                        "Delete ServiceA + update ServiceB + delete ServiceB must add 3 outbox entries (total 4)");
                assertFalse(h.serviceSupport.hasActiveQueryContext());

                // Reentrant delete must actually delete note #11 and case #50 while leaving updated note #10 intact
                h.txTemplate.executeWithoutResult(status -> {
                    assertTrue(h.caseRepo.findById(50L).isEmpty());
                    assertTrue(h.noteRepo.findById(11L).isEmpty());
                    P11AuditNoteEntity note10 = h.noteRepo.findById(10L).orElseThrow();
                    assertEquals("updated-during-after-delete", note10.title);
                    assertEquals("raw-memo-10", note10.confidentialMemo, "DB column must never be masked");
                });
            });
        } finally {
            h.emfBean.destroy();
        }
    }

    @Test
    void optInRecordContextualSearchMaskingMergesPerRowTargetMasksDuringSearch() {
        Harness h = createHarness();
        try {
            h.txTemplate.executeWithoutResult(status -> {
                h.caseRepo.save(new P11CaseEntity(1L, "tenant-a", 100L, "OPEN", "LOW", 3L, "low-summary", "raw-low-secret"));
                h.caseRepo.save(new P11CaseEntity(2L, "tenant-a", 100L, "OPEN", "HIGH", 9L, "high-summary", "raw-high-secret"));
            });

            h.provider.mode.set(ProviderTestMode.P12_PER_ROW_CONTEXTUAL_MASK);
            h.caseService.setContextualPerRowMasking(true);
            AuthzCallerContext caller = AuthzCallerContext.of(
                    "tenant-a",
                    Map.of("subject.principalId", "usr-p12", "subject.organizationUnitIds", List.of(100L))
            );

            h.callerContextProvider.runWithContext(caller, () -> {
                h.provider.evaluateTargetCalls.set(0);
                Page<P11CaseResponseDto> page = h.txTemplate.execute(status ->
                        h.caseService.filter(new P11CaseFilterDto(), PageRequest.of(0, 10), List.of())
                );
                assertNotNull(page);
                assertEquals(2, page.getContent().size());
                assertEquals(2, h.provider.evaluateTargetCalls.get(),
                        "P12 opt-in requiresRecordContextualSearchMasking() must evaluate TARGET per returned row");

                P11CaseResponseDto rowLow = page.getContent().stream().filter(r -> r.id().equals(1L)).findFirst().orElseThrow();
                P11CaseResponseDto rowHigh = page.getContent().stream().filter(r -> r.id().equals(2L)).findFirst().orElseThrow();

                assertEquals("***SEARCH-MASK***", rowLow.publicSummary());
                assertEquals("raw-low-secret", rowLow.secretNote(),
                        "Row #1 (LOW risk) must receive global SEARCH mask without HIGH-risk row #2 TARGET mask leaking");

                assertEquals("***SEARCH-MASK***", rowHigh.publicSummary());
                assertEquals("***HIGH-RISK-TARGET-MASK***", rowHigh.secretNote(),
                        "Row #2 (HIGH risk) must merge both SEARCH mask and per-row TARGET mask");

                // Also verify findById merges TARGET + SEARCH masks on single-row retrieval
                P11CaseResponseDto foundHigh = h.txTemplate.execute(status -> h.caseService.findById(2L).body());
                assertEquals("***HIGH-RISK-TARGET-MASK***", foundHigh.secretNote());
                assertFalse(h.serviceSupport.hasActiveQueryContext());
            });

            // Raw DB values remain intact
            h.txTemplate.executeWithoutResult(status -> {
                assertEquals("raw-high-secret", h.caseRepo.findById(2L).orElseThrow().secretNote);
            });
        } finally {
            h.emfBean.destroy();
        }
    }

    @Test
    void jpaCriteriaDataScopeTranslatorEnforcesNegatedCorrelatedNullabilityAndCaseInsensitiveComparisons() {
        String dbName = "p11_c03b_" + UUID.randomUUID().toString().replace("-", "");
        DriverManagerDataSource dataSource = new DriverManagerDataSource(
                "jdbc:h2:mem:" + dbName + ";DB_CLOSE_DELAY=-1;MODE=PostgreSQL",
                "sa",
                ""
        );
        LocalContainerEntityManagerFactoryBean emfBean = new LocalContainerEntityManagerFactoryBean();
        emfBean.setDataSource(dataSource);
        emfBean.setPackagesToScan(P11HttpAndReentrantServiceIntegrationTest.class.getPackageName());
        emfBean.setPersistenceProviderClass(HibernatePersistenceProvider.class);
        emfBean.setJpaVendorAdapter(new HibernateJpaVendorAdapter());
        Properties jpaProps = new Properties();
        jpaProps.setProperty("hibernate.hbm2ddl.auto", "create-drop");
        jpaProps.setProperty("hibernate.dialect", "org.hibernate.dialect.H2Dialect");
        emfBean.setJpaProperties(jpaProps);
        emfBean.afterPropertiesSet();

        try {
            JpaTransactionManager txManager = new JpaTransactionManager(Objects.requireNonNull(emfBean.getObject()));
            TransactionTemplate txTemplate = new TransactionTemplate(txManager);
            EntityManager em = SharedEntityManagerCreator.createSharedEntityManager(emfBean.getObject());

            txTemplate.executeWithoutResult(status -> {
                P11EmployeeEntity e1 = new P11EmployeeEntity(1L, "tenant-a", "b-user");
                e1.addDependent(101L, "dep-ok-1");
                e1.addDependent(102L, "dep-ok-2");

                P11EmployeeEntity e2 = new P11EmployeeEntity(2L, "tenant-a", "M-user");
                e2.addDependent(201L, null);

                P11EmployeeEntity e3 = new P11EmployeeEntity(3L, "tenant-a", "z-user");
                // No dependents

                P11EmployeeEntity e4 = new P11EmployeeEntity(4L, "tenant-a", "a-mixed");
                e4.addDependent(401L, "dep-valid");
                e4.addDependent(402L, null);

                em.persist(e1);
                em.persist(e2);
                em.persist(e3);
                em.persist(e4);
            });

            String qpId = "qp-p11-employees";
            String qpDigest = digest(qpId);
            String dpDigest = digest("dp-p11-employees");
            String fcDigest = digest("fc-p11-employees");
            QueryableResourceProjection projection = new QueryableResourceProjection(
                    QueryableResourceProjection.SCHEMA_VERSION_V1,
                    qpId,
                    "p11.employees",
                    qpDigest,
                    Map.of(
                            "resource.dependentMemo",
                            new QueryableFieldDescriptor(
                                    "resource.dependentMemo", "p11.employees.dependent_memo", FactValueType.STRING,
                                    Set.of(SearchPredicateOperator.IS_NULL, SearchPredicateOperator.IS_NOT_NULL), true
                            ),
                            "resource.code",
                            new QueryableFieldDescriptor(
                                    "resource.code", "p11.employees.code", FactValueType.STRING,
                                    Set.of(SearchPredicateOperator.GT, SearchPredicateOperator.GTE,
                                            SearchPredicateOperator.LT, SearchPredicateOperator.LTE), false
                            )
                    )
            );
            JpaCriteriaDataScopeTranslator translator = new JpaCriteriaDataScopeTranslator(
                    projection,
                    List.of(
                            new QueryAdapterFieldBinding(
                                    "p11.employees", "resource.dependentMemo", "p11.employees.dependent_memo",
                                    "dependents.memo", RelationTraversalStrategy.CORRELATED_EXISTS_SUBQUERY, true
                            ),
                            new QueryAdapterFieldBinding(
                                    "p11.employees", "resource.code", "p11.employees.code",
                                    "code", RelationTraversalStrategy.INNER_JOIN_SCALAR, false
                            )
                    )
            );

            ResourceFilterAccessScope<P11EmployeeEntity> tenantHardScope =
                    ResourceFilterAccessScope.restricted((root, query, cb) -> cb.equal(root.get("tenantId"), "tenant-a"));

            // 1. Kleene 3VL NOT(IS_NULL) under CORRELATED_EXISTS_SUBQUERY -> NOT EXISTS(dep where memo is null)
            // Must return #1 (no null dependent memo) and #3 (0 dependents), and exclude #2 & #4 (which have a null memo)
            List<Long> notNullMemoIds = executeEmployeeQuery(txTemplate, em, translator, tenantHardScope, qpId, qpDigest, dpDigest, fcDigest,
                    new LogicalPredicateIr(
                            SearchPredicateOperator.NOT,
                            List.of(new NullabilityPredicateIr(
                                    SearchPredicateOperator.IS_NULL,
                                    "resource.dependentMemo",
                                    "p11.employees.dependent_memo"
                            ))
                    )
            );
            assertEquals(List.of(1L, 3L), notNullMemoIds,
                    "NOT(IS_NULL) on CORRELATED_EXISTS_SUBQUERY must compile to NOT EXISTS(...) matching only employees with no null dependent memo");

            // 2. caseInsensitive GT / GTE / LT / LTE comparisons ("a-mixed", "b-user", "M-user", "z-user")
            // Notice 'M' (ASCII 77) < 'b' (98) < 'm' (109), so without cb.lower + lowercase literal these break!
            List<Long> gtIds = executeEmployeeQuery(txTemplate, em, translator, tenantHardScope, qpId, qpDigest, dpDigest, fcDigest,
                    new ComparisonPredicateIr(
                            SearchPredicateOperator.GT, "resource.code", "p11.employees.code",
                            FactValueType.STRING, new LiteralOperandIr("M"), true
                    )
            );
            assertEquals(List.of(2L, 3L), gtIds, "caseInsensitive GT('M') must match 'M-user' and 'z-user'");

            List<Long> gteIds = executeEmployeeQuery(txTemplate, em, translator, tenantHardScope, qpId, qpDigest, dpDigest, fcDigest,
                    new ComparisonPredicateIr(
                            SearchPredicateOperator.GTE, "resource.code", "p11.employees.code",
                            FactValueType.STRING, new LiteralOperandIr("m-user"), true
                    )
            );
            assertEquals(List.of(2L, 3L), gteIds, "caseInsensitive GTE('m-user') must match 'M-user' and 'z-user'");

            List<Long> ltIds = executeEmployeeQuery(txTemplate, em, translator, tenantHardScope, qpId, qpDigest, dpDigest, fcDigest,
                    new ComparisonPredicateIr(
                            SearchPredicateOperator.LT, "resource.code", "p11.employees.code",
                            FactValueType.STRING, new LiteralOperandIr("m"), true
                    )
            );
            assertEquals(List.of(1L, 4L), ltIds, "caseInsensitive LT('m') must exclude 'M-user' and match 'a-mixed' & 'b-user'");

            List<Long> lteIds = executeEmployeeQuery(txTemplate, em, translator, tenantHardScope, qpId, qpDigest, dpDigest, fcDigest,
                    new ComparisonPredicateIr(
                            SearchPredicateOperator.LTE, "resource.code", "p11.employees.code",
                            FactValueType.STRING, new LiteralOperandIr("B-USER"), true
                    )
            );
            assertEquals(List.of(1L, 4L), lteIds, "caseInsensitive LTE('B-USER') must match 'a-mixed' & 'b-user'");
        } finally {
            emfBean.destroy();
        }
    }

    private static List<Long> executeEmployeeQuery(
            TransactionTemplate txTemplate,
            EntityManager em,
            JpaCriteriaDataScopeTranslator translator,
            ResourceFilterAccessScope<P11EmployeeEntity> tenantHardScope,
            String qpId,
            String qpDigest,
            String dpDigest,
            String fcDigest,
            SearchPredicateIr predicateIr
    ) {
        DataScopePlan plan = new DataScopePlan(
                DataScopePlan.FORMAT_V1,
                "plan-" + UUID.randomUUID(),
                dpDigest,
                "p11.employees",
                "rev-1",
                digest("policy-emp"),
                fcDigest,
                qpId,
                qpDigest,
                DataScopeOutcome.FILTER,
                PushdownMode.FULL_PUSHDOWN,
                predicateIr
        );
        return txTemplate.execute(status -> {
            ResourceFilterAccessScope<P11EmployeeEntity> scope = translator.toResourceFilterAccessScope(plan, tenantHardScope);
            CriteriaBuilder cb = em.getCriteriaBuilder();
            CriteriaQuery<P11EmployeeEntity> cq = cb.createQuery(P11EmployeeEntity.class);
            Root<P11EmployeeEntity> root = cq.from(P11EmployeeEntity.class);
            cq.select(root).where(scope.specification().toPredicate(root, cq, cb)).orderBy(cb.asc(root.get("id")));
            return em.createQuery(cq).getResultList().stream().map(e -> e.id).toList();
        });
    }

    private static DecisionPointDescriptor buildDecisionPoint(
            String serviceKey,
            String resourceKey,
            String path,
            String fcId,
            String fcDigest,
            String qpId,
            String qpDigest
    ) {
        return new DecisionPointDescriptor(
                DecisionPointDescriptor.SCHEMA_VERSION_V1,
                DecisionPointIdentity.resourceOperation(serviceKey, resourceKey, "filter"),
                DecisionKind.AUTHORIZATION,
                DecisionResultContractKind.GATE,
                null,
                "SEARCH",
                "POST",
                path,
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
                new FactContractRef(fcId, fcDigest),
                new QueryableProjectionRef(qpId, qpDigest),
                null,
                null,
                "STATUTORY_LEGAL_OBLIGATION",
                "LGPD:ART_7_III",
                null,
                digest(serviceKey + "|" + resourceKey + "|dp")
        );
    }

    private static String digest(String seed) {
        return CanonicalDigestCalculator.computeDigest(DigestDomainKind.DEPENDENCY_MANIFEST_DIGEST, seed);
    }
}
