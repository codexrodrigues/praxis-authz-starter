package org.praxisplatform.authz.starter;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.LongNode;
import com.fasterxml.jackson.databind.node.TextNode;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.models.SpecVersion;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EntityManager;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Version;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.constraints.NotNull;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Properties;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import org.hibernate.jpa.HibernatePersistenceProvider;
import org.junit.jupiter.api.Test;
import org.praxisplatform.authz.autoconfigure.PraxisAuthzAutoConfiguration;
import org.praxisplatform.authz.autoconfigure.PraxisAuthzHostBridgeAutoConfiguration;
import org.praxisplatform.authz.catalog.MethodBindingAdmissionRecord;
import org.praxisplatform.authz.compatibility.HostRuntimePolicyCoordinates;
import org.praxisplatform.authz.contracts.binding.BatchAuthorizationMode;
import org.praxisplatform.authz.contracts.context.FactResolutionStatus;
import org.praxisplatform.authz.contracts.decisionpoint.FieldUseCategory;
import org.praxisplatform.authz.contracts.envelope.FieldUseEffectDirective;
import org.praxisplatform.authz.contracts.envelope.MaskDirective;
import org.praxisplatform.authz.contracts.envelope.RuleEffect;
import org.praxisplatform.authz.contracts.obligation.DefaultObligationHandlerRegistry;
import org.praxisplatform.authz.contracts.policy.DualScopeDelegationSpec;
import org.praxisplatform.authz.enforcement.fielduse.FieldUseQueryGuard;
import org.praxisplatform.authz.enforcement.fielduse.FieldUseViolationException;
import org.praxisplatform.authz.enforcement.jpa.JpaDataScopeAdapter;
import org.praxisplatform.authz.enforcement.jpa.QueryAdapterFieldBinding;
import org.praxisplatform.authz.enforcement.jpa.RelationTraversalStrategy;
import org.praxisplatform.authz.enforcement.masking.DetachedDtoMaskingProcessor;
import org.praxisplatform.authz.enforcement.obligation.ObligationBarrierCoordinator;
import org.praxisplatform.authz.enforcement.writeintent.DtoWriteIntentExtractor;
import org.praxisplatform.authz.enforcement.writeintent.FieldWriteAuthorizer;
import org.praxisplatform.authz.enforcement.writeintent.FieldWriteViolationException;
import org.praxisplatform.authz.host.metadata.AbstractAuthzGovernedReadOnlyResourceService;
import org.praxisplatform.authz.host.metadata.AbstractAuthzGovernedResourceService;
import org.praxisplatform.authz.host.metadata.AuthzCallerContext;
import org.praxisplatform.authz.host.metadata.AuthzCallerContextProvider;
import org.praxisplatform.authz.host.metadata.AuthzGovernedBulkDomainResourceAdapter;
import org.praxisplatform.authz.host.metadata.AuthzGovernedBulkDomainResourceAdapter.BulkCohortItemOutcome;
import org.praxisplatform.authz.host.metadata.AuthzGovernedBulkDomainResourceAdapter.GovernedBulkProposalGrant;
import org.praxisplatform.authz.host.metadata.AuthzGovernedCollectionExportExecutor;
import org.praxisplatform.authz.host.metadata.AuthzGovernedOptionSourceProvider;
import org.praxisplatform.authz.host.metadata.AuthzGovernedReactiveDeterminationProvider;
import org.praxisplatform.authz.host.metadata.AuthzGovernedResourceServiceSupport;
import org.praxisplatform.authz.host.metadata.AuthzGovernedStatsQueryExecutor;
import org.praxisplatform.authz.host.metadata.AuthzHostReadinessReviewer;
import org.praxisplatform.authz.host.metadata.AuthzResourceGovernanceSpec;
import org.praxisplatform.authz.host.metadata.AuthzResourceOperationAvailabilityProvider;
import org.praxisplatform.authz.host.metadata.AuthzResourceOperationAvailabilityProvider.CallerAvailabilityFactContext;
import org.praxisplatform.authz.host.metadata.AuthzResourceOperationAvailabilityProvider.ResourceAvailabilityPolicyBinding;
import org.praxisplatform.authz.host.metadata.AuthzResourceOperationAvailabilityProvider.UnmappedResourcePolicy;
import org.praxisplatform.authz.host.metadata.JpaCriteriaDataScopeTranslator;
import org.praxisplatform.authz.host.metadata.MetadataDtoGovernanceIntrospector;
import org.praxisplatform.authz.host.metadata.MetadataDtoGovernanceIntrospector.IntrospectedDtoGovernanceContract;
import org.praxisplatform.authz.host.metadata.ThreadLocalAuthzCallerContextProvider;
import org.praxisplatform.authz.opa.client.OpaAuthorizationProviderAdapter;
import org.praxisplatform.authz.opa.client.OpaClientTransport;
import org.praxisplatform.authz.opa.revision.SameInstanceSearchRevisionGuard;
import org.praxisplatform.authz.outbox.JdbcTransactionalAuditOutbox;
import org.praxisplatform.authz.pilot.AfastamentoAuthzPilotBlueprint;
import org.praxisplatform.authz.seams.GovernedExportAndAiToolAuthorizationSeam.AiGovernanceMetadataView;
import org.praxisplatform.authz.seams.GovernedExportAndAiToolAuthorizationSeam.SanitizedAiToolProjection;
import org.praxisplatform.authz.seams.MetadataResourceAuthorizationSeam;
import org.praxisplatform.authz.telemetry.SanitizedAuthorizationTelemetryPublisher;
import org.praxisplatform.authz.telemetry.SanitizedAuthorizationTelemetryPublisher.SanitizedDecisionTelemetryEvent;
import org.praxisplatform.uischema.action.ActionAvailabilityContext;
import org.praxisplatform.uischema.action.ActionDefinition;
import org.praxisplatform.uischema.action.ActionExecutionContract;
import org.praxisplatform.uischema.action.ActionScope;
import org.praxisplatform.uischema.action.AllowedStatesActionAvailabilityRule;
import org.praxisplatform.uischema.action.ContextualActionAvailabilityRule;
import org.praxisplatform.uischema.action.DefaultActionAvailabilityEvaluator;
import org.praxisplatform.uischema.action.RequiredAuthoritiesActionAvailabilityRule;
import org.praxisplatform.uischema.annotation.BulkEditable;
import org.praxisplatform.uischema.annotation.DomainClassification;
import org.praxisplatform.uischema.annotation.DomainDataCategory;
import org.praxisplatform.uischema.annotation.DomainGovernance;
import org.praxisplatform.uischema.annotation.DomainGovernancePreset;
import org.praxisplatform.uischema.annotation.DomainLineage;
import org.praxisplatform.uischema.bulk.BulkEditableFields;
import org.praxisplatform.uischema.bulk.BulkFieldChange;
import org.praxisplatform.uischema.bulk.BulkMode;
import org.praxisplatform.uischema.capability.AvailabilityDecision;
import org.praxisplatform.uischema.capability.NoOpResourceOperationAvailabilityProvider;
import org.praxisplatform.uischema.capability.ResourceOperationAvailabilityContext;
import org.praxisplatform.uischema.capability.ResourceStateSnapshot;
import org.praxisplatform.uischema.capability.ResourceStateSnapshotProvider;
import org.praxisplatform.uischema.command.GovernedResourceCommandExecutor;
import org.praxisplatform.uischema.command.ResourceCommandExecutionRequest;
import org.praxisplatform.uischema.command.ResourceCommandExecutionResult;
import org.praxisplatform.uischema.command.ResourceCommandOutcome;
import org.praxisplatform.uischema.command.ResourceCommandResponsePolicy;
import org.praxisplatform.uischema.concurrency.ResourceRepresentationResult;
import org.praxisplatform.uischema.concurrency.ResourceVersionEtagService;
import org.praxisplatform.uischema.concurrency.ResourceVersionPreconditionException;
import org.praxisplatform.uischema.concurrency.ResourceVersionScope;
import org.praxisplatform.uischema.concurrency.ResourceVersionUpdatePrecondition;
import org.praxisplatform.uischema.determination.ReactiveDeterminationDefinition;
import org.praxisplatform.uischema.determination.ReactiveDeterminationProvenance;
import org.praxisplatform.uischema.determination.ReactiveDeterminationProvenanceKind;
import org.praxisplatform.uischema.dto.OptionDTO;
import org.praxisplatform.uischema.exporting.CollectionExportExecutor;
import org.praxisplatform.uischema.exporting.CollectionExportField;
import org.praxisplatform.uischema.exporting.CollectionExportFormat;
import org.praxisplatform.uischema.exporting.CollectionExportRequest;
import org.praxisplatform.uischema.exporting.CollectionExportResult;
import org.praxisplatform.uischema.exporting.CollectionExportScope;
import org.praxisplatform.uischema.exporting.CsvCollectionExportEngine;
import org.praxisplatform.uischema.exporting.DefaultCollectionExportExecutor;
import org.praxisplatform.uischema.filter.dto.GenericFilterDTO;
import org.praxisplatform.uischema.mapper.base.ResourceMapper;
import org.praxisplatform.uischema.options.EntityLookupDescriptor;
import org.praxisplatform.uischema.options.LookupCapabilities;
import org.praxisplatform.uischema.options.LookupDisplayDescriptor;
import org.praxisplatform.uischema.options.LookupDisplayFieldDescriptor;
import org.praxisplatform.uischema.options.LookupFilterRequest;
import org.praxisplatform.uischema.options.LookupSelectionPolicy;
import org.praxisplatform.uischema.options.OptionSourceDescriptor;
import org.praxisplatform.uischema.options.OptionSourceFilterRequest;
import org.praxisplatform.uischema.options.OptionSourcePolicy;
import org.praxisplatform.uischema.options.OptionSourceRegistry;
import org.praxisplatform.uischema.options.OptionSourceType;
import org.praxisplatform.uischema.options.service.jpa.JpaOptionSourceQueryExecutor;
import org.praxisplatform.uischema.repository.base.BaseCrudRepository;
import org.praxisplatform.uischema.service.base.AbstractBaseQueryResourceService;
import org.praxisplatform.uischema.service.base.AbstractBaseResourceService;
import org.praxisplatform.uischema.service.base.ResourceFilterAccessScope;
import org.praxisplatform.uischema.service.base.ResourceMutationContext;
import org.praxisplatform.uischema.service.base.VersionedCreateUpdateResourceService;
import org.praxisplatform.uischema.stats.DistributionMode;
import org.praxisplatform.uischema.stats.StatsBucketOrder;
import org.praxisplatform.uischema.stats.StatsEligibility;
import org.praxisplatform.uischema.stats.StatsFieldRegistry;
import org.praxisplatform.uischema.stats.StatsMetric;
import org.praxisplatform.uischema.stats.StatsProperties;
import org.praxisplatform.uischema.stats.StatsSupportMode;
import org.praxisplatform.uischema.stats.dto.DistributionStatsRequest;
import org.praxisplatform.uischema.stats.dto.DistributionStatsResponse;
import org.praxisplatform.uischema.stats.dto.GroupByStatsRequest;
import org.praxisplatform.uischema.stats.dto.GroupByStatsResponse;
import org.praxisplatform.uischema.stats.dto.StatsMetricRequest;
import org.praxisplatform.uischema.stats.service.jpa.JpaStatsQueryExecutor;
import org.praxisplatform.uischema.surface.AllowedStatesSurfaceAvailabilityRule;
import org.praxisplatform.uischema.surface.ContextualSurfaceAvailabilityRule;
import org.praxisplatform.uischema.surface.DefaultSurfaceAvailabilityEvaluator;
import org.praxisplatform.uischema.surface.RequiredAuthoritiesSurfaceAvailabilityRule;
import org.praxisplatform.uischema.surface.SurfaceAvailabilityContext;
import org.praxisplatform.uischema.surface.SurfaceDefinition;
import org.praxisplatform.uischema.surface.SurfaceKind;
import org.praxisplatform.uischema.surface.SurfaceResponseCardinality;
import org.praxisplatform.uischema.surface.SurfaceScope;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.jpa.repository.support.JpaRepositoryFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.orm.jpa.SharedEntityManagerCreator;
import org.springframework.orm.jpa.vendor.HibernateJpaVendorAdapter;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Fase P10.2 End-to-End Integration Test proving:
 * <ul>
 *   <li>Automatic DTO annotation introspection ({@link DomainLineage}, {@link DomainGovernance},
 *       {@link Schema}) via {@link MetadataDtoGovernanceIntrospector};</li>
 *   <li>Real subclassing of {@link AbstractBaseResourceService} backed by a real Spring Data JPA
 *       {@link BaseCrudRepository} ({@link JpaRepositoryFactory}) and {@code AuthzMaskingResourceMapperDecorator};</li>
 *   <li>Full execution of {@code service.filter(...)}, {@code service.findById(...)},
 *       {@code service.update(...)}, and {@code service.exportCollection(...)} with zero manual
 *       field-schema boilerplate.</li>
 * </ul>
 */
class P102RealAbstractBaseResourceServiceIntegrationTest {

    @Entity(name = "P102AfastamentoJpaEntity")
    @Table(name = "p102_afastamento_jpa")
    @DomainGovernance(
            classification = DomainClassification.INTERNAL,
            dataCategory = DomainDataCategory.OPERATIONAL,
            reason = "Entidade JPA de afastamento funcional"
    )
    static class P102AfastamentoJpaEntity {

        @Id
        @Column(name = "id", nullable = false)
        Long id;

        @Column(name = "tenant_id", nullable = false, length = 64)
        String tenantId;

        @Column(name = "cedente_orgao_id", nullable = false)
        @DomainGovernance(exportable = false, reason = "Internal custody identifier excluded from CSV export")
        Long cedenteOrgaoId;

        @Column(name = "cessionario_orgao_id", nullable = false)
        Long cessionarioOrgaoId;

        @Column(name = "lotacao_setor_id")
        Long lotacaoSetorId;

        @Column(name = "status_afastamento", nullable = false, length = 32)
        String statusAfastamento;

        @Column(name = "substituto_servidor_id")
        Long substitutoServidorId;

        @Column(name = "cid_codigo", length = 32)
        @DomainGovernance(
                preset = DomainGovernancePreset.LGPD_SENSITIVE_DATA,
                reason = "Diagnóstico médico CID protegido pelo Art. 11 da LGPD"
        )
        String cidCodigo;

        @Version
        @Column(name = "version")
        Long version;

        protected P102AfastamentoJpaEntity() {
        }

        P102AfastamentoJpaEntity(
                Long id,
                String tenantId,
                Long cedenteOrgaoId,
                Long cessionarioOrgaoId,
                Long lotacaoSetorId,
                String statusAfastamento,
                Long substitutoServidorId,
                String cidCodigo
        ) {
            this.id = id;
            this.tenantId = tenantId;
            this.cedenteOrgaoId = cedenteOrgaoId;
            this.cessionarioOrgaoId = cessionarioOrgaoId;
            this.lotacaoSetorId = lotacaoSetorId;
            this.statusAfastamento = statusAfastamento;
            this.substitutoServidorId = substitutoServidorId;
            this.cidCodigo = cidCodigo;
        }
    }

    /** Real Spring Data JPA repository extending {@link BaseCrudRepository} from {@code praxis-metadata-starter}. */
    interface P102AfastamentoRepository extends BaseCrudRepository<P102AfastamentoJpaEntity, Long> {
    }

    /**
     * Real immutable {@code ResponseDTO} Java record annotated with {@link DomainLineage},
     * {@link DomainGovernance}, and {@link Schema} from {@code praxis-metadata-starter}.
     * Notice that {@code cidCodigo} inherits {@link DomainGovernancePreset#LGPD_SENSITIVE_DATA}
     * directly from {@link P102AfastamentoJpaEntity} via {@link DomainLineage} ({@code P44..P50}).
     */
    @DomainGovernance(
            classification = DomainClassification.INTERNAL,
            dataCategory = DomainDataCategory.OPERATIONAL,
            reason = "Representação de resposta de afastamento funcional"
    )
    public record AfastamentoAnnotatedResponseDTO(
            @DomainLineage(attributeId = "ergon.afastamentos.id")
            @Schema(nullable = false)
            Long id,

            @DomainLineage(attributeId = "ergon.afastamentos.tenant_id")
            @Schema(nullable = false)
            String tenantId,

            @DomainLineage(
                    sourceClass = P102AfastamentoJpaEntity.class,
                    sourcePaths = "cedenteOrgaoId",
                    attributeId = "ergon.afastamentos.cedente_orgao_id"
            )
            @Schema(nullable = false)
            Long orgCedenteId,

            @DomainLineage(attributeId = "ergon.afastamentos.cessionario_orgao_id")
            @Schema(nullable = false)
            Long orgCessionariaId,

            @DomainLineage(attributeId = "ergon.afastamentos.lotacao_setor_id")
            @Schema(nullable = true)
            Long lotacaoSetorId,

            @DomainLineage(attributeId = "ergon.afastamentos.status_afastamento")
            @Schema(nullable = false)
            String statusAfastamento,

            @DomainLineage(attributeId = "ergon.afastamentos.substituto_servidor_id")
            @Schema(nullable = true)
            Long substitutoServidorId,

            @DomainLineage(
                    sourceClass = P102AfastamentoJpaEntity.class,
                    sourcePaths = "cidCodigo",
                    attributeId = "ergon.afastamentos.cid_codigo"
            )
            @Schema(nullable = true)
            String cidCodigo
    ) {}

    /** Projection attempting to weaken origin LGPD_SENSITIVE_DATA governance (must fail closed per P46/P49). */
    record WeakenedAfastamentoDto(
            @DomainLineage(
                    sourceClass = P102AfastamentoJpaEntity.class,
                    sourcePaths = "cidCodigo",
                    attributeId = "ergon.afastamentos.cid_codigo"
            )
            @DomainGovernance(
                    classification = DomainClassification.PUBLIC,
                    exportable = true,
                    reason = "Attempted illegal weakening of restricted CID field"
            )
            String cidCodigo
    ) {}

    /** Interface contract with @DomainLineage and @NotNull on getter (P10.2-R02). */
    interface AuditedAfastamentoProjectionContract {
        @NotNull
        @DomainLineage(attributeId = "ergon.afastamentos.id")
        @Schema(description = "ID obrigatório via @NotNull sem nullable explícito no @Schema")
        Long getId();
    }

    /** Superclass POJO DTO for testing inheritance deduplication and shadowing (P10.2-R02). */
    @DomainGovernance(
            classification = DomainClassification.INTERNAL,
            dataCategory = DomainDataCategory.OPERATIONAL,
            reason = "Superclasse POJO de afastamento"
    )
    static class SuperPojoDto implements AuditedAfastamentoProjectionContract {
        Long id;

        @DomainLineage(attributeId = "ergon.afastamentos.status_afastamento")
        String statusAfastamento;

        @Override
        public Long getId() {
            return id;
        }
    }

    /** Subclass POJO DTO shadowing statusAfastamento and declaring getter @DomainGovernance (P10.2-R02). */
    static final class SubPojoDto extends SuperPojoDto {
        // Shadowed field in subclass must not duplicate fieldSchemas entry
        @DomainLineage(attributeId = "ergon.afastamentos.status_afastamento")
        @NotNull
        String statusAfastamento;

        String cidCodigo;

        @DomainLineage(
                sourceClass = P102AfastamentoJpaEntity.class,
                sourcePaths = "cidCodigo",
                attributeId = "ergon.afastamentos.cid_codigo"
        )
        public String getCidCodigo() {
            return cidCodigo;
        }
    }

    /** Real {@code CreateDTO} Java record annotated with {@link DomainLineage}. */
    record AfastamentoAnnotatedCreateDTO(
            @DomainLineage(attributeId = "ergon.afastamentos.id") Long id,
            @DomainLineage(attributeId = "ergon.afastamentos.tenant_id") String tenantId,
            @DomainLineage(attributeId = "ergon.afastamentos.cedente_orgao_id") Long orgCedenteId,
            @DomainLineage(attributeId = "ergon.afastamentos.cessionario_orgao_id") Long orgCessionariaId,
            @DomainLineage(attributeId = "ergon.afastamentos.lotacao_setor_id") Long lotacaoSetorId,
            @DomainLineage(attributeId = "ergon.afastamentos.status_afastamento") String statusAfastamento,
            @DomainLineage(attributeId = "ergon.afastamentos.substituto_servidor_id") Long substitutoServidorId,
            @DomainLineage(attributeId = "ergon.afastamentos.cid_codigo") String cidCodigo
    ) {}

    /** Real {@code UpdateDTO} Java record annotated with {@link DomainLineage} and {@link BulkEditable}. */
    record AfastamentoAnnotatedUpdateDTO(
            @DomainLineage(attributeId = "ergon.afastamentos.substituto_servidor_id")
            @BulkEditable(modes = {BulkMode.UNIFORM_UPDATE, BulkMode.PER_ITEM_UPDATE}, allowClear = true)
            @Schema(nullable = true)
            Long substitutoServidorId,

            @DomainLineage(attributeId = "ergon.afastamentos.cid_codigo")
            @BulkEditable(modes = {BulkMode.UNIFORM_UPDATE, BulkMode.PER_ITEM_UPDATE}, allowClear = true)
            @Schema(nullable = true)
            String cidCodigo
    ) {}

    /** FilterDTO for Afastamento (enriched in Fase P10.15-A with @Filterable single and multi-relation fields). */
    static class AfastamentoFilterDTO implements GenericFilterDTO {
        @org.praxisplatform.uischema.filter.annotation.Filterable
        String statusAfastamento;

        @org.praxisplatform.uischema.filter.annotation.Filterable
        String cidCodigo;

        @org.praxisplatform.uischema.filter.annotation.Filterable(
                operation = org.praxisplatform.uischema.filter.annotation.Filterable.FilterOperation.LIKE,
                relations = {"statusAfastamento", "cidCodigo"}
        )
        String buscaAmplaComCid;
    }

    /** FilterDTO with a broken @Filterable relation path for testing AUTHZ-HOST-006-INVALID-FILTERABLE-ENTITY-PATH (P10.15-R04). */
    static class BrokenPathAfastamentoFilterDTO implements GenericFilterDTO {
        @org.praxisplatform.uischema.filter.annotation.Filterable(relation = "vinculoInexistente.setorFantasma")
        String filtroQuebrado;
    }

    /** ResponseDTO with a VALUE+DENY (SECRET_CREDENTIAL) attribute for testing AUTHZ-HOST-011 and AUTHZ-HOST-012 (Fase P10.21-A). */
    @DomainGovernance(
            classification = DomainClassification.INTERNAL,
            dataCategory = DomainDataCategory.OPERATIONAL,
            reason = "DTO com segredo VALUE+DENY para auditoria AUTHZ-HOST-011 e AUTHZ-HOST-012"
    )
    record SecretTokenAfastamentoResponseDTO(
            @DomainLineage(attributeId = "ergon.afastamentos.id") Long id,
            @DomainLineage(attributeId = "ergon.afastamentos.tenant_id") String tenantId,
            @DomainLineage(attributeId = "ergon.afastamentos.cedente_orgao_id")
            @DomainGovernance(exportable = false, reason = "Internal custody identifier excluded from CSV export")
            Long orgCedenteId,
            @DomainLineage(attributeId = "ergon.afastamentos.cessionario_orgao_id") Long orgCessionariaId,
            @DomainLineage(attributeId = "ergon.afastamentos.lotacao_setor_id") Long lotacaoSetorId,
            @DomainLineage(attributeId = "ergon.afastamentos.status_afastamento") String statusAfastamento,
            @DomainLineage(attributeId = "ergon.afastamentos.webhook_token")
            @DomainGovernance(
                    classification = DomainClassification.RESTRICTED,
                    dataCategory = DomainDataCategory.CREDENTIAL,
                    reason = "Segredo de integração nunca exposto em filtro ou analytics"
            )
            String webhookToken
    ) {}

    /** FilterDTO illegally exposing a VALUE+DENY (SECRET_CREDENTIAL) attribute via @Filterable (Fase P10.21-A). */
    static class SecretTokenAfastamentoFilterDTO implements GenericFilterDTO {
        @org.praxisplatform.uischema.filter.annotation.Filterable(relation = "statusAfastamento")
        String webhookToken;
    }

    /**
     * Real subclass of {@link AbstractBaseResourceService} from {@code praxis-metadata-starter}
     * wired with {@link AuthzGovernedResourceServiceSupport} and {@link MetadataDtoGovernanceIntrospector}.
     */
    static class AfastamentoGovernedResourceService extends AbstractBaseResourceService<
            P102AfastamentoJpaEntity,
            AfastamentoAnnotatedResponseDTO,
            Long,
            AfastamentoFilterDTO,
            AfastamentoAnnotatedCreateDTO,
            AfastamentoAnnotatedUpdateDTO
    > {
        private final AfastamentoAuthzPilotBlueprint blueprint;
        private final AuthzGovernedResourceServiceSupport serviceSupport;
        private final JpaDataScopeAdapter jpaAdapter;
        private final JpaCriteriaDataScopeTranslator criteriaTranslator;
        private final IntrospectedDtoGovernanceContract responseContract;
        private final IntrospectedDtoGovernanceContract createContract;
        private final IntrospectedDtoGovernanceContract updateContract;
        private final ResourceMapper<
                P102AfastamentoJpaEntity,
                AfastamentoAnnotatedResponseDTO,
                AfastamentoAnnotatedCreateDTO,
                AfastamentoAnnotatedUpdateDTO,
                Long> decoratedMapper;

        final AtomicBoolean callerIsCedente = new AtomicBoolean(false);
        final AtomicBoolean validateCreateCalled = new AtomicBoolean(false);
        final AtomicBoolean validateUpdateCalled = new AtomicBoolean(false);
        final AtomicBoolean validateDeleteCalled = new AtomicBoolean(false);
        final AtomicBoolean failInValidateUpdate = new AtomicBoolean(false);
        final AtomicReference<String> rawCidObservedInValidateUpdate = new AtomicReference<>();
        final java.util.concurrent.atomic.AtomicInteger searchScopeEvaluations =
                new java.util.concurrent.atomic.AtomicInteger(0);

        AfastamentoGovernedResourceService(
                P102AfastamentoRepository repository,
                AfastamentoAuthzPilotBlueprint blueprint,
                AuthzGovernedResourceServiceSupport serviceSupport,
                JpaDataScopeAdapter jpaAdapter,
                JpaCriteriaDataScopeTranslator criteriaTranslator
        ) {
            super(repository, P102AfastamentoJpaEntity.class);
            this.blueprint = blueprint;
            this.serviceSupport = serviceSupport;
            this.jpaAdapter = jpaAdapter;
            this.criteriaTranslator = criteriaTranslator;
            this.responseContract = serviceSupport.dtoIntrospector()
                    .introspect(AfastamentoAnnotatedResponseDTO.class, blueprint.resourceKey());
            this.createContract = serviceSupport.dtoIntrospector()
                    .introspect(AfastamentoAnnotatedCreateDTO.class, blueprint.resourceKey());
            this.updateContract = serviceSupport.dtoIntrospector()
                    .introspect(AfastamentoAnnotatedUpdateDTO.class, blueprint.resourceKey());

            ResourceMapper<
                    P102AfastamentoJpaEntity,
                    AfastamentoAnnotatedResponseDTO,
                    AfastamentoAnnotatedCreateDTO,
                    AfastamentoAnnotatedUpdateDTO,
                    Long> baseMapper = new ResourceMapper<>() {
                @Override
                public AfastamentoAnnotatedResponseDTO toResponse(P102AfastamentoJpaEntity e) {
                    return new AfastamentoAnnotatedResponseDTO(
                            e.id,
                            e.tenantId,
                            e.cedenteOrgaoId,
                            e.cessionarioOrgaoId,
                            e.lotacaoSetorId,
                            e.statusAfastamento,
                            e.substitutoServidorId,
                            e.cidCodigo
                    );
                }

                @Override
                public P102AfastamentoJpaEntity newEntity(AfastamentoAnnotatedCreateDTO dto) {
                    return new P102AfastamentoJpaEntity(
                            dto.id(),
                            dto.tenantId(),
                            dto.orgCedenteId(),
                            dto.orgCessionariaId(),
                            dto.lotacaoSetorId(),
                            dto.statusAfastamento(),
                            dto.substitutoServidorId(),
                            dto.cidCodigo()
                    );
                }

                @Override
                public void applyUpdate(P102AfastamentoJpaEntity e, AfastamentoAnnotatedUpdateDTO dto) {
                    if (dto.substitutoServidorId() != null) {
                        e.substitutoServidorId = dto.substitutoServidorId();
                    }
                    if (dto.cidCodigo() != null) {
                        e.cidCodigo = dto.cidCodigo();
                    }
                }

                @Override
                public Long extractId(P102AfastamentoJpaEntity e) {
                    return e.id;
                }
            };
            this.decoratedMapper = serviceSupport.wrapResourceMapper(
                    baseMapper,
                    AfastamentoAnnotatedResponseDTO.class,
                    blueprint.resourceKey()
            );
        }

        @Override
        protected ResourceMapper<
                P102AfastamentoJpaEntity,
                AfastamentoAnnotatedResponseDTO,
                AfastamentoAnnotatedCreateDTO,
                AfastamentoAnnotatedUpdateDTO,
                Long> getResourceMapper() {
            return decoratedMapper;
        }

        @Override
        protected ResourceFilterAccessScope<P102AfastamentoJpaEntity> resolveResourceFilterAccessScope() {
            searchScopeEvaluations.incrementAndGet();
            ResourceFilterAccessScope<P102AfastamentoJpaEntity> tenantHardScope =
                    ResourceFilterAccessScope.restricted((root, query, cb) -> cb.equal(root.get("tenantId"), "tenant-gov-br"));
            return serviceSupport.authorizeAndResolveAccessScope(
                    blueprint.decisionPoint(),
                    blueprint.factContract().factContractDigest(),
                    Set.of("Authorization", "Accept"),
                    Map.of("subject.principalId", "usr-gestor-101", "subject.organizationUnitIds", List.of(100L)),
                    Map.of("subject.principalId", FactResolutionStatus.PRESENT, "subject.organizationUnitIds", FactResolutionStatus.PRESENT),
                    Map.of(FieldUseCategory.FILTER, Set.of("ergon.afastamentos.lotacao_setor_id")),
                    responseContract.baselineFieldUseDirectives(),
                    jpaAdapter,
                    "e.tenantId = :tenantId",
                    Map.of("tenantId", "tenant-gov-br"),
                    criteriaTranslator,
                    tenantHardScope
            );
        }

        @Override
        protected void assertEntityAccessAllowed(P102AfastamentoJpaEntity entity) {
            if (!"tenant-gov-br".equals(entity.tenantId) || !Objects.equals(100L, entity.lotacaoSetorId)) {
                throw new SecurityException("Entity #" + entity.id + " is outside authorized DataScopePlan (403)");
            }
            // Bind query context at most once per operation so filter/export/findAllById/findEntityForMutation
            // do not trigger N+1 OPA SEARCH evaluations (P10.4-R03)
            serviceSupport.ensureActiveQueryContext(this::resolveResourceFilterAccessScope);
        }

        @Override
        protected Object prepareCreateValidationDraft(
                AfastamentoAnnotatedCreateDTO dto,
                P102AfastamentoJpaEntity candidate
        ) {
            return getResourceMapper().toResponse(candidate);
        }

        /** Exposes protected prepareCreateValidationDraft for testing P10.4-R05 unmasked draft projection. */
        AfastamentoAnnotatedResponseDTO invokePrepareCreateValidationDraft(
                AfastamentoAnnotatedCreateDTO dto,
                P102AfastamentoJpaEntity candidate
        ) {
            return (AfastamentoAnnotatedResponseDTO) prepareCreateValidationDraft(dto, candidate);
        }

        /** Exposes protected prepareUpdateValidationDraft for testing P10.2-R01 unmasked draft projection. */
        AfastamentoAnnotatedResponseDTO invokePrepareUpdateValidationDraft(
                Long id,
                P102AfastamentoJpaEntity candidate,
                AfastamentoAnnotatedUpdateDTO dto
        ) {
            return (AfastamentoAnnotatedResponseDTO) super.prepareUpdateValidationDraft(id, candidate, dto);
        }

        @Override
        protected void beforeCreate(AfastamentoAnnotatedCreateDTO dto, P102AfastamentoJpaEntity entity) {
            // STEP_11: Pre-hydration WriteIntent + DualScope authorization BEFORE validateCreate (STEP_12)
            Map<String, Object> rawPayload = new java.util.LinkedHashMap<>();
            if (dto.id() != null) rawPayload.put("id", dto.id());
            if (dto.tenantId() != null) rawPayload.put("tenantId", dto.tenantId());
            if (dto.orgCedenteId() != null) rawPayload.put("orgCedenteId", dto.orgCedenteId());
            if (dto.orgCessionariaId() != null) rawPayload.put("orgCessionariaId", dto.orgCessionariaId());
            if (dto.lotacaoSetorId() != null) rawPayload.put("lotacaoSetorId", dto.lotacaoSetorId());
            if (dto.statusAfastamento() != null) rawPayload.put("statusAfastamento", dto.statusAfastamento());
            if (dto.substitutoServidorId() != null) rawPayload.put("substitutoServidorId", dto.substitutoServidorId());
            if (dto.cidCodigo() != null) rawPayload.put("cidCodigo", dto.cidCodigo());

            serviceSupport.authorizeBeforeHydrationAndRules(
                    blueprint.decisionPoint(),
                    blueprint.factContract().factContractDigest(),
                    "POST",
                    false,
                    rawPayload,
                    createContract.wirePointerToAttributeIdMap(),
                    Set.of(),
                    Set.of(
                            "ergon.afastamentos.id",
                            "ergon.afastamentos.tenant_id",
                            "ergon.afastamentos.cedente_orgao_id",
                            "ergon.afastamentos.cessionario_orgao_id",
                            "ergon.afastamentos.lotacao_setor_id"
                    ),
                    blueprint.dualScopeSpec(),
                    callerIsCedente.get(),
                    true,
                    Map.of(
                            "subject.principalId", "usr-gestor-101",
                            "subject.organizationUnitIds", List.of(100L),
                            "resource.lotacaoSetorId", entity.lotacaoSetorId
                    ),
                    Map.of(
                            "subject.principalId", FactResolutionStatus.PRESENT,
                            "subject.organizationUnitIds", FactResolutionStatus.PRESENT,
                            "resource.lotacaoSetorId", FactResolutionStatus.PRESENT
                    )
            );
        }

        @Override
        protected void validateCreate(
                ResourceMutationContext context,
                AfastamentoAnnotatedCreateDTO dto,
                P102AfastamentoJpaEntity entity
        ) {
            validateCreateCalled.set(true);
        }

        @Override
        protected void afterCreate(AfastamentoAnnotatedCreateDTO dto, P102AfastamentoJpaEntity saved) {
            // STEP_14 + STEP_15: Mark ready so getResourceMapper().toResponse(saved) writes outbox and masks SavedResult
            serviceSupport.markPostMutationReadyForOutboxAndMasking();
        }

        @Override
        protected void beforeUpdate(Long id, P102AfastamentoJpaEntity existing, AfastamentoAnnotatedUpdateDTO dto) {
            // STEP_11: Pre-hydration WriteIntent + DualScope authorization BEFORE validateUpdate (STEP_12)
            Map<String, Object> rawPayload = new java.util.LinkedHashMap<>();
            if (dto.substitutoServidorId() != null
                    && !Objects.equals(dto.substitutoServidorId(), existing.substitutoServidorId)) {
                rawPayload.put("substitutoServidorId", dto.substitutoServidorId());
            }
            if (dto.cidCodigo() != null
                    && !Objects.equals(dto.cidCodigo(), existing.cidCodigo)) {
                rawPayload.put("cidCodigo", dto.cidCodigo());
            }
            serviceSupport.authorizeBeforeHydrationAndRules(
                    blueprint.decisionPoint(),
                    blueprint.factContract().factContractDigest(),
                    "PATCH",
                    true,
                    rawPayload,
                    updateContract.wirePointerToAttributeIdMap(),
                    Set.of(),
                    Set.of("ergon.afastamentos.lotacao_setor_id"),
                    blueprint.dualScopeSpec(),
                    callerIsCedente.get(),
                    true,
                    Map.of(
                            "subject.principalId", "usr-gestor-101",
                            "subject.organizationUnitIds", List.of(100L),
                            "resource.lotacaoSetorId", existing.lotacaoSetorId
                    ),
                    Map.of(
                            "subject.principalId", FactResolutionStatus.PRESENT,
                            "subject.organizationUnitIds", FactResolutionStatus.PRESENT,
                            "resource.lotacaoSetorId", FactResolutionStatus.PRESENT
                    )
            );
        }

        @Override
        protected com.fasterxml.jackson.databind.JsonNode validateUpdate(
                ResourceMutationContext context,
                Long id,
                P102AfastamentoJpaEntity existing,
                AfastamentoAnnotatedUpdateDTO dto
        ) {
            // STEP_12: Domain rules execute on the RAW unmasked entity (P13, P14, P40)
            validateUpdateCalled.set(true);
            rawCidObservedInValidateUpdate.set(existing.cidCodigo);
            if (failInValidateUpdate.get()) {
                throw new IllegalStateException("Regra de domínio violada no STEP_12 (422)");
            }
            return null;
        }

        @Override
        protected void afterUpdate(Long id, P102AfastamentoJpaEntity saved, AfastamentoAnnotatedUpdateDTO dto) {
            // STEP_14 + STEP_15: Mark ready so getResourceMapper().toResponse(saved) writes outbox and masks DTO
            serviceSupport.markPostMutationReadyForOutboxAndMasking();
        }

        @Override
        protected void beforeDelete(Long id, P102AfastamentoJpaEntity existing) {
            // STEP_11: Pre-delete DualScope + OPA authorization BEFORE validateDelete (STEP_12)
            serviceSupport.authorizeBeforeDelete(
                    blueprint.decisionPoint(),
                    blueprint.factContract().factContractDigest(),
                    blueprint.dualScopeSpec(),
                    callerIsCedente.get(),
                    true,
                    Map.of(
                            "subject.principalId", "usr-gestor-101",
                            "subject.organizationUnitIds", List.of(100L),
                            "resource.lotacaoSetorId", existing.lotacaoSetorId
                    ),
                    Map.of(
                            "subject.principalId", FactResolutionStatus.PRESENT,
                            "subject.organizationUnitIds", FactResolutionStatus.PRESENT,
                            "resource.lotacaoSetorId", FactResolutionStatus.PRESENT
                    )
            );
        }

        @Override
        protected void validateDelete(ResourceMutationContext context, Long id, P102AfastamentoJpaEntity existing) {
            validateDeleteCalled.set(true);
        }

        @Override
        protected void afterDelete(Long id, P102AfastamentoJpaEntity deleted) {
            // STEP_14: Fulfill BEFORE_COMMIT_OUTBOX atomically in FIFO order (since delete returns void and skips toResponse)
            serviceSupport.completeAfterDeleteOutbox();
        }

        @Override
        protected void enrichResponses(List<AfastamentoAnnotatedResponseDTO> responses) {
            serviceSupport.completeBatchEnrichResponses();
        }

        @Override
        protected List<CollectionExportField> exportFields() {
            return List.of(
                    new CollectionExportField("id", "ID", true, true, "number", "id"),
                    new CollectionExportField("orgCedenteId", "Órgão Cedente", true, true, "number", "orgCedenteId"),
                    new CollectionExportField("lotacaoSetorId", "Setor Lotação", true, true, "number", "lotacaoSetorId"),
                    new CollectionExportField("substitutoServidorId", "Substituto", true, true, "number", "substitutoServidorId"),
                    new CollectionExportField("cidCodigo", "CID Médico", true, true, "text", "cidCodigo")
            );
        }

        @Override
        public OptionSourceRegistry getDeclaredOptionSourceRegistry() {
            EntityLookupDescriptor lookupDescriptor = new EntityLookupDescriptor(
                    blueprint.resourceKey(),
                    "id",
                    List.of("statusAfastamento", "cidCodigo"),
                    "statusAfastamento",
                    null,
                    null,
                    List.of("statusAfastamento"),
                    Map.of(),
                    new LookupSelectionPolicy(
                            null,
                            "statusAfastamento",
                            List.of("DEFERIDO", "HOMOLOGADO"),
                            List.of("REVOGADO"),
                            true,
                            "Afastamento #{id} em situação {status}",
                            "Afastamento não selecionável"
                    ),
                    LookupCapabilities.standardDirectory(),
                    null,
                    new LookupDisplayDescriptor(
                            "directory",
                            "form",
                            "comfortable",
                            "chip",
                            "card",
                            "statusAfastamento",
                            List.of(
                                    new LookupDisplayFieldDescriptor("statusAfastamento", "statusAfastamento", "Situação", null, "badge", null, "text"),
                                    new LookupDisplayFieldDescriptor("cidCodigo", "cidCodigo", "CID", null, "secondary", null, "text")
                            ),
                            List.of("cidCodigo"),
                            List.of("statusAfastamento"),
                            null,
                            false,
                            true,
                            true,
                            true,
                            true,
                            true,
                            2
                    ),
                    null
            );
            OptionSourceDescriptor descriptor = new OptionSourceDescriptor(
                    "afastamentoLookup",
                    OptionSourceType.RESOURCE_ENTITY,
                    "/api/human-resources/afastamentos",
                    "id",
                    "id",
                    "statusAfastamento",
                    "id",
                    List.of(),
                    Map.of(),
                    OptionSourcePolicy.defaults(),
                    lookupDescriptor
            );
            return OptionSourceRegistry.builder()
                    .add(P102AfastamentoJpaEntity.class, descriptor)
                    .build();
        }

        @Override
        public StatsSupportMode getGroupByStatsSupportMode() {
            return StatsSupportMode.AUTO;
        }

        @Override
        public StatsSupportMode getDistributionStatsSupportMode() {
            return StatsSupportMode.AUTO;
        }

        @Override
        public StatsFieldRegistry getStatsFieldRegistry() {
            return StatsFieldRegistry.builder()
                    .categoricalGroupByBucket("statusAfastamento", "statusAfastamento")
                    .categoricalTermsBucket("statusAfastamentoTerm", "statusAfastamento")
                    .numericMeasureField("substitutoServidorId", "substitutoServidorId")
                    // Intentionally registered to prove both discovery-time filtering and runtime FieldUseViolationException blocking!
                    .categoricalGroupByBucket("cidCodigo", "cidCodigo")
                    .build();
        }
    }

    /** Command request DTO for @WorkflowAction "homologar-afastamento" (Fase P10.4). */
    record HomologarAfastamentoCommandDTO(
            @DomainLineage(attributeId = "ergon.afastamentos.status_afastamento") String statusAfastamento,
            @DomainLineage(attributeId = "ergon.afastamentos.substituto_servidor_id") Long substitutoServidorId
    ) {}

    /**
     * Real versioned subclass implementing {@link VersionedCreateUpdateResourceService}
     * from {@code praxis-metadata-starter} (Fase P10.3 & Fase P10.4).
     */
    static final class VersionedAfastamentoGovernedResourceService
            extends AfastamentoGovernedResourceService
            implements VersionedCreateUpdateResourceService<
                    AfastamentoAnnotatedResponseDTO,
                    Long,
                    AfastamentoFilterDTO,
                    AfastamentoAnnotatedCreateDTO,
                    AfastamentoAnnotatedUpdateDTO
            > {

        private final AfastamentoAuthzPilotBlueprint blueprint;
        private final AuthzGovernedResourceServiceSupport serviceSupport;
        private final IntrospectedDtoGovernanceContract homologarContract;

        VersionedAfastamentoGovernedResourceService(
                P102AfastamentoRepository repository,
                AfastamentoAuthzPilotBlueprint blueprint,
                AuthzGovernedResourceServiceSupport serviceSupport,
                JpaDataScopeAdapter jpaAdapter,
                JpaCriteriaDataScopeTranslator criteriaTranslator
        ) {
            super(repository, blueprint, serviceSupport, jpaAdapter, criteriaTranslator);
            this.blueprint = blueprint;
            this.serviceSupport = serviceSupport;
            this.homologarContract = serviceSupport.dtoIntrospector()
                    .introspect(HomologarAfastamentoCommandDTO.class, blueprint.resourceKey());
        }

        @Override
        public AfastamentoAnnotatedResponseDTO update(Long id, AfastamentoAnnotatedUpdateDTO dto) {
            throw ResourceVersionPreconditionException.required();
        }

        @Override
        public ResourceRepresentationResult<AfastamentoAnnotatedResponseDTO> update(
                Long id,
                AfastamentoAnnotatedUpdateDTO dto,
                ResourceVersionUpdatePrecondition<Long> precondition
        ) {
            return super.update(id, dto, precondition);
        }

        /**
         * Governed @WorkflowAction domain command ("homologar-afastamento") executed via
         * {@link AbstractBaseResourceService#executeVersionedMutation} (Fase P10.4).
         */
        ResourceRepresentationResult<AfastamentoAnnotatedResponseDTO> homologarAfastamento(
                Long id,
                HomologarAfastamentoCommandDTO commandDto,
                ResourceVersionUpdatePrecondition<Long> precondition
        ) {
            return executeVersionedMutation(id, precondition, entity -> {
                Map<String, Object> rawPayload = new java.util.LinkedHashMap<>();
                if (commandDto.statusAfastamento() != null) {
                    rawPayload.put("statusAfastamento", commandDto.statusAfastamento());
                }
                if (commandDto.substitutoServidorId() != null) {
                    rawPayload.put("substitutoServidorId", commandDto.substitutoServidorId());
                }
                // STEP_11: Pre-mutation WriteIntent + DualScope authorization inside command transaction
                serviceSupport.authorizeBeforeHydrationAndRules(
                        blueprint.decisionPoint(),
                        blueprint.factContract().factContractDigest(),
                        "POST",
                        true,
                        rawPayload,
                        homologarContract.wirePointerToAttributeIdMap(),
                        Set.of(),
                        Set.of("ergon.afastamentos.lotacao_setor_id"),
                        blueprint.dualScopeSpec(),
                        callerIsCedente.get(),
                        true,
                        Map.of(
                                "subject.principalId", "usr-gestor-101",
                                "subject.organizationUnitIds", List.of(100L),
                                "resource.lotacaoSetorId", entity.lotacaoSetorId
                        ),
                        Map.of(
                                "subject.principalId", FactResolutionStatus.PRESENT,
                                "subject.organizationUnitIds", FactResolutionStatus.PRESENT,
                                "resource.lotacaoSetorId", FactResolutionStatus.PRESENT
                        )
                );
                // STEP_12 / STEP_13: Apply domain state transition on raw unmasked entity
                if (commandDto.statusAfastamento() != null) {
                    entity.statusAfastamento = commandDto.statusAfastamento();
                }
                if (commandDto.substitutoServidorId() != null) {
                    entity.substitutoServidorId = commandDto.substitutoServidorId();
                }
                // STEP_14 + STEP_15: Mark ready so toResourceRepresentation(saved) writes outbox and masks DTO
                serviceSupport.markPostMutationReadyForOutboxAndMasking();
            });
        }
    }

    @Test
    void verifyP102MetadataDtoGovernanceIntrospectionAndRealAbstractBaseResourceServiceLifecycle() throws Exception {
        AfastamentoAuthzPilotBlueprint blueprint = AfastamentoAuthzPilotBlueprint.createErgonAfastamentoBlueprint();

        // 1. Verify MetadataDtoGovernanceIntrospector automatically extracts @DomainLineage, @DomainGovernance, and @Schema
        MetadataDtoGovernanceIntrospector introspector = new MetadataDtoGovernanceIntrospector();
        IntrospectedDtoGovernanceContract responseContract = introspector.introspect(
                AfastamentoAnnotatedResponseDTO.class,
                blueprint.resourceKey()
        );
        assertEquals(8, responseContract.fieldSchemas().size());
        assertTrue(responseContract.nonExportableFieldNames().contains("orgCedenteId"));
        assertTrue(responseContract.nonExportableFieldNames().contains("ergon.afastamentos.cedente_orgao_id"));
        assertTrue(responseContract.nonExportableFieldNames().contains("cidCodigo"),
                "LGPD_SENSITIVE_DATA preset has exportable = false and must be auto-detected");
        assertTrue(responseContract.nonExportableFieldNames().contains("ergon.afastamentos.cid_codigo"));
        assertEquals("ergon.afastamentos.cid_codigo", responseContract.wirePointerToAttributeIdMap().get("/cidCodigo"));
        assertEquals("ergon.afastamentos.substituto_servidor_id",
                responseContract.wirePointerToAttributeIdMap().get("/substitutoServidorId"));

        // Verify LGPD_SENSITIVE_DATA generated baseline DENY directives for FILTER, SORT, GROUP, AGGREGATE, JOIN + AI_CONTEXT denied
        List<FieldUseEffectDirective> cidDirectives = responseContract.baselineFieldUseDirectives().stream()
                .filter(d -> "ergon.afastamentos.cid_codigo".equals(d.attributeId()) && d.effect() == RuleEffect.DENY)
                .toList();
        assertEquals(5, cidDirectives.size());
        assertTrue(responseContract.aiContextDeniedAttributeIds().contains("ergon.afastamentos.cid_codigo"));
        assertTrue(responseContract.aiContextDeniedAttributeIds().contains("cidCodigo"));

        // Verify DomainLineage anti-weakening enforcement (P46/P49)
        assertThrows(IllegalArgumentException.class, () ->
                introspector.introspect(WeakenedAfastamentoDto.class, blueprint.resourceKey())
        );

        // Verify POJO inheritance deduplication, interface @NotNull, and getter @DomainLineage (P10.2-R02)
        IntrospectedDtoGovernanceContract subPojoContract = introspector.introspect(
                SubPojoDto.class,
                blueprint.resourceKey()
        );
        assertEquals(3, subPojoContract.fieldSchemas().size(),
                "Shadowed field statusAfastamento must be deduplicated across SuperPojoDto and SubPojoDto");
        assertEquals("id", subPojoContract.fieldSchemas().get(0).wireFieldName());
        assertFalse(subPojoContract.fieldSchemas().get(0).nullable(),
                "@NotNull on interface getter getId() must infer nullable = false");
        assertEquals("statusAfastamento", subPojoContract.fieldSchemas().get(1).wireFieldName());
        assertFalse(subPojoContract.fieldSchemas().get(1).nullable(),
                "@NotNull on subclass field statusAfastamento must infer nullable = false");
        assertTrue(subPojoContract.nonExportableFieldNames().contains("cidCodigo"),
                "Getter @DomainLineage on SubPojoDto.getCidCodigo() must inherit LGPD_SENSITIVE_DATA");

        // 2. Boot real H2 + Hibernate JPA + Spring Data BaseCrudRepository + JdbcTransactionalAuditOutbox
        String dbName = "p102_service_" + UUID.randomUUID().toString().replace("-", "");
        DriverManagerDataSource dataSource = new DriverManagerDataSource(
                "jdbc:h2:mem:" + dbName + ";DB_CLOSE_DELAY=-1;MODE=PostgreSQL",
                "sa",
                ""
        );
        LocalContainerEntityManagerFactoryBean emfBean = new LocalContainerEntityManagerFactoryBean();
        emfBean.setDataSource(dataSource);
        emfBean.setPackagesToScan(P102RealAbstractBaseResourceServiceIntegrationTest.class.getPackageName());
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

        OpaAuthorizationProviderAdapter opaAdapter = new OpaAuthorizationProviderAdapter(
                blueprint.localOpaTransport(), new SameInstanceSearchRevisionGuard(1)
        );
        DetachedDtoMaskingProcessor maskingProcessor = new DetachedDtoMaskingProcessor();
        List<SanitizedDecisionTelemetryEvent> recordedTelemetry = new java.util.concurrent.CopyOnWriteArrayList<>();
        SanitizedAuthorizationTelemetryPublisher telemetryPublisher =
                new SanitizedAuthorizationTelemetryPublisher(List.of(recordedTelemetry::add), 100);
        MetadataResourceAuthorizationSeam seam = new MetadataResourceAuthorizationSeam(
                opaAdapter,
                new FieldUseQueryGuard(),
                new DtoWriteIntentExtractor(),
                new FieldWriteAuthorizer(),
                maskingProcessor,
                new ObligationBarrierCoordinator(new DefaultObligationHandlerRegistry(), jdbcOutbox),
                telemetryPublisher
        );
        AuthzGovernedResourceServiceSupport serviceSupport =
                new AuthzGovernedResourceServiceSupport(seam, maskingProcessor, introspector);

        JpaDataScopeAdapter jpaAdapter = new JpaDataScopeAdapter(
                blueprint.queryProjection(),
                List.of(new QueryAdapterFieldBinding(
                        blueprint.resourceKey(),
                        "resource.lotacaoSetorId",
                        "ergon.afastamentos.lotacao_setor_id",
                        "lotacaoSetorId",
                        RelationTraversalStrategy.INNER_JOIN_SCALAR,
                        true
                ))
        );
        JpaCriteriaDataScopeTranslator criteriaTranslator = new JpaCriteriaDataScopeTranslator(
                blueprint.queryProjection(),
                List.of(new QueryAdapterFieldBinding(
                        blueprint.resourceKey(),
                        "resource.lotacaoSetorId",
                        "ergon.afastamentos.lotacao_setor_id",
                        "lotacaoSetorId",
                        RelationTraversalStrategy.INNER_JOIN_SCALAR,
                        true
                ))
        );

        // Create real Spring Data JPA BaseCrudRepository via JpaRepositoryFactory
        P102AfastamentoRepository repository = new JpaRepositoryFactory(sharedEm)
                .getRepository(P102AfastamentoRepository.class);

        AfastamentoGovernedResourceService service = new AfastamentoGovernedResourceService(
                repository,
                blueprint,
                serviceSupport,
                jpaAdapter,
                criteriaTranslator
        );

        // Inject EntityManager and dynamic AuthzGovernedCollectionExportExecutor (P10.2-R03) into AbstractBaseQueryResourceService
        Field emField = AbstractBaseQueryResourceService.class.getDeclaredField("entityManager");
        emField.setAccessible(true);
        emField.set(service, sharedEm);

        CollectionExportExecutor governedExportExecutor = serviceSupport.wrapCollectionExportExecutor(
                new DefaultCollectionExportExecutor(List.of(new CsvCollectionExportEngine())),
                AfastamentoAnnotatedResponseDTO.class,
                blueprint.resourceKey()
        );
        Field exportExecField = AbstractBaseQueryResourceService.class.getDeclaredField("collectionExportExecutor");
        exportExecField.setAccessible(true);
        exportExecField.set(service, governedExportExecutor);

        // Seed 3 rows via repository
        txTemplate.executeWithoutResult(status -> {
            repository.save(new P102AfastamentoJpaEntity(
                    101L, "tenant-gov-br", 1L, 2L, 100L, "DEFERIDO", 5001L, "M54.5"));
            repository.save(new P102AfastamentoJpaEntity(
                    102L, "tenant-gov-br", 1L, 2L, 999L, "DEFERIDO", 5002L, "F32.0"));
            repository.save(new P102AfastamentoJpaEntity(
                    103L, "tenant-outro", 1L, 2L, 100L, "DEFERIDO", 5003L, "A09"));
        });

        // 3. Execute REAL AbstractBaseQueryResourceService.filter(...)
        Page<AfastamentoAnnotatedResponseDTO> page = txTemplate.execute(status ->
                service.filter(new AfastamentoFilterDTO(), PageRequest.of(0, 10), List.of())
        );
        assertNotNull(page);
        assertEquals(1L, page.getTotalElements());
        AfastamentoAnnotatedResponseDTO dto101 = page.getContent().getFirst();
        assertEquals(101L, dto101.id());
        assertEquals("***CID-RESTRITO***", dto101.cidCodigo());

        // Verify managed JPA entity in database STILL has raw "M54.5" (P13, P40)
        txTemplate.executeWithoutResult(status -> {
            P102AfastamentoJpaEntity rawInDb = sharedEm.find(P102AfastamentoJpaEntity.class, 101L);
            assertEquals("M54.5", rawInDb.cidCodigo);
        });

        // 4. Execute REAL AbstractBaseQueryResourceService.findById(...) for authorized (#101) and out-of-scope (#102)
        ResourceRepresentationResult<AfastamentoAnnotatedResponseDTO> byId101 = txTemplate.execute(status ->
                service.findById(101L)
        );
        assertNotNull(byId101);
        assertEquals("***CID-RESTRITO***", byId101.body().cidCodigo());

        assertThrows(SecurityException.class, () ->
                txTemplate.execute(status -> service.findById(102L))
        );

        // 4b. Verify prepareUpdateValidationDraft (P10.2-R01) observes RAW unmasked "M54.5" even when called before beforeUpdate
        AfastamentoAnnotatedResponseDTO draftDto = service.invokePrepareUpdateValidationDraft(
                101L,
                new P102AfastamentoJpaEntity(101L, "tenant-gov-br", 1L, 2L, 100L, "DEFERIDO", 5001L, "M54.5"),
                new AfastamentoAnnotatedUpdateDTO(8888L, null)
        );
        assertEquals("M54.5", draftDto.cidCodigo(),
                "prepareUpdateValidationDraft must observe raw unmasked CID 'M54.5' (P13, P14)");
        assertEquals(8888L, draftDto.substitutoServidorId());

        // 5. Execute REAL AbstractBaseResourceService.update(...) with forbidden cidCodigo modification
        // Must fail closed in beforeUpdate (STEP_11) BEFORE validateUpdate (STEP_12) is ever called!
        service.validateUpdateCalled.set(false);
        assertThrows(FieldWriteViolationException.class, () ->
                txTemplate.execute(status ->
                        service.update(101L, new AfastamentoAnnotatedUpdateDTO(7777L, "Z00.0"))
                )
        );
        assertFalse(service.validateUpdateCalled.get(),
                "STEP_11 FieldWriteAuthorizer must block forbidden cidCodigo write BEFORE validateUpdate (STEP_12)");
        assertTrue(jdbcOutbox.listCommittedEntries().isEmpty());

        // 5b. Verify mid-mutation exception in STEP_12 (validateUpdate) rolls back cleanly and NEVER poisons subsequent filter() (P10.2-R01)
        service.failInValidateUpdate.set(true);
        try {
            assertThrows(IllegalStateException.class, () ->
                    txTemplate.execute(status ->
                            service.update(101L, new AfastamentoAnnotatedUpdateDTO(8888L, null))
                    )
            );
        } finally {
            service.failInValidateUpdate.set(false);
        }
        assertTrue(jdbcOutbox.listCommittedEntries().isEmpty(),
                "Rolled-back STEP_12 failure must not commit any outbox entry");
        Page<AfastamentoAnnotatedResponseDTO> pageAfterRollback = txTemplate.execute(status ->
                service.filter(new AfastamentoFilterDTO(), PageRequest.of(0, 10), List.of())
        );
        assertNotNull(pageAfterRollback);
        assertEquals("***CID-RESTRITO***", pageAfterRollback.getContent().getFirst().cidCodigo(),
                "Subsequent query on same thread after STEP_12 exception must still mask cidCodigo (P10.2-R01)");

        // 6. Execute REAL AbstractBaseResourceService.update(...) with permitted substitutoServidorId modification
        // Must run STEP_11 -> STEP_12 (seeing raw "M54.5") -> save -> STEP_14 outbox -> STEP_15 masked ResponseDTO!
        AfastamentoAnnotatedResponseDTO updatedDto = txTemplate.execute(status ->
                service.update(101L, new AfastamentoAnnotatedUpdateDTO(9999L, null))
        );
        assertNotNull(updatedDto);
        assertTrue(service.validateUpdateCalled.get());
        assertEquals("M54.5", service.rawCidObservedInValidateUpdate.get(),
                "STEP_12 validateUpdate must observe raw unmasked cidCodigo 'M54.5'");
        assertEquals(9999L, updatedDto.substitutoServidorId());
        assertEquals("***CID-RESTRITO***", updatedDto.cidCodigo(),
                "STEP_15 response from service.update(...) must have masked cidCodigo");
        assertEquals(1, jdbcOutbox.listCommittedEntries().size(),
                "STEP_14 BEFORE_COMMIT_OUTBOX must commit atomically inside service.update(...)");

        // 7. Execute REAL AbstractBaseQueryResourceService.exportCollection(...)
        CollectionExportRequest<AfastamentoFilterDTO> exportReq = new CollectionExportRequest<>(
                "table", "tbl-afastamentos", "/api/human-resources/afastamentos",
                CollectionExportFormat.CSV, CollectionExportScope.ALL,
                null, null, new AfastamentoFilterDTO(), null, null, null,
                true, false, 100, "afastamentos.csv", null, null, Map.of()
        );
        CollectionExportResult exportResult = txTemplate.execute(status ->
                service.exportCollection(exportReq)
        );
        assertNotNull(exportResult);
        String csvText = new String(exportResult.content(), StandardCharsets.UTF_8);
        assertFalse(csvText.contains("M54.5"), "Exported CSV must never leak raw CID M54.5");
        assertFalse(csvText.contains("orgCedenteId"), "Exported CSV must exclude @DomainGovernance(exportable = false) field orgCedenteId");

        // 8. Fase P10.3: Execute REAL AbstractBaseResourceService.create(...)
        // 8a. Cessionário-only caller cannot create with Cedente-exclusive statusAfastamento (blocked at STEP_11 before validateCreate)
        service.callerIsCedente.set(false);
        service.validateCreateCalled.set(false);
        assertThrows(FieldWriteViolationException.class, () ->
                txTemplate.execute(status ->
                        service.create(new AfastamentoAnnotatedCreateDTO(
                                104L, "tenant-gov-br", 1L, 2L, 100L, "DEFERIDO", 6001L, null
                        ))
                )
        );
        assertFalse(service.validateCreateCalled.get(),
                "STEP_11 DualScope check must block Cessionário-only create on statusAfastamento BEFORE validateCreate (STEP_12)");
        assertEquals(1, jdbcOutbox.listCommittedEntries().size());

        // 8b. Cedente caller succeeds on create(dto) -> STEP_11 -> STEP_12 -> save -> STEP_14 outbox -> STEP_15 masked SavedResult
        service.callerIsCedente.set(true);
        var saved104 = txTemplate.execute(status ->
                service.create(new AfastamentoAnnotatedCreateDTO(
                        104L, "tenant-gov-br", 1L, 2L, 100L, "DEFERIDO", 6001L, null
                ))
        );
        assertNotNull(saved104);
        assertTrue(service.validateCreateCalled.get());
        assertEquals(104L, saved104.id());
        assertEquals("***CID-RESTRITO***", saved104.body().cidCodigo(),
                "STEP_15 SavedResult.body() from service.create(...) must have masked cidCodigo");
        assertEquals(2, jdbcOutbox.listCommittedEntries().size(),
                "STEP_14 BEFORE_COMMIT_OUTBOX must commit atomically inside service.create(...)");

        // Also create #105 so we can test batch deleteAllById(List.of(104L, 105L))
        var saved105 = txTemplate.execute(status ->
                service.create(new AfastamentoAnnotatedCreateDTO(
                        105L, "tenant-gov-br", 1L, 2L, 100L, "DEFERIDO", 6002L, null
                ))
        );
        assertNotNull(saved105);
        assertEquals(3, jdbcOutbox.listCommittedEntries().size());

        // 9. Fase P10.3: Execute REAL AbstractBaseResourceService.deleteById(...) and deleteAllById(...)
        // 9a. Cessionário-only caller cannot delete a Dual-Scope entity with Cedente-exclusive attributes
        service.callerIsCedente.set(false);
        service.validateDeleteCalled.set(false);
        FieldWriteViolationException deleteViolation = assertThrows(FieldWriteViolationException.class, () ->
                txTemplate.executeWithoutResult(status -> service.deleteById(104L))
        );
        assertTrue(deleteViolation.getReasonCode().startsWith("AUTHZ_DUAL_SCOPE_DELETE_REQUIRES_CEDENTE"));
        assertFalse(service.validateDeleteCalled.get(),
                "STEP_11 DualScope delete guard must block Cessionário-only delete BEFORE validateDelete (STEP_12)");
        assertEquals(3, jdbcOutbox.listCommittedEntries().size());

        // 9b. Cedente caller executes batch deleteAllById(List.of(104L, 105L)) -> 2 beforeDelete + 2 afterDelete in FIFO order
        service.callerIsCedente.set(true);
        txTemplate.executeWithoutResult(status ->
                service.deleteAllById(List.of(104L, 105L))
        );
        assertTrue(service.validateDeleteCalled.get());
        assertEquals(5, jdbcOutbox.listCommittedEntries().size(),
                "Batch deleteAllById([104, 105]) must commit 2 BEFORE_COMMIT_OUTBOX entries in FIFO order via completeAfterDeleteOutbox()");

        // 10. Fase P10.3: Execute REAL VersionedCreateUpdateResourceService (If-Match / @Version optimistic locking)
        VersionedAfastamentoGovernedResourceService versionedService = new VersionedAfastamentoGovernedResourceService(
                repository,
                blueprint,
                serviceSupport,
                jpaAdapter,
                criteriaTranslator
        );
        emField.set(versionedService, sharedEm);
        exportExecField.set(versionedService, governedExportExecutor);

        ResourceVersionEtagService etagService = new ResourceVersionEtagService("p103-version-etag-secret-key");

        // 10a. Unversioned 2-arg update(id, dto) must fail closed with ResourceVersionPreconditionException (428 Precondition Required)
        assertThrows(ResourceVersionPreconditionException.class, () ->
                txTemplate.execute(status ->
                        versionedService.update(101L, new AfastamentoAnnotatedUpdateDTO(7001L, null))
                )
        );

        // Read current persisted version of #101 via findById(101L)
        ResourceRepresentationResult<AfastamentoAnnotatedResponseDTO> currentRep101 = txTemplate.execute(status ->
                versionedService.findById(101L)
        );
        assertNotNull(currentRep101);
        long currentVersion101 = currentRep101.requirePersistedVersion();

        // 10b. Stale If-Match precondition must fail closed BEFORE beforeUpdate (STEP_11) or validateUpdate (STEP_12)
        versionedService.validateUpdateCalled.set(false);
        String staleIfMatch = etagService.create(blueprint.resourceKey(), 101L, currentVersion101 + 99L);
        ResourceVersionUpdatePrecondition<Long> stalePrecondition = new ResourceVersionUpdatePrecondition<>(
                etagService, staleIfMatch, blueprint.resourceKey(), 101L
        );
        assertThrows(ResourceVersionPreconditionException.class, () ->
                txTemplate.execute(status ->
                        versionedService.update(101L, new AfastamentoAnnotatedUpdateDTO(7001L, null), stalePrecondition)
                )
        );
        assertFalse(versionedService.validateUpdateCalled.get(),
                "Stale If-Match precondition must reject in lockEntityForVersionedUpdate BEFORE STEP_11/STEP_12");
        assertEquals(5, jdbcOutbox.listCommittedEntries().size());

        // 10c. Matching If-Match precondition succeeds -> increments @Version, commits outbox, and returns masked body
        String validIfMatch = etagService.create(blueprint.resourceKey(), 101L, currentVersion101);
        ResourceVersionUpdatePrecondition<Long> validPrecondition = new ResourceVersionUpdatePrecondition<>(
                etagService, validIfMatch, blueprint.resourceKey(), 101L
        );
        ResourceRepresentationResult<AfastamentoAnnotatedResponseDTO> versionedUpdated = txTemplate.execute(status ->
                versionedService.update(101L, new AfastamentoAnnotatedUpdateDTO(7002L, null), validPrecondition)
        );
        assertNotNull(versionedUpdated);
        assertEquals(currentVersion101 + 1L, versionedUpdated.requirePersistedVersion(),
                "Versioned update must flush and return incremented @Version");
        assertEquals(7002L, versionedUpdated.body().substitutoServidorId());
        assertEquals("***CID-RESTRITO***", versionedUpdated.body().cidCodigo(),
                "Versioned update response must mask cidCodigo via AuthzMaskingResourceMapperDecorator");
        assertEquals(6, jdbcOutbox.listCommittedEntries().size(),
                "Versioned update must commit BEFORE_COMMIT_OUTBOX entry atomically");

        // 11. Fase P10.4: Contextual Discovery (AuthzResourceOperationAvailabilityProvider + Action/Surface Evaluators)
        // and Governed Command Execution (@WorkflowAction + GovernedResourceCommandExecutor)
        ResourceStateSnapshotProvider snapshotProvider = (resourceKey, resourceId) -> {
            if (!blueprint.resourceKey().equals(resourceKey) || !(resourceId instanceof Long id)) {
                return Optional.empty();
            }
            return txTemplate.execute(status ->
                    repository.findById(id).map(e -> ResourceStateSnapshot.of(
                            e.statusAfastamento,
                            Map.of("lotacaoSetorId", e.lotacaoSetorId)
                    ))
            );
        };

        AuthzResourceOperationAvailabilityProvider availabilityProvider =
                serviceSupport.createAvailabilityProvider(snapshotProvider);
        availabilityProvider.registerResourceBinding(new ResourceAvailabilityPolicyBinding(
                blueprint.resourceKey(),
                blueprint.decisionPoint(),
                blueprint.factContract().factContractDigest(),
                blueprint.dualScopeSpec(),
                Map.of(
                        "homologar-afastamento", Set.of("ergon.afastamentos.status_afastamento"),
                        "designar-substituto", Set.of("ergon.afastamentos.substituto_servidor_id"),
                        "alterar-cid-medico", Set.of("ergon.afastamentos.cid_codigo")
                ),
                () -> new CallerAvailabilityFactContext(
                        Map.of(
                                "subject.principalId", "usr-gestor-101",
                                "subject.organizationUnitIds", List.of(100L)
                        ),
                        Map.of(
                                "subject.principalId", FactResolutionStatus.PRESENT,
                                "subject.organizationUnitIds", FactResolutionStatus.PRESENT
                        ),
                        versionedService.callerIsCedente.get(),
                        !versionedService.callerIsCedente.get()
                ),
                snapshot -> {
                    Object setor = snapshot.metadata().get("lotacaoSetorId");
                    return setor != null ? Map.of("resource.lotacaoSetorId", setor) : Map.of();
                }
        ));

        // 11a. Collection-scoped operations never leak item state and are permitted for in-scope caller
        AvailabilityDecision collectionFilterDecision = availabilityProvider.evaluate(
                ResourceOperationAvailabilityContext.collection(
                        blueprint.resourceKey(), "/api/human-resources/afastamentos", "filter"
                )
        );
        assertTrue(collectionFilterDecision.allowed());
        assertEquals(Boolean.TRUE, collectionFilterDecision.metadata().get("advisoryOnly"));
        assertEquals(Boolean.TRUE, collectionFilterDecision.metadata().get("revalidatedOnExecution"));

        // 11b. Item-scoped view on out-of-scope #102 (lotacaoSetorId = 999L) is denied by OPA TARGET gate
        AvailabilityDecision view102Decision = availabilityProvider.evaluate(
                ResourceOperationAvailabilityContext.item(
                        blueprint.resourceKey(), "/api/human-resources/afastamentos", "view", 102L
                )
        );
        assertFalse(view102Decision.allowed());
        assertEquals("policy-gate-denied", view102Decision.reason());

        // 11c. Item-scoped delete on #101 is denied for Cessionário-only and allowed for Cedente
        versionedService.callerIsCedente.set(false);
        AvailabilityDecision delete101Cessionario = availabilityProvider.evaluate(
                ResourceOperationAvailabilityContext.item(
                        blueprint.resourceKey(), "/api/human-resources/afastamentos", "delete", 101L
                )
        );
        assertFalse(delete101Cessionario.allowed());
        assertEquals("dual-scope-cedente-custody-required", delete101Cessionario.reason());

        versionedService.callerIsCedente.set(true);
        AvailabilityDecision delete101Cedente = availabilityProvider.evaluate(
                ResourceOperationAvailabilityContext.item(
                        blueprint.resourceKey(), "/api/human-resources/afastamentos", "delete", 101L
                )
        );
        assertTrue(delete101Cedente.allowed());

        // 11d. DefaultActionAvailabilityEvaluator + DefaultSurfaceAvailabilityEvaluator from praxis-metadata-starter
        DefaultActionAvailabilityEvaluator actionEvaluator = new DefaultActionAvailabilityEvaluator(List.of(
                new ContextualActionAvailabilityRule(),
                new RequiredAuthoritiesActionAvailabilityRule(),
                new AllowedStatesActionAvailabilityRule(),
                availabilityProvider
        ));
        DefaultSurfaceAvailabilityEvaluator surfaceEvaluator = new DefaultSurfaceAvailabilityEvaluator(List.of(
                new RequiredAuthoritiesSurfaceAvailabilityRule(),
                new ContextualSurfaceAvailabilityRule(),
                new AllowedStatesSurfaceAvailabilityRule(),
                availabilityProvider
        ));

        ActionDefinition homologarActionDef = new ActionDefinition(
                "homologar-afastamento", blueprint.resourceKey(), "/api/human-resources/afastamentos",
                "human-resources", ActionScope.ITEM, "Homologar Afastamento", "Homologa o afastamento funcional",
                null, null, null, 10, "Homologado", List.of(), List.of("DEFERIDO"), List.of(),
                ActionExecutionContract.defaults(ActionScope.ITEM)
        );
        ActionDefinition designarActionDef = new ActionDefinition(
                "designar-substituto", blueprint.resourceKey(), "/api/human-resources/afastamentos",
                "human-resources", ActionScope.ITEM, "Designar Substituto", "Designa servidor substituto",
                null, null, null, 20, "Substituto designado", List.of(), List.of("DEFERIDO"), List.of(),
                ActionExecutionContract.defaults(ActionScope.ITEM)
        );
        ActionDefinition alterarCidActionDef = new ActionDefinition(
                "alterar-cid-medico", blueprint.resourceKey(), "/api/human-resources/afastamentos",
                "human-resources", ActionScope.ITEM, "Alterar CID", "Altera CID médico",
                null, null, null, 30, "CID alterado", List.of(), List.of("DEFERIDO"), List.of(),
                ActionExecutionContract.defaults(ActionScope.ITEM)
        );

        ResourceStateSnapshot snapshot101 = snapshotProvider.resolve(blueprint.resourceKey(), 101L).orElseThrow();
        ActionAvailabilityContext actionCtx101 = new ActionAvailabilityContext(
                blueprint.resourceKey(), "/api/human-resources/afastamentos", 101L,
                "tenant-gov-br", Locale.ROOT, () -> "usr-gestor-101", Set.of("ROLE_GESTOR"), snapshot101
        );

        // Pure Cessionário (callerIsCedente = false, callerMatchesCessionario = true):
        // designar-substituto = ALLOW, homologar-afastamento = DENY (dual-scope), alterar-cid-medico = DENY (dual-scope)
        versionedService.callerIsCedente.set(false);
        assertTrue(actionEvaluator.evaluate(designarActionDef, actionCtx101).allowed());
        AvailabilityDecision homologarCessionario = actionEvaluator.evaluate(homologarActionDef, actionCtx101);
        assertFalse(homologarCessionario.allowed());
        assertEquals("dual-scope-custody-denied", homologarCessionario.reason());
        assertFalse(actionEvaluator.evaluate(alterarCidActionDef, actionCtx101).allowed());

        // Pure Cedente (callerIsCedente = true, callerMatchesCessionario = false):
        // homologar-afastamento = ALLOW, alterar-cid-medico = ALLOW, designar-substituto = DENY (Cessionário-exclusive partition)
        versionedService.callerIsCedente.set(true);
        assertTrue(actionEvaluator.evaluate(homologarActionDef, actionCtx101).allowed());
        assertTrue(actionEvaluator.evaluate(alterarCidActionDef, actionCtx101).allowed());
        AvailabilityDecision designarPureCedente = actionEvaluator.evaluate(designarActionDef, actionCtx101);
        assertFalse(designarPureCedente.allowed());
        assertEquals("dual-scope-custody-denied", designarPureCedente.reason());

        // Surface evaluation: detail surface allowed on #101, denied on out-of-scope #102
        SurfaceDefinition detailSurfaceDef = new SurfaceDefinition(
                "detail", blueprint.resourceKey(), "/api/human-resources/afastamentos",
                "human-resources", SurfaceKind.VIEW, SurfaceScope.ITEM, "Visão 360°", "Detalhe do afastamento",
                "detail", "visibility", "response", SurfaceResponseCardinality.OBJECT,
                null, null, 1, List.of(), List.of(), List.of(), null
        );
        SurfaceAvailabilityContext surfaceCtx101 = new SurfaceAvailabilityContext(
                blueprint.resourceKey(), "/api/human-resources/afastamentos", 101L,
                "tenant-gov-br", Locale.ROOT, () -> "usr-gestor-101", Set.of("ROLE_GESTOR"), snapshot101
        );
        ResourceStateSnapshot snapshot102 = snapshotProvider.resolve(blueprint.resourceKey(), 102L).orElseThrow();
        SurfaceAvailabilityContext surfaceCtx102 = new SurfaceAvailabilityContext(
                blueprint.resourceKey(), "/api/human-resources/afastamentos", 102L,
                "tenant-gov-br", Locale.ROOT, () -> "usr-gestor-101", Set.of("ROLE_GESTOR"), snapshot102
        );
        assertTrue(surfaceEvaluator.evaluate(detailSurfaceDef, surfaceCtx101).allowed());
        assertFalse(surfaceEvaluator.evaluate(detailSurfaceDef, surfaceCtx102).allowed());

        // 11e. GovernedResourceCommandExecutor from praxis-metadata-starter
        AtomicReference<ResourceVersionUpdatePrecondition<Long>> activeCommandPrecondition = new AtomicReference<>();
        GovernedResourceCommandExecutor commandExecutor = new GovernedResourceCommandExecutor(
                serviceSupport.wrapCommandExecutionProvider(cmdReq -> {
                    HomologarAfastamentoCommandDTO payload = (HomologarAfastamentoCommandDTO) cmdReq.payload();
                    Long targetId = (Long) cmdReq.resourceId();
                    ResourceRepresentationResult<AfastamentoAnnotatedResponseDTO> rep = txTemplate.execute(status ->
                            versionedService.homologarAfastamento(targetId, payload, activeCommandPrecondition.get())
                    );
                    return ResourceCommandExecutionResult.success(
                            cmdReq,
                            targetId,
                            Objects.requireNonNull(rep).body(),
                            Map.of("persistedVersion", rep.requirePersistedVersion())
                    );
                }),
                availabilityProvider,
                null
        );

        ResourceCommandExecutionRequest homologarReq = ResourceCommandExecutionRequest.item(
                blueprint.resourceKey(),
                "/api/human-resources/afastamentos",
                "homologar-afastamento",
                101L,
                new HomologarAfastamentoCommandDTO("HOMOLOGADO", 7003L),
                ResourceCommandResponsePolicy.READ_AFTER_WRITE
        );

        // Case A: Cessionário-only caller is rejected by GovernedResourceCommandExecutor availability pre-check
        versionedService.callerIsCedente.set(false);
        ResourceCommandExecutionResult deniedByPreCheck = commandExecutor.execute(homologarReq);
        assertFalse(deniedByPreCheck.successful());
        assertEquals(ResourceCommandOutcome.PERMISSION_DENIED, deniedByPreCheck.outcome());
        assertEquals(6, jdbcOutbox.listCommittedEntries().size());

        // Case B: Stale HATEOAS link replay (bypassing discovery pre-check after custody revocation, P10/P17)
        // Must still fail closed inside executeVersionedMutation at STEP_11 and return PERMISSION_DENIED!
        GovernedResourceCommandExecutor staleLinkBypassExecutor = new GovernedResourceCommandExecutor(
                serviceSupport.wrapCommandExecutionProvider(cmdReq -> {
                    HomologarAfastamentoCommandDTO payload = (HomologarAfastamentoCommandDTO) cmdReq.payload();
                    Long targetId = (Long) cmdReq.resourceId();
                    ResourceRepresentationResult<AfastamentoAnnotatedResponseDTO> rep = txTemplate.execute(status ->
                            versionedService.homologarAfastamento(targetId, payload, activeCommandPrecondition.get())
                    );
                    return ResourceCommandExecutionResult.success(cmdReq, targetId, Objects.requireNonNull(rep).body(), Map.of());
                }),
                new NoOpResourceOperationAvailabilityProvider(),
                null
        );
        long versionBeforeCommand = versionedUpdated.requirePersistedVersion();
        activeCommandPrecondition.set(new ResourceVersionUpdatePrecondition<>(
                etagService,
                etagService.create(blueprint.resourceKey(), 101L, versionBeforeCommand),
                blueprint.resourceKey(),
                101L
        ));
        ResourceCommandExecutionResult deniedAtStep11 = staleLinkBypassExecutor.execute(homologarReq);
        assertFalse(deniedAtStep11.successful(),
                "Stale HATEOAS link replayed after Cedente custody revocation must fail closed at STEP_11 (P10/P17)");
        assertEquals(ResourceCommandOutcome.PERMISSION_DENIED, deniedAtStep11.outcome());
        assertEquals(6, jdbcOutbox.listCommittedEntries().size());

        // Case C: Cedente caller with stale If-Match throws ResourceVersionPreconditionException (preserved by GovernedResourceCommandExecutor)
        versionedService.callerIsCedente.set(true);
        activeCommandPrecondition.set(new ResourceVersionUpdatePrecondition<>(
                etagService,
                etagService.create(blueprint.resourceKey(), 101L, versionBeforeCommand + 50L),
                blueprint.resourceKey(),
                101L
        ));
        assertThrows(ResourceVersionPreconditionException.class, () -> commandExecutor.execute(homologarReq));
        assertEquals(6, jdbcOutbox.listCommittedEntries().size());

        // Case D: Cedente caller with valid If-Match succeeds -> increments @Version, commits outbox, and masks ResponseDTO
        activeCommandPrecondition.set(new ResourceVersionUpdatePrecondition<>(
                etagService,
                etagService.create(blueprint.resourceKey(), 101L, versionBeforeCommand),
                blueprint.resourceKey(),
                101L
        ));
        ResourceCommandExecutionResult commandSuccess = commandExecutor.execute(homologarReq);
        assertTrue(commandSuccess.successful());
        assertEquals(ResourceCommandOutcome.SUCCESS, commandSuccess.outcome());
        AfastamentoAnnotatedResponseDTO homologadoDto = (AfastamentoAnnotatedResponseDTO) commandSuccess.body();
        assertNotNull(homologadoDto);
        assertEquals("HOMOLOGADO", homologadoDto.statusAfastamento());
        assertEquals(7003L, homologadoDto.substitutoServidorId());
        assertEquals("***CID-RESTRITO***", homologadoDto.cidCodigo(),
                "Governed command response body must mask cidCodigo at STEP_15");
        assertEquals(versionBeforeCommand + 1L, commandSuccess.evidence().get("persistedVersion"));
        assertEquals(7, jdbcOutbox.listCommittedEntries().size(),
                "Governed command must commit BEFORE_COMMIT_OUTBOX entry atomically at STEP_14");

        // 12. Enterprise Critical Review Regressions (P10.4-R01 .. P10.4-R06)
        // P10.4-R01: UnmappedResourcePolicy.FAIL_CLOSED vs ALLOW_UNMAPPED_FOR_INCREMENTAL_ADOPTION across all 3 interfaces
        ActionDefinition unmappedActionDef = new ActionDefinition(
                "unmapped-action", "ergon.unmapped-resource", "/api/human-resources/unmapped",
                "human-resources", ActionScope.COLLECTION, "Unmapped", "Unmapped action",
                null, null, null, 1, "Done", List.of(), List.of(), List.of(),
                ActionExecutionContract.defaults(ActionScope.COLLECTION)
        );
        ActionAvailabilityContext unmappedActionCtx = new ActionAvailabilityContext(
                "ergon.unmapped-resource", "/api/human-resources/unmapped", null,
                "tenant-gov-br", Locale.ROOT, () -> "usr-gestor-101", Set.of("ROLE_GESTOR"), null
        );
        SurfaceDefinition unmappedSurfaceDef = new SurfaceDefinition(
                "detail", "ergon.unmapped-resource", "/api/human-resources/unmapped",
                "human-resources", SurfaceKind.VIEW, SurfaceScope.COLLECTION, "Unmapped", "Unmapped surface",
                "detail", "visibility", "response", SurfaceResponseCardinality.OBJECT,
                null, null, 1, List.of(), List.of(), List.of(), null
        );
        SurfaceAvailabilityContext unmappedSurfaceCtx = new SurfaceAvailabilityContext(
                "ergon.unmapped-resource", "/api/human-resources/unmapped", null,
                "tenant-gov-br", Locale.ROOT, () -> "usr-gestor-101", Set.of("ROLE_GESTOR"), null
        );
        // Default availabilityProvider uses FAIL_CLOSED (P20)
        assertFalse(availabilityProvider.evaluate(unmappedActionDef, unmappedActionCtx).allowed(),
                "Default UnmappedResourcePolicy.FAIL_CLOSED must deny unmapped ActionDefinition (P10.4-R01)");
        assertEquals("AUTHZ_DECISION_POINT_UNMAPPED",
                availabilityProvider.evaluate(unmappedActionDef, unmappedActionCtx).reason());
        assertFalse(availabilityProvider.evaluate(unmappedSurfaceDef, unmappedSurfaceCtx).allowed(),
                "Default UnmappedResourcePolicy.FAIL_CLOSED must deny unmapped SurfaceDefinition (P10.4-R01)");

        // Opt-in ALLOW_UNMAPPED_FOR_INCREMENTAL_ADOPTION allows unmapped resources while governing mapped ones
        AuthzResourceOperationAvailabilityProvider incrementalProvider =
                new AuthzResourceOperationAvailabilityProvider(seam, snapshotProvider)
                        .withUnmappedResourcePolicy(UnmappedResourcePolicy.ALLOW_UNMAPPED_FOR_INCREMENTAL_ADOPTION);
        assertTrue(incrementalProvider.evaluate(unmappedActionDef, unmappedActionCtx).allowed(),
                "ALLOW_UNMAPPED_FOR_INCREMENTAL_ADOPTION must allow unmapped resources during brownfield rollout (P10.4-R01)");
        assertTrue(incrementalProvider.evaluate(unmappedSurfaceDef, unmappedSurfaceCtx).allowed());

        // P10.4-R02 & P10.4-R06: Verify zero stale thread-local query/mutation contexts after delete/command lifecycles
        assertFalse(serviceSupport.hasActiveQueryContext(),
                "Thread-local query context must be clean after governed lifecycle completion (P10.4-R02/R06)");

        // P10.4-R03: Verify filter(...) and findAllById(...) execute exactly 1 OPA SEARCH evaluation instead of N+1
        versionedService.searchScopeEvaluations.set(0);
        Page<AfastamentoAnnotatedResponseDTO> r03Page = txTemplate.execute(status ->
                versionedService.filter(new AfastamentoFilterDTO(), PageRequest.of(0, 10), List.of())
        );
        assertNotNull(r03Page);
        assertEquals(1, r03Page.getTotalElements());
        assertEquals(1, versionedService.searchScopeEvaluations.get(),
                "filter(...) must execute exactly 1 OPA SEARCH evaluation instead of N+1 (P10.4-R03)");

        versionedService.searchScopeEvaluations.set(0);
        List<AfastamentoAnnotatedResponseDTO> r03Batch = txTemplate.execute(status ->
                versionedService.findAllById(List.of(101L))
        );
        assertNotNull(r03Batch);
        assertEquals(1, r03Batch.size());
        assertEquals("***CID-RESTRITO***", r03Batch.getFirst().cidCodigo());
        assertEquals(1, versionedService.searchScopeEvaluations.get(),
                "findAllById(...) must execute at most 1 OPA SEARCH evaluation for the entire batch (P10.4-R03)");

        // P10.4-R04: Verify evaluateOperationAvailability publishes sanitized DecisionTelemetryEvent
        int telemetryBeforeAvailability = recordedTelemetry.size();
        availabilityProvider.evaluate(
                ResourceOperationAvailabilityContext.collection(
                        blueprint.resourceKey(), "/api/human-resources/afastamentos", "filter"
                )
        );
        availabilityProvider.evaluate(
                ResourceOperationAvailabilityContext.item(
                        blueprint.resourceKey(), "/api/human-resources/afastamentos", "view", 101L
                )
        );
        assertEquals(telemetryBeforeAvailability + 2, recordedTelemetry.size(),
                "evaluateOperationAvailability must publish DecisionTelemetryEvent for both COLLECTION and ITEM probes (P10.4-R04)");

        // P10.4-R05: Verify prepareCreateValidationDraft returns unmasked draft projection
        P102AfastamentoJpaEntity createCandidate = new P102AfastamentoJpaEntity(
                109L, "tenant-gov-br", 10L, 20L, 100L, "DEFERIDO", 7009L, "CID-F32.1"
        );
        AfastamentoAnnotatedCreateDTO createDraftDto = new AfastamentoAnnotatedCreateDTO(
                109L, "tenant-gov-br", 10L, 20L, 100L, "DEFERIDO", 7009L, "CID-F32.1"
        );
        AfastamentoAnnotatedResponseDTO unmaskedCreateDraft =
                versionedService.invokePrepareCreateValidationDraft(createDraftDto, createCandidate);
        assertEquals("CID-F32.1", unmaskedCreateDraft.cidCodigo(),
                "prepareCreateValidationDraft must return raw unmasked CID before post-mutation masking (P10.4-R05)");

        // 13. Fase P10.5: Direct Coupling of Bulk Operations (BulkDomainResourceAdapter + BulkEditableFields)
        //     and OptionSource (OptionSourceRegistry + JpaOptionSourceQueryExecutor + AuthzGovernedOptionSourceProvider)
        txTemplate.executeWithoutResult(status ->
                sharedEm.persist(new P102AfastamentoJpaEntity(
                        107L, "tenant-gov-br", 10L, 20L, 100L, "DEFERIDO", 6001L, "CID-M54.2"
                ))
        );

        ObjectMapper bulkMapper = new ObjectMapper();
        com.fasterxml.jackson.databind.node.ObjectNode resolvedUpdateSchema = bulkMapper.createObjectNode();
        resolvedUpdateSchema.put("type", "object");
        com.fasterxml.jackson.databind.node.ObjectNode propsNode = resolvedUpdateSchema.putObject("properties");
        propsNode.putObject("substitutoServidorId").put("type", "integer").put("nullable", true);
        propsNode.putObject("cidCodigo").put("type", "string").put("nullable", true);

        BulkEditableFields compiledEditableFields = BulkEditableFields.compile(
                bulkMapper,
                bulkMapper.constructType(AfastamentoAnnotatedUpdateDTO.class),
                resolvedUpdateSchema,
                SpecVersion.V30,
                Set.of("id")
        );
        assertTrue(compiledEditableFields.writableFields(BulkMode.UNIFORM_UPDATE).contains("substitutoServidorId"));
        assertTrue(compiledEditableFields.clearableFields(BulkMode.UNIFORM_UPDATE).contains("substitutoServidorId"));

        Validator beanValidator = Validation.buildDefaultValidatorFactory().getValidator();
        AuthzGovernedBulkDomainResourceAdapter<Long, AfastamentoFilterDTO> governedBulkAdapter =
                serviceSupport.wrapBulkDomainResourceAdapter(
                        versionedService.bulkDomainAdapter(
                                bulkMapper,
                                beanValidator,
                                etagService,
                                () -> new ResourceVersionScope("tenant-gov-br:usr-gestor-101")
                        )
                );

        // 13a. Scoped Cohort Selection: selectBulkIdentities intersects hardScope + OPA DataScopePlan (omits #102 and #104)
        List<Long> selectedBulkIds = txTemplate.execute(status ->
                governedBulkAdapter.selectBulkIdentities(
                        new AfastamentoFilterDTO(),
                        List.of(101L, 102L, 104L, 107L),
                        List.of(),
                        100
                )
        );
        assertEquals(List.of(101L, 107L), selectedBulkIds,
                "selectBulkIdentities must include only in-scope records #101 and #107 (P05/P15)");
        assertFalse(serviceSupport.hasActiveQueryContext(),
                "selectBulkIdentities must clean up thread-local query context in finally");

        // 13b. 2-Phase Proposal Evaluation (UNIFORM_UPDATE on substitutoServidorId = 8080L)
        versionedService.callerIsCedente.set(false);
        Instant bulkRefInstant = Instant.parse("2026-11-09T15:00:00Z");
        String activePolicyDigest = blueprint.bundleArtifact().runtimeHead().policySetDigest();
        String activeRuntimeRev = blueprint.bundleArtifact().runtimeHead().runtimeRevision();

        GovernedBulkProposalGrant<Long> substitutoProposalGrant = txTemplate.execute(status ->
                governedBulkAdapter.evaluateAndIssueProposalGrant(
                        "prop-substituto-8080",
                        "usr-gestor-101",
                        "tenant-gov-br",
                        activePolicyDigest,
                        activeRuntimeRev,
                        BatchAuthorizationMode.REJECT_ALL,
                        BulkMode.UNIFORM_UPDATE,
                        selectedBulkIds,
                        List.of(BulkFieldChange.set("substitutoServidorId", LongNode.valueOf(8080L))),
                        compiledEditableFields,
                        bulkRefInstant
                )
        );
        assertNotNull(substitutoProposalGrant);
        assertEquals(2, substitutoProposalGrant.candidatesByTargetId().size());
        // P10.6-R01: Candidate.facts() must mask restricted cidCodigo so proposal previews never leak raw "M54.5",
        // while Candidate.plan() retains raw "M54.5" for server-side confirmation!
        assertEquals("***CID-RESTRITO***",
                substitutoProposalGrant.candidatesByTargetId().get(101L).facts().get("cidCodigo").asText(),
                "Candidate.facts() in bulk proposal grant must mask cidCodigo (P10.6-R01/P50)");
        assertEquals("M54.5",
                substitutoProposalGrant.candidatesByTargetId().get(101L).plan().get("cidCodigo").asText(),
                "Candidate.plan() in bulk proposal grant must retain raw unmasked cidCodigo for server-side confirmation (P10.6-R01/P13/P14)");
        assertEquals(7, jdbcOutbox.listCommittedEntries().size(),
                "Stage.EVALUATION proposal must never write premature BEFORE_COMMIT_OUTBOX entries");
        assertFalse(serviceSupport.hasActiveQueryContext());

        // 13c. Anti-Confused-Deputy (P15/P34): another principal cannot confirm usr-gestor-101's proposal grant
        SecurityException confusedDeputyEx = assertThrows(SecurityException.class, () ->
                txTemplate.execute(status ->
                        governedBulkAdapter.confirmProposalGrant(
                                substitutoProposalGrant,
                                "usr-intruso-202",
                                "tenant-gov-br",
                                activePolicyDigest,
                                BulkMode.UNIFORM_UPDATE,
                                bulkRefInstant
                        )
                )
        );
        assertTrue(confusedDeputyEx.getMessage().contains("AUTHZ_BULK_CONFUSED_DEPUTY_DENIED"));

        // 13d. Policy Digest Continuity (P15/P18): rotated policy digest rejects stale proposal confirmation
        SecurityException rotatedDigestEx = assertThrows(SecurityException.class, () ->
                txTemplate.execute(status ->
                        governedBulkAdapter.confirmProposalGrant(
                                substitutoProposalGrant,
                                "usr-gestor-101",
                                "tenant-gov-br",
                                "sha256:rotated-policy-digest",
                                BulkMode.UNIFORM_UPDATE,
                                bulkRefInstant
                        )
                )
        );
        assertTrue(rotatedDigestEx.getMessage().contains("AUTHZ_BULK_POLICY_REVOKED_OR_ROTATED"));

        // 13e. Dual-Scope Split Custody in Bulk: PER_ITEM vs REJECT_ALL when Cedente custody is revoked before confirmation
        versionedService.callerIsCedente.set(true);
        GovernedBulkProposalGrant<Long> cidPartialGrant = txTemplate.execute(status ->
                governedBulkAdapter.evaluateAndIssueProposalGrant(
                        "prop-cid-partial",
                        "usr-gestor-101",
                        "tenant-gov-br",
                        activePolicyDigest,
                        activeRuntimeRev,
                        BatchAuthorizationMode.PER_ITEM,
                        BulkMode.UNIFORM_UPDATE,
                        selectedBulkIds,
                        List.of(BulkFieldChange.set("cidCodigo", TextNode.valueOf("CID-Z00.0"))),
                        compiledEditableFields,
                        bulkRefInstant
                )
        );
        // Revoke Cedente custody before confirmation
        versionedService.callerIsCedente.set(false);
        List<BulkCohortItemOutcome<Long>> partialOutcomes = txTemplate.execute(status ->
                governedBulkAdapter.confirmProposalGrant(
                        cidPartialGrant,
                        "usr-gestor-101",
                        "tenant-gov-br",
                        activePolicyDigest,
                        BulkMode.UNIFORM_UPDATE,
                        bulkRefInstant
                )
        );
        assertNotNull(partialOutcomes);
        assertEquals(2, partialOutcomes.size());
        assertFalse(partialOutcomes.get(0).committed());
        assertFalse(partialOutcomes.get(1).committed());
        assertEquals(7, jdbcOutbox.listCommittedEntries().size(),
                "Denied items in PER_ITEM must not commit BEFORE_COMMIT_OUTBOX entries");

        // 13f. Authorized Bulk Confirmation: commits both #101 and #107 and writes 2 BEFORE_COMMIT_OUTBOX entries atomically
        List<BulkCohortItemOutcome<Long>> committedOutcomes = txTemplate.execute(status ->
                governedBulkAdapter.confirmProposalGrant(
                        substitutoProposalGrant,
                        "usr-gestor-101",
                        "tenant-gov-br",
                        activePolicyDigest,
                        BulkMode.UNIFORM_UPDATE,
                        bulkRefInstant
                )
        );
        assertNotNull(committedOutcomes);
        assertEquals(2, committedOutcomes.size());
        assertTrue(committedOutcomes.get(0).committed());
        assertTrue(committedOutcomes.get(1).committed());
        assertEquals(9, jdbcOutbox.listCommittedEntries().size(),
                "Bulk confirmation must fulfill BEFORE_COMMIT_OUTBOX for each updated item in the cohort (7 + 2 = 9)");

        P102AfastamentoJpaEntity raw101AfterBulk = txTemplate.execute(status -> sharedEm.find(P102AfastamentoJpaEntity.class, 101L));
        P102AfastamentoJpaEntity raw107AfterBulk = txTemplate.execute(status -> sharedEm.find(P102AfastamentoJpaEntity.class, 107L));
        assertEquals(8080L, Objects.requireNonNull(raw101AfterBulk).substitutoServidorId);
        assertEquals("M54.5", raw101AfterBulk.cidCodigo, "Raw CID on #101 must remain unmasked after bulk update");
        assertEquals(8080L, Objects.requireNonNull(raw107AfterBulk).substitutoServidorId);
        assertEquals("CID-M54.2", raw107AfterBulk.cidCodigo, "Raw CID on #107 must remain unmasked after bulk update");

        // 13g. OptionSource Direct Coupling: filterOptionSourceOptions + includeIds + detached extra masking + byIds historical display-only
        AuthzGovernedOptionSourceProvider governedOptionSource = serviceSupport.wrapOptionSourceQueryExecutor(
                new JpaOptionSourceQueryExecutor(),
                AfastamentoAnnotatedResponseDTO.class,
                blueprint.resourceKey()
        );
        Field optionSourceExecField = AbstractBaseQueryResourceService.class.getDeclaredField("optionSourceQueryExecutor");
        optionSourceExecField.setAccessible(true);
        optionSourceExecField.set(versionedService, governedOptionSource);

        Page<OptionDTO<Object>> optionPage = txTemplate.execute(status ->
                versionedService.filterOptionSourceOptions(
                        "afastamentoLookup",
                        new OptionSourceFilterRequest<AfastamentoFilterDTO>(
                                new AfastamentoFilterDTO(),
                                List.of(),
                                null,
                                null,
                                null,
                                List.of(101L, 102L, 104L) // #102 and #104 are out-of-scope and must NOT be hydrated!
                        ),
                        PageRequest.of(0, 10)
                )
        );
        assertNotNull(optionPage);
        assertEquals(2, optionPage.getContent().size(),
                "filterOptionSourceOptions must return only in-scope #101 and #107 and never hydrate out-of-scope #102 or #104 via includeIds (P06/P07)");
        assertFalse(serviceSupport.hasActiveQueryContext(),
                "AuthzGovernedOptionSourceProvider must clean up thread-local query context in finally");

        OptionDTO<Object> opt101 = optionPage.getContent().stream()
                .filter(o -> Objects.equals(101L, ((Number) o.id()).longValue()))
                .findFirst()
                .orElseThrow();
        assertNotNull(opt101.extra());
        assertEquals(Boolean.TRUE, opt101.extra().get("selectable"));
        @SuppressWarnings("unchecked")
        Map<String, Object> opt101DisplayFields = (Map<String, Object>) opt101.extra().get("displayFields");
        assertNotNull(opt101DisplayFields);
        assertEquals("***CID-RESTRITO***", opt101DisplayFields.get("cidCodigo"),
                "OptionDTO.extra.displayFields must mask restricted cidCodigo via AuthzGovernedOptionSourceProvider (P09/P12/P50)");
        assertEquals("HOMOLOGADO - ***CID-RESTRITO***", opt101.extra().get("description"),
                "OptionDTO.extra.description must also mask restricted cidCodigo segment");

        // P10.6-R03: Pre-SQL FieldUseQueryGuard on OptionSource LookupFilterRequest & sortKey
        assertThrows(FieldUseViolationException.class, () ->
                txTemplate.execute(status ->
                        versionedService.filterOptionSourceOptions(
                                "afastamentoLookup",
                                new OptionSourceFilterRequest<AfastamentoFilterDTO>(
                                        new AfastamentoFilterDTO(),
                                        List.of(new LookupFilterRequest("cidCodigo", "EQ", "M54.5")),
                                        null,
                                        null,
                                        null,
                                        List.of()
                                ),
                                PageRequest.of(0, 10)
                        )
                ),
                "OptionSource LookupFilterRequest on restricted cidCodigo must fail closed with FieldUseViolationException before SQL (P10.6-R03)"
        );
        assertThrows(FieldUseViolationException.class, () ->
                txTemplate.execute(status ->
                        versionedService.filterOptionSourceOptions(
                                "afastamentoLookup",
                                new OptionSourceFilterRequest<AfastamentoFilterDTO>(
                                        new AfastamentoFilterDTO(),
                                        List.of(),
                                        null,
                                        null,
                                        "cidCodigo:asc",
                                        List.of()
                                ),
                                PageRequest.of(0, 10)
                        )
                ),
                "OptionSource sortKey on restricted cidCodigo must fail closed with FieldUseViolationException before SQL (P10.6-R03)"
        );
        assertFalse(serviceSupport.hasActiveQueryContext());

        // Transition #107 to REVOGADO (blocked status in LookupSelectionPolicy with allowRetainInvalidExistingValue = true)
        txTemplate.executeWithoutResult(status -> {
            P102AfastamentoJpaEntity e107 = sharedEm.find(P102AfastamentoJpaEntity.class, 107L);
            e107.statusAfastamento = "REVOGADO";
            sharedEm.flush();
        });

        List<OptionDTO<Object>> byIdsOptions = txTemplate.execute(status ->
                versionedService.byIdsOptionSourceOptions(
                        "afastamentoLookup",
                        List.of(101L, 107L, 102L) // #102 out-of-scope omitted; #107 historical REVOGADO retained read-only
                )
        );
        assertEquals(2, byIdsOptions.size(),
                "byIdsOptionSourceOptions must omit out-of-scope #102 while retaining in-scope #101 and historical #107 (P06/P07)");
        OptionDTO<Object> optById101 = byIdsOptions.get(0);
        OptionDTO<Object> optById107 = byIdsOptions.get(1);
        assertEquals(Boolean.TRUE, Objects.requireNonNull(optById101.extra()).get("selectable"));
        assertEquals(Boolean.FALSE, Objects.requireNonNull(optById107.extra()).get("selectable"),
                "REVOGADO option #107 must be marked non-selectable for new writes");
        assertEquals(Boolean.TRUE, optById107.extra().get("disabled"));
        assertEquals(Boolean.TRUE, optById107.extra().get("historicalDisplayOnly"),
                "In-scope historical option #107 reloaded via byIds with allowRetainInvalidExistingValue=true must be stamped historicalDisplayOnly=true");
        assertEquals("Afastamento #107 em situação REVOGADO", optById107.extra().get("disabledReason"));
        assertFalse(serviceSupport.hasActiveQueryContext());

        // Clean up #107 so subsequent assertions see clean state
        txTemplate.executeWithoutResult(status -> {
            P102AfastamentoJpaEntity e107 = sharedEm.find(P102AfastamentoJpaEntity.class, 107L);
            if (e107 != null) {
                sharedEm.remove(e107);
            }
        });

        // 15. Fase P10.6 — Governed Analytics Seam (StatsQueryExecutor + StatsFieldRegistry) & Reactive Determination / AI Context Projection
        AuthzGovernedStatsQueryExecutor governedStatsExecutor = serviceSupport.wrapStatsQueryExecutor(
                new JpaStatsQueryExecutor(),
                AfastamentoAnnotatedResponseDTO.class,
                blueprint.resourceKey()
        );
        Field statsExecField = AbstractBaseQueryResourceService.class.getDeclaredField("statsQueryExecutor");
        statsExecField.setAccessible(true);
        statsExecField.set(versionedService, governedStatsExecutor);

        Field statsEligField = AbstractBaseQueryResourceService.class.getDeclaredField("statsEligibility");
        statsEligField.setAccessible(true);
        statsEligField.set(versionedService, new StatsEligibility());

        Field statsPropsField = AbstractBaseQueryResourceService.class.getDeclaredField("statsProperties");
        statsPropsField.setAccessible(true);
        statsPropsField.set(versionedService, new StatsProperties(true, 20, 100, StatsSupportMode.AUTO));

        // 15a. Discovery-time StatsFieldRegistry filtering strips LGPD_SENSITIVE_DATA 'cidCodigo' while keeping permitted dimensions/metrics
        StatsFieldRegistry filteredStatsRegistry = governedStatsExecutor.filterStatsFieldRegistry(
                versionedService.getStatsFieldRegistry()
        );
        assertTrue(filteredStatsRegistry.resolve("statusAfastamento").isPresent());
        assertTrue(filteredStatsRegistry.resolve("substitutoServidorId").isPresent());
        assertFalse(filteredStatsRegistry.resolve("cidCodigo").isPresent(),
                "filterStatsFieldRegistry must strip cidCodigo whose GROUP/AGGREGATE is denied by LGPD_SENSITIVE_DATA (P10/P46)");

        // 15b. Scoped GroupByStats & DistributionStats on permitted fields (#101 only; out-of-scope #102 and #104 excluded)
        GroupByStatsResponse statusGroupStats = txTemplate.execute(status ->
                versionedService.groupByStats(
                        new GroupByStatsRequest<>(
                                new AfastamentoFilterDTO(),
                                "statusAfastamento",
                                new StatsMetricRequest(StatsMetric.COUNT, null),
                                10,
                                StatsBucketOrder.KEY_ASC
                        )
                )
        );
        assertNotNull(statusGroupStats);
        assertEquals(1, statusGroupStats.buckets().size(),
                "groupByStats must aggregate only in-scope record #101 (HOMOLOGADO) and exclude out-of-scope #102 and #104 (P05/P14)");
        assertEquals("HOMOLOGADO", statusGroupStats.buckets().getFirst().key());
        assertEquals(1L, statusGroupStats.buckets().getFirst().count());
        assertFalse(serviceSupport.hasActiveQueryContext(),
                "AuthzGovernedStatsQueryExecutor must clean up activeQueryContext on transaction completion");

        DistributionStatsResponse statusDistStats = txTemplate.execute(status ->
                versionedService.distributionStats(
                        new DistributionStatsRequest<>(
                                new AfastamentoFilterDTO(),
                                "statusAfastamentoTerm",
                                DistributionMode.TERMS,
                                new StatsMetricRequest(StatsMetric.COUNT, null),
                                null,
                                null,
                                10,
                                StatsBucketOrder.KEY_ASC
                        )
                )
        );
        assertNotNull(statusDistStats);
        assertEquals(1, statusDistStats.buckets().size());
        assertEquals("HOMOLOGADO", statusDistStats.buckets().getFirst().key());
        assertFalse(serviceSupport.hasActiveQueryContext());

        // 15c. Runtime Pre-SQL FIELD_USE blocking: attempting groupByStats on restricted 'cidCodigo' fails closed with FieldUseViolationException
        FieldUseViolationException statsFieldUseEx = assertThrows(FieldUseViolationException.class, () ->
                txTemplate.execute(status ->
                        versionedService.groupByStats(
                                new GroupByStatsRequest<>(
                                        new AfastamentoFilterDTO(),
                                        "cidCodigo",
                                        new StatsMetricRequest(StatsMetric.COUNT, null),
                                        10,
                                        StatsBucketOrder.KEY_ASC
                                )
                        )
                )
        );
        assertTrue(statsFieldUseEx.getMessage().contains("GROUP"));
        assertTrue(statsFieldUseEx.getMessage().contains("ergon.afastamentos.cid_codigo"));
        assertFalse(serviceSupport.hasActiveQueryContext());

        // 15d. Governed Reactive Determination Provider & Runtime Execution (P05, P12, P13, P14, P50)
        ReactiveDeterminationDefinition substitutoDeterminationDef = ReactiveDeterminationDefinition
                .forCrudResource(
                        "det-substituto-preview",
                        "createAfastamento",
                        "updateAfastamento",
                        "previewSubstitutoAfastamento"
                )
                .source("/substitutoServidorId")
                .input("/substitutoServidorId", "/substitutoServidorId")
                .output("/statusAfastamento", "/statusAfastamento")
                .output("/cidCodigo", "/cidCodigo")
                .provenance(new ReactiveDeterminationProvenance(
                        ReactiveDeterminationProvenanceKind.HOST,
                        "previewSubstitutoAfastamento",
                        "v1"
                ))
                .build();

        AuthzGovernedReactiveDeterminationProvider governedDeterminationProvider =
                serviceSupport.wrapReactiveDeterminationProvider(
                        () -> List.of(substitutoDeterminationDef),
                        AfastamentoAnnotatedResponseDTO.class,
                        blueprint.resourceKey()
                );
        assertEquals(1, governedDeterminationProvider.definitions().size());

        int outboxBeforeDetermination = jdbcOutbox.listCommittedEntries().size();
        // P10.6-R05: 5-arg evaluateGovernedDetermination automatically applies live OPA MaskDirectives from TARGET evaluation!
        Map<String, Object> determinationOutput101 = txTemplate.execute(status -> {
            P102AfastamentoJpaEntity raw101 = sharedEm.find(P102AfastamentoJpaEntity.class, 101L);
            sharedEm.detach(raw101);
            return governedDeterminationProvider.evaluateGovernedDetermination(
                    blueprint.decisionPoint(),
                    blueprint.factContract().factContractDigest(),
                    Map.of(
                            "subject.principalId", "usr-gestor-101",
                            "subject.organizationUnitIds", List.of(100L),
                            "resource.lotacaoSetorId", raw101.lotacaoSetorId
                    ),
                    Map.of(
                            "subject.principalId", FactResolutionStatus.PRESENT,
                            "subject.organizationUnitIds", FactResolutionStatus.PRESENT,
                            "resource.lotacaoSetorId", FactResolutionStatus.PRESENT
                    ),
                    () -> versionedService.invokePrepareUpdateValidationDraft(
                            101L,
                            raw101,
                            new AfastamentoAnnotatedUpdateDTO(9090L, null)
                    )
            );
        });
        assertNotNull(determinationOutput101);
        assertEquals(9090L, determinationOutput101.get("substitutoServidorId"));
        assertEquals("***CID-RESTRITO***", determinationOutput101.get("cidCodigo"),
                "Reactive determination response must automatically mask restricted cidCodigo from live OPA TARGET evaluation (P10.6-R05/P50)");
        assertEquals(outboxBeforeDetermination, jdbcOutbox.listCommittedEntries().size(),
                "Non-persistent reactive determination must never write BEFORE_COMMIT_OUTBOX entries");
        assertFalse(serviceSupport.hasActiveQueryContext());

        // Out-of-scope cross-entity probe (#102 in lotacao 999) in reactive determination must fail closed
        assertThrows(SecurityException.class, () ->
                txTemplate.execute(status -> {
                    P102AfastamentoJpaEntity raw102 = sharedEm.find(P102AfastamentoJpaEntity.class, 102L);
                    return governedDeterminationProvider.evaluateGovernedDetermination(
                            blueprint.decisionPoint(),
                            blueprint.factContract().factContractDigest(),
                            Map.of(
                                    "subject.principalId", "usr-gestor-101",
                                    "subject.organizationUnitIds", List.of(100L),
                                    "resource.lotacaoSetorId", raw102.lotacaoSetorId
                            ),
                            Map.of(
                                    "subject.principalId", FactResolutionStatus.PRESENT,
                                    "subject.organizationUnitIds", FactResolutionStatus.PRESENT,
                                    "resource.lotacaoSetorId", FactResolutionStatus.PRESENT
                            ),
                            () -> versionedService.invokePrepareUpdateValidationDraft(
                                    102L,
                                    raw102,
                                    new AfastamentoAnnotatedUpdateDTO(9090L, null)
                            )
                    );
                })
        );

        // 15e. AI Context & Tool Grounding Projection suppresses LGPD_SENSITIVE_DATA ('cidCodigo' -> aiAllowed = false)
        // P10.6-R05: 5-arg projectGovernedAiContext automatically populates runtimeRevision and policySetDigest from live OPA TARGET evaluation
        SanitizedAiToolProjection aiProjection101 = txTemplate.execute(status -> {
            P102AfastamentoJpaEntity raw101 = sharedEm.find(P102AfastamentoJpaEntity.class, 101L);
            AfastamentoAnnotatedResponseDTO rawDto101 = new AfastamentoAnnotatedResponseDTO(
                    raw101.id,
                    raw101.tenantId,
                    raw101.cedenteOrgaoId,
                    raw101.cessionarioOrgaoId,
                    raw101.lotacaoSetorId,
                    raw101.statusAfastamento,
                    raw101.substitutoServidorId,
                    raw101.cidCodigo
            );
            return governedDeterminationProvider.projectGovernedAiContext(
                    blueprint.decisionPoint(),
                    blueprint.factContract().factContractDigest(),
                    rawDto101,
                    Map.of(
                            "subject.principalId", "usr-gestor-101",
                            "subject.organizationUnitIds", List.of(100L),
                            "resource.lotacaoSetorId", raw101.lotacaoSetorId
                    ),
                    Map.of(
                            "subject.principalId", FactResolutionStatus.PRESENT,
                            "subject.organizationUnitIds", FactResolutionStatus.PRESENT,
                            "resource.lotacaoSetorId", FactResolutionStatus.PRESENT
                    )
            );
        });
        assertNotNull(aiProjection101);
        assertEquals(blueprint.bundleArtifact().runtimeHead().runtimeRevision(), aiProjection101.runtimeRevision());
        assertEquals(blueprint.bundleArtifact().runtimeHead().policySetDigest(), aiProjection101.policySetDigest());
        assertFalse(aiProjection101.detachedPayload().containsKey("cidCodigo"),
                "AI context projection must completely suppress cidCodigo (LGPD_SENSITIVE_DATA aiAllowed=false) (P47/P57/P62)");
        assertTrue(aiProjection101.suppressedAiAttributeIds().contains("ergon.afastamentos.cid_codigo"));
        assertEquals(8080L, aiProjection101.detachedPayload().get("substitutoServidorId"));

        List<AiGovernanceMetadataView> aiMetadataViews = governedDeterminationProvider.projectAiGovernanceMetadata();
        assertEquals(8, aiMetadataViews.size());
        AiGovernanceMetadataView cidAiMeta = aiMetadataViews.stream()
                .filter(v -> "ergon.afastamentos.cid_codigo".equals(v.attributeId()))
                .findFirst()
                .orElseThrow();
        assertEquals("NONE", cidAiMeta.aiUsageMode());
        assertFalse(cidAiMeta.exportable());

        // 16. Verify PraxisAuthzHostBridgeAutoConfiguration registers MetadataDtoGovernanceIntrospector and AuthzResourceOperationAvailabilityProvider beans
        new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(
                        PraxisAuthzAutoConfiguration.class,
                        PraxisAuthzHostBridgeAutoConfiguration.class
                ))
                .withBean(OpaClientTransport.class, blueprint::localOpaTransport)
                .withBean(HostRuntimePolicyCoordinates.class, blueprint::coordinates)
                .withBean(MethodBindingAdmissionRecord.class, () -> blueprint.admissionRecords().getFirst())
                .run(context -> {
                    assertNotNull(context.getBean(MetadataDtoGovernanceIntrospector.class));
                    assertNotNull(context.getBean(AuthzGovernedResourceServiceSupport.class));
                    assertNotNull(context.getBean(AuthzResourceOperationAvailabilityProvider.class));
                });

        // 17. Fase P10.7: Zero-Boilerplate Base Hierarchy (AbstractAuthzGovernedReadOnlyResourceService & AbstractAuthzGovernedResourceService)
        ConciseAfastamentoRadarReadOnlyService radarReadOnlyService = new ConciseAfastamentoRadarReadOnlyService(
                repository,
                serviceSupport,
                blueprint,
                jpaAdapter,
                criteriaTranslator,
                sharedEm
        );
        radarReadOnlyService.configureGovernedQueryInfrastructure(
                new DefaultCollectionExportExecutor(List.of(new CsvCollectionExportEngine())),
                new JpaOptionSourceQueryExecutor(),
                new JpaStatsQueryExecutor(),
                new StatsProperties(true, 20, 100, StatsSupportMode.AUTO)
        );

        Page<AfastamentoAnnotatedResponseDTO> radarPage = txTemplate.execute(status ->
                radarReadOnlyService.filter(new AfastamentoFilterDTO(), PageRequest.of(0, 10), List.of())
        );
        assertNotNull(radarPage);
        assertEquals(1, radarPage.getTotalElements(),
                "AbstractAuthzGovernedReadOnlyResourceService.filter must enforce hardScope + OPA DataScopePlan out of the box (P10.7)");
        assertEquals("***CID-RESTRITO***", radarPage.getContent().getFirst().cidCodigo(),
                "AbstractAuthzGovernedReadOnlyResourceService must automatically wrap getRawResourceMapper() and mask cidCodigo (P10.7)");
        assertFalse(radarReadOnlyService.getStatsFieldRegistry().resolve("cidCodigo").isPresent(),
                "AbstractAuthzGovernedReadOnlyResourceService.getStatsFieldRegistry() must automatically strip LGPD_SENSITIVE_DATA cidCodigo (P10.7)");
        assertTrue(radarReadOnlyService.getStatsFieldRegistry().resolve("statusAfastamento").isPresent());

        ConciseAfastamentoGovernedService conciseMutableService = new ConciseAfastamentoGovernedService(
                repository,
                serviceSupport,
                blueprint,
                jpaAdapter,
                criteriaTranslator,
                sharedEm
        );
        conciseMutableService.configureGovernedQueryInfrastructure(
                new DefaultCollectionExportExecutor(List.of(new CsvCollectionExportEngine())),
                new JpaOptionSourceQueryExecutor(),
                new JpaStatsQueryExecutor(),
                new StatsProperties(true, 20, 100, StatsSupportMode.AUTO)
        );

        // Verify R-11 ordering (STEP_11 before hydrateBeforeCreate before STEP_12 validateCreate) + atomic outbox + response masking
        int outboxBeforeConcise = jdbcOutbox.listCommittedEntries().size();
        conciseMutableService.callerIsCedente.set(true);
        var conciseCreated = txTemplate.execute(status ->
                conciseMutableService.create(new AfastamentoAnnotatedCreateDTO(
                        108L, "tenant-gov-br", 10L, 20L, 100L, "DEFERIDO", 5001L, "CID-J01.0"
                ))
        );
        assertNotNull(conciseCreated);
        assertEquals(108L, conciseCreated.id());
        assertEquals("***CID-RESTRITO***", conciseCreated.body().cidCodigo(),
                "AbstractAuthzGovernedResourceService.create must mask cidCodigo in SavedResult (P10.7)");
        assertEquals(List.of("STEP_11_DONE", "HYDRATE_CREATE", "STEP_12_VALIDATE_CREATE"),
                conciseMutableService.executionTrace,
                "AbstractAuthzGovernedResourceService must enforce R-11 ordering: STEP_11 -> hydrateBeforeCreate -> validateCreate (P10.7)");
        assertEquals(outboxBeforeConcise + 1, jdbcOutbox.listCommittedEntries().size(),
                "AbstractAuthzGovernedResourceService.create must fulfill BEFORE_COMMIT_OUTBOX atomically (P10.7)");

        // Verify Cessionário-only caller cannot modify Cedente-exclusive cidCodigo on #108 via AbstractAuthzGovernedResourceService
        conciseMutableService.callerIsCedente.set(false);
        assertThrows(FieldWriteViolationException.class, () ->
                txTemplate.execute(status ->
                        conciseMutableService.update(108L, new AfastamentoAnnotatedUpdateDTO(5002L, "CID-PROIBIDO"))
                )
        );

        // Verify Cessionário-only caller CAN modify substitutoServidorId on #108 and R-11 ordering holds on update
        conciseMutableService.executionTrace.clear();
        AfastamentoAnnotatedResponseDTO conciseUpdated = txTemplate.execute(status ->
                conciseMutableService.update(108L, new AfastamentoAnnotatedUpdateDTO(5005L, null))
        );
        assertNotNull(conciseUpdated);
        assertEquals(5005L, conciseUpdated.substitutoServidorId());
        assertEquals("***CID-RESTRITO***", conciseUpdated.cidCodigo());
        assertEquals(List.of("STEP_11_DONE", "HYDRATE_UPDATE", "STEP_12_VALIDATE_UPDATE"),
                conciseMutableService.executionTrace,
                "AbstractAuthzGovernedResourceService must enforce R-11 ordering: STEP_11 -> hydrateBeforeUpdate -> validateUpdate (P10.7)");
        assertEquals(outboxBeforeConcise + 2, jdbcOutbox.listCommittedEntries().size());

        // Verify deleteById on #108 via AbstractAuthzGovernedResourceService fulfills BEFORE_COMMIT_OUTBOX
        conciseMutableService.callerIsCedente.set(true);
        txTemplate.executeWithoutResult(status -> conciseMutableService.deleteById(108L));
        assertEquals(outboxBeforeConcise + 3, jdbcOutbox.listCommittedEntries().size(),
                "AbstractAuthzGovernedResourceService.deleteById must fulfill BEFORE_COMMIT_OUTBOX in afterDelete (P10.7)");
        assertFalse(serviceSupport.hasActiveQueryContext());

        // 18. Fase P10.8: Declarative AuthzResourceGovernanceSpec + ThreadLocalAuthzCallerContextProvider + Cedente-Only Create
        AuthzResourceGovernanceSpec<P102AfastamentoJpaEntity> governanceSpec =
                AuthzResourceGovernanceSpec.<P102AfastamentoJpaEntity>builder(blueprint.resourceKey())
                        .decisionPoint(blueprint.decisionPoint())
                        .factContractDigest(blueprint.factContract().factContractDigest())
                        .queryAdapter(
                                blueprint.queryProjection(),
                                List.of(new QueryAdapterFieldBinding(
                                        blueprint.resourceKey(),
                                        "resource.lotacaoSetorId",
                                        "ergon.afastamentos.lotacao_setor_id",
                                        "lotacaoSetorId",
                                        RelationTraversalStrategy.INNER_JOIN_SCALAR,
                                        true
                                ))
                        )
                        .dualScopeDelegationSpec(blueprint.dualScopeSpec())
                        .stateField("statusAfastamento")
                        .cedenteCustody("cedenteOrgaoId", "subject.cedenteOrgaoIds")
                        .cessionarioCustody("cessionarioOrgaoId", "subject.cessionarioOrgaoIds")
                        .operationModifiedAttributes(Map.of(
                                "homologar-afastamento", Set.of("ergon.afastamentos.status_afastamento"),
                                "designar-substituto", Set.of("ergon.afastamentos.substituto_servidor_id"),
                                "alterar-cid-medico", Set.of("ergon.afastamentos.cid_codigo")
                        ))
                        .mandatoryScopeAnchorAttributeIds(Set.of(
                                "ergon.afastamentos.id",
                                "ergon.afastamentos.tenant_id",
                                "ergon.afastamentos.cedente_orgao_id",
                                "ergon.afastamentos.cessionario_orgao_id",
                                "ergon.afastamentos.lotacao_setor_id"
                        ))
                        .tenantField("tenantId")
                        .build();

        ThreadLocalAuthzCallerContextProvider callerContextProvider = new ThreadLocalAuthzCallerContextProvider();
        SpecDrivenAfastamentoGovernedService specService = new SpecDrivenAfastamentoGovernedService(
                repository,
                serviceSupport,
                governanceSpec,
                callerContextProvider,
                sharedEm
        );
        specService.configureGovernedQueryInfrastructure(
                new DefaultCollectionExportExecutor(List.of(new CsvCollectionExportEngine())),
                new JpaOptionSourceQueryExecutor(),
                new JpaStatsQueryExecutor(),
                new StatsProperties(true, 20, 100, StatsSupportMode.AUTO)
        );

        // 18a. Calling filter without a bound AuthzCallerContext must fail closed (AUTHZ_CALLER_CONTEXT_MISSING)
        SecurityException missingCallerEx = assertThrows(SecurityException.class, () ->
                txTemplate.execute(status -> specService.filter(new AfastamentoFilterDTO(), PageRequest.of(0, 10), List.of()))
        );
        assertTrue(missingCallerEx.getMessage().contains("AUTHZ_CALLER_CONTEXT_MISSING"));

        AuthzCallerContext callerCtx = AuthzCallerContext.of(
                "tenant-gov-br",
                Map.of(
                        "subject.principalId", "usr-gestor-101",
                        "subject.organizationUnitIds", List.of(100L)
                )
        );

        // 18b. Scoped execution with AuthzCallerContext resolves hardScope + OPA DataScopePlan automatically
        Page<AfastamentoAnnotatedResponseDTO> specFiltered = callerContextProvider.callWithContext(callerCtx, () ->
                txTemplate.execute(status -> specService.filter(new AfastamentoFilterDTO(), PageRequest.of(0, 10), List.of()))
        );
        assertNotNull(specFiltered);
        assertEquals(1, specFiltered.getTotalElements());
        assertEquals("***CID-RESTRITO***", specFiltered.getContent().getFirst().cidCodigo());

        // 18b-R03/R04: Automatic in-memory DataScopePlan evaluation on findById / assertItemAccessible (zero custom Java predicate)
        // plus deterministic ThreadLocal cleanup after assertItemAccessible and failed findById outside @Transactional
        callerContextProvider.runWithContext(callerCtx, () -> {
            specService.assertItemAccessible(101L);
            assertFalse(serviceSupport.hasActiveQueryContext(),
                    "P10.8-R04: assertItemAccessible(101L) must clean up activeQueryContext in finally");

            SecurityException outOfScopeItemEx = assertThrows(SecurityException.class, () ->
                    specService.assertItemAccessible(102L)
            );
            assertTrue(outOfScopeItemEx.getMessage().contains("AUTHZ_ENTITY_DATA_SCOPE_DENIED"),
                    "P10.8-R03: assertItemAccessible(102L) must fail closed via automatic in-memory DataScopePlan evaluation");
            assertFalse(serviceSupport.hasActiveQueryContext(),
                    "P10.8-R04: Failed assertEntityAccessAllowed(102L) must clean up activeQueryContext in catch/finally");

            SecurityException crossTenantItemEx = assertThrows(SecurityException.class, () ->
                    specService.findById(103L)
            );
            assertTrue(crossTenantItemEx.getMessage().contains("AUTHZ_HARD_SCOPE_TENANT_MISMATCH"),
                    "P10.8-R03: findById(103L) in tenant-outro must fail closed via declarative tenantField('tenantId') guard");
            assertFalse(serviceSupport.hasActiveQueryContext());

            txTemplate.executeWithoutResult(status ->
                    repository.save(new P102AfastamentoJpaEntity(
                            113L, "tenant-gov-br", 1L, 2L, null, "DEFERIDO", 5003L, "A09"))
            );
            try {
                SecurityException nullScopeItemEx = assertThrows(SecurityException.class, () ->
                        specService.findById(113L)
                );
                assertTrue(nullScopeItemEx.getMessage().contains("AUTHZ_ENTITY_DATA_SCOPE_DENIED"),
                        "P10.8-R03: findById(113L) with null lotacaoSetorId must fail closed via Kleene 3-valued in-memory DataScopePlan evaluation");
                assertFalse(serviceSupport.hasActiveQueryContext());
            } finally {
                txTemplate.executeWithoutResult(status -> repository.deleteById(113L));
            }
        });

        // 18b-R01/R02/R05: Verify introspectWriteDto lineage inheritance (R01), update anchor null clear guard (R02), and final hooks (R05)
        record UnannotatedWriteDto(Long orgCedenteId, String cidCodigo, String customWriteOnlyNotes) {}
        IntrospectedDtoGovernanceContract inheritedWriteContract = introspector.introspectWriteDto(
                UnannotatedWriteDto.class, AfastamentoAnnotatedResponseDTO.class, blueprint.resourceKey());
        assertEquals("ergon.afastamentos.cedente_orgao_id",
                inheritedWriteContract.wirePointerToAttributeIdMap().get("/orgCedenteId"),
                "P10.8-R01: introspectWriteDto must inherit ResponseDTO @DomainLineage attributeId when WriteDTO omits @DomainLineage");
        assertEquals("human_resources.afastamentos.custom_write_only_notes",
                inheritedWriteContract.wirePointerToAttributeIdMap().get("/customWriteOnlyNotes"),
                "P10.8-R01: introspectWriteDto must synthesize canonical attributeId for write-only fields");
        assertTrue(java.lang.reflect.Modifier.isFinal(
                AbstractAuthzGovernedResourceService.class.getDeclaredMethod("getStatsFieldRegistry").getModifiers()),
                "P10.8-R05: getStatsFieldRegistry must be final on AbstractAuthzGovernedResourceService");
        assertTrue(java.lang.reflect.Modifier.isFinal(
                AbstractAuthzGovernedResourceService.class.getDeclaredMethod("assertItemAccessible", Object.class).getModifiers()),
                "P10.8-R05: assertItemAccessible must be final on AbstractAuthzGovernedResourceService");

        // 18c. Cedente-only caller (isCallerCedente = true, isCallerCessionario = false) CAN create a record
        // when Cessionário-exclusive substitutoServidorId is null (omitted on CREATE), and cannot set substitutoServidorId != null
        specService.callerIsCedente.set(true);
        specService.callerIsCessionario.set(false);
        assertThrows(FieldWriteViolationException.class, () ->
                callerContextProvider.callWithContext(callerCtx, () ->
                        txTemplate.execute(status ->
                                specService.create(new AfastamentoAnnotatedCreateDTO(
                                        109L, "tenant-gov-br", 10L, 20L, 100L, "DEFERIDO", 5001L, "CID-M54.5"
                                ))
                        )
                ),
                "Cedente-only caller must be blocked from populating Cessionário-exclusive substitutoServidorId on CREATE (P10.8)"
        );

        // Missing mandatory scope anchor (lotacaoSetorId = null) on CREATE must fail closed with AUTHZ_SCOPE_ANCHOR_CLEAR_FORBIDDEN
        SecurityException missingAnchorCreateEx = assertThrows(SecurityException.class, () ->
                callerContextProvider.callWithContext(callerCtx, () ->
                        txTemplate.execute(status ->
                                specService.create(new AfastamentoAnnotatedCreateDTO(
                                        109L, "tenant-gov-br", 10L, 20L, null, "DEFERIDO", null, "CID-M54.5"
                                ))
                        )
                )
        );
        assertTrue(missingAnchorCreateEx.getMessage().contains("AUTHZ_SCOPE_ANCHOR_CLEAR_FORBIDDEN"));

        int outboxBeforeSpec = jdbcOutbox.listCommittedEntries().size();
        var specCreated = callerContextProvider.callWithContext(callerCtx, () ->
                txTemplate.execute(status ->
                        specService.create(new AfastamentoAnnotatedCreateDTO(
                                109L, "tenant-gov-br", 10L, 20L, 100L, "DEFERIDO", null, "CID-M54.5"
                        ))
                )
        );
        assertNotNull(specCreated);
        assertEquals(109L, specCreated.id());
        assertEquals(null, specCreated.body().substitutoServidorId());
        assertEquals("***CID-RESTRITO***", specCreated.body().cidCodigo());
        assertEquals(outboxBeforeSpec + 1, jdbcOutbox.listCommittedEntries().size());

        // Clean up #109
        callerContextProvider.runWithContext(callerCtx, () ->
                txTemplate.executeWithoutResult(status -> specService.deleteById(109L))
        );
        assertEquals(outboxBeforeSpec + 2, jdbcOutbox.listCommittedEntries().size());

        // 18d. Verify PraxisAuthzHostBridgeAutoConfiguration registers ThreadLocalAuthzCallerContextProvider,
        // ResourceStateSnapshotProvider, AuthzCallerContextFilter, and runs authzGovernedResourceServiceInfrastructureInitializer
        // (including automatic ResourceAvailabilityPolicyBinding registration — Fase P10.9)
        new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(PraxisAuthzHostBridgeAutoConfiguration.class))
                .withBean(jakarta.persistence.EntityManagerFactory.class, () -> Objects.requireNonNull(emfBean.getObject()))
                .withBean(DetachedDtoMaskingProcessor.class, DetachedDtoMaskingProcessor::new)
                .withBean(MetadataResourceAuthorizationSeam.class, () -> seam)
                .withBean(CollectionExportExecutor.class, () -> new DefaultCollectionExportExecutor(List.of(new CsvCollectionExportEngine())))
                .withBean(org.praxisplatform.uischema.options.service.OptionSourceQueryExecutor.class, JpaOptionSourceQueryExecutor::new)
                .withBean(org.praxisplatform.uischema.stats.service.StatsQueryExecutor.class, JpaStatsQueryExecutor::new)
                .withBean(StatsProperties.class, () -> new StatsProperties(true, 20, 100, StatsSupportMode.AUTO))
                .withBean(org.praxisplatform.authz.host.metadata.AuthzCallerContextHttpResolver.class, () -> req -> {
                    String authHeader = req.getHeader("Authorization");
                    if (authHeader == null || !authHeader.startsWith("Bearer token-")) {
                        return Optional.empty();
                    }
                    String resolvedTenant = authHeader.substring("Bearer token-".length()).trim();
                    return Optional.of(AuthzCallerContext.of(
                            resolvedTenant,
                            Map.of(
                                    "subject.principalId", "usr-gestor-101",
                                    "subject.organizationUnitIds", List.of(100L),
                                    "subject.cedenteOrgaoIds", List.of(1L),
                                    "subject.cessionarioOrgaoIds", List.of()
                            )
                    ));
                })
                .withBean("authzCallerContextProvider", ThreadLocalAuthzCallerContextProvider.class, () -> callerContextProvider)
                .withBean(SpecDrivenAfastamentoGovernedService.class, () -> {
                    SpecDrivenAfastamentoGovernedService s = new SpecDrivenAfastamentoGovernedService(
                            repository,
                            serviceSupport,
                            governanceSpec,
                            callerContextProvider,
                            sharedEm
                    );
                    s.useDeclarativeCustody.set(true);
                    return s;
                })
                .run(ctx -> {
                    assertTrue(ctx.containsBean("authzCallerContextProvider"),
                            "PraxisAuthzHostBridgeAutoConfiguration must auto-register ThreadLocalAuthzCallerContextProvider (P10.8)");
                    assertTrue(ctx.containsBean("resourceStateSnapshotProvider"),
                            "PraxisAuthzHostBridgeAutoConfiguration must auto-register ResourceStateSnapshotProvider (P10.9)");
                    assertTrue(ctx.containsBean("authzCallerContextFilter"),
                            "PraxisAuthzHostBridgeAutoConfiguration must auto-register AuthzCallerContextFilter when AuthzCallerContextHttpResolver is present (P10.9)");
                    assertTrue(ctx.containsBean("authzGovernedResourceServiceInfrastructureInitializer"),
                            "PraxisAuthzHostBridgeAutoConfiguration must auto-register SmartInitializingSingleton infrastructure initializer (P10.7..P10.9)");

                    ThreadLocalAuthzCallerContextProvider autoCallerProvider =
                            ctx.getBean(ThreadLocalAuthzCallerContextProvider.class);
                    SpecDrivenAfastamentoGovernedService autoWiredService = ctx.getBean(SpecDrivenAfastamentoGovernedService.class);
                    AuthzResourceOperationAvailabilityProvider autoAvailability =
                            ctx.getBean(AuthzResourceOperationAvailabilityProvider.class);
                    assertTrue(autoAvailability.hasResourceBinding(blueprint.resourceKey()),
                            "P10.9: SmartInitializingSingleton must automatically register ResourceAvailabilityPolicyBinding for spec-driven governed services");

                    // 19a. Zero-Boilerplate Availability Discovery & Snapshot Resolution via auto-registered binding
                    AuthzCallerContext pureCedenteCaller = AuthzCallerContext.of(
                            "tenant-gov-br",
                            Map.of(
                                    "subject.principalId", "usr-gestor-101",
                                    "subject.organizationUnitIds", List.of(100L),
                                    "subject.cedenteOrgaoIds", List.of(1L),
                                    "subject.cessionarioOrgaoIds", List.of()
                            )
                    );
                    AuthzCallerContext pureCessionarioCaller = AuthzCallerContext.of(
                            "tenant-gov-br",
                            Map.of(
                                    "subject.principalId", "usr-gestor-101",
                                    "subject.organizationUnitIds", List.of(100L),
                                    "subject.cedenteOrgaoIds", List.of(),
                                    "subject.cessionarioOrgaoIds", List.of(2L)
                            )
                    );

                    autoCallerProvider.runWithContext(pureCedenteCaller, () -> {
                        // COLLECTION filter allowed
                        assertTrue(autoAvailability.evaluate(ResourceOperationAvailabilityContext.collection(
                                blueprint.resourceKey(), "/api/human-resources/afastamentos", "filter"
                        )).allowed());

                        // ITEM #101 (in-scope lotacao 100L, cedenteOrgaoId=1L, cessionarioOrgaoId=2L):
                        // view allowed, delete allowed for Cedente, homologar-afastamento allowed, designar-substituto denied
                        assertTrue(autoAvailability.evaluate(ResourceOperationAvailabilityContext.item(
                                blueprint.resourceKey(), "/api/human-resources/afastamentos", "view", 101L
                        )).allowed());
                        assertTrue(autoAvailability.evaluate(ResourceOperationAvailabilityContext.item(
                                blueprint.resourceKey(), "/api/human-resources/afastamentos", "delete", 101L
                        )).allowed());
                        assertTrue(autoAvailability.evaluate(ResourceOperationAvailabilityContext.item(
                                blueprint.resourceKey(), "/api/human-resources/afastamentos", "homologar-afastamento", 101L
                        )).allowed());
                        AvailabilityDecision designarForCedente = autoAvailability.evaluate(ResourceOperationAvailabilityContext.item(
                                blueprint.resourceKey(), "/api/human-resources/afastamentos", "designar-substituto", 101L
                        ));
                        assertFalse(designarForCedente.allowed(),
                                "P10.9: Pure Cedente caller (cedenteOrgaoIds=[1], cessionarioOrgaoIds=[]) must be denied Cessionário-exclusive designar-substituto on #101");
                        assertEquals("dual-scope-custody-denied", designarForCedente.reason());

                        // ITEM #102 (same tenant, out-of-scope lotacao 999L) denied by OPA TARGET gate
                        AvailabilityDecision view102 = autoAvailability.evaluate(ResourceOperationAvailabilityContext.item(
                                blueprint.resourceKey(), "/api/human-resources/afastamentos", "view", 102L
                        ));
                        assertFalse(view102.allowed());
                        assertEquals("policy-gate-denied", view102.reason());

                        // ITEM #103 (cross-tenant 'tenant-outro', even with lotacao 100L) denied by hard-scope tenant snapshot guard!
                        AvailabilityDecision view103 = autoAvailability.evaluate(ResourceOperationAvailabilityContext.item(
                                blueprint.resourceKey(), "/api/human-resources/afastamentos", "view", 103L
                        ));
                        assertFalse(view103.allowed(),
                                "P10.9: Cross-tenant item #103 must be denied in availability discovery via snapshot tenant guard");
                        assertEquals("hard-scope-tenant-mismatch", view103.reason());

                        // P10.9-R02: Non-existent item #999999L must fail closed with resource-state-not-found
                        AvailabilityDecision viewNonExistent = autoAvailability.evaluate(ResourceOperationAvailabilityContext.item(
                                blueprint.resourceKey(), "/api/human-resources/afastamentos", "view", 999999L
                        ));
                        assertFalse(viewNonExistent.allowed(),
                                "P10.9-R02: Non-existent item #999999L must fail closed in item availability discovery");
                        assertEquals("resource-state-not-found", viewNonExistent.reason());

                        // P10.9-R03: String raw resource ID ("101") resolved via ResolvableType on AopUtils.getTargetClass(this)
                        assertTrue(autoWiredService.resolveItemSnapshotForAvailability("101").isPresent(),
                                "P10.9-R03: resolveItemSnapshotForAvailability must convert string ID '101' to Long 101L");
                    });

                    // P10.9-R01: Custom cedenteCustodyPredicate & cessionarioCustodyPredicate parity on ResourceStateSnapshot
                    AuthzResourceGovernanceSpec<P102AfastamentoJpaEntity> customPredicateSpec =
                            AuthzResourceGovernanceSpec.<P102AfastamentoJpaEntity>builder(blueprint.resourceKey())
                                    .decisionPoint(blueprint.decisionPoint())
                                    .factContractDigest(blueprint.factContract().factContractDigest())
                                    .queryAdapter(
                                            blueprint.queryProjection(),
                                            List.of(new QueryAdapterFieldBinding(
                                                    blueprint.resourceKey(),
                                                    "resource.lotacaoSetorId",
                                                    "ergon.afastamentos.lotacao_setor_id",
                                                    "lotacaoSetorId",
                                                    RelationTraversalStrategy.INNER_JOIN_SCALAR,
                                                    true
                                            ))
                                    )
                                    .dualScopeDelegationSpec(blueprint.dualScopeSpec())
                                    .cedenteCustodyPredicate((entity, cCtx) -> Objects.equals(1L, entity.cedenteOrgaoId)
                                            && "usr-gestor-101".equals(cCtx.subjectAndEnvironmentFacts().get("subject.principalId")))
                                    .cessionarioCustodyPredicate((entity, cCtx) -> false)
                                    .tenantField("tenantId")
                                    .build();
                    P102AfastamentoJpaEntity entity101 = repository.findById(101L).orElseThrow();
                    var customPredicateSnapshot101 = customPredicateSpec.toResourceStateSnapshot(entity101);
                    assertTrue(customPredicateSpec.isCallerCedenteForSnapshot(customPredicateSnapshot101, pureCedenteCaller),
                            "P10.9-R01: isCallerCedenteForSnapshot must evaluate custom cedenteCustodyPredicate via SNAPSHOT_ENTITY_REF_META_KEY");
                    assertFalse(customPredicateSpec.isCallerCessionarioForSnapshot(customPredicateSnapshot101, pureCedenteCaller),
                            "P10.9-R01: isCallerCessionarioForSnapshot must evaluate custom cessionarioCustodyPredicate via SNAPSHOT_ENTITY_REF_META_KEY");
                    assertFalse(customPredicateSpec.isCallerCedenteForSnapshot(null, pureCedenteCaller),
                            "P10.9-R01: isCallerCedenteForSnapshot must fail closed (false) when snapshot is null");

                    // Pure Cessionário caller (cedenteOrgaoIds=[], cessionarioOrgaoIds=[2L]):
                    // designar-substituto allowed on #101, homologar-afastamento and delete denied!
                    autoCallerProvider.runWithContext(pureCessionarioCaller, () -> {
                        assertTrue(autoAvailability.evaluate(ResourceOperationAvailabilityContext.item(
                                blueprint.resourceKey(), "/api/human-resources/afastamentos", "designar-substituto", 101L
                        )).allowed());
                        assertFalse(autoAvailability.evaluate(ResourceOperationAvailabilityContext.item(
                                blueprint.resourceKey(), "/api/human-resources/afastamentos", "homologar-afastamento", 101L
                        )).allowed());
                        AvailabilityDecision deleteForCessionario = autoAvailability.evaluate(ResourceOperationAvailabilityContext.item(
                                blueprint.resourceKey(), "/api/human-resources/afastamentos", "delete", 101L
                        ));
                        assertFalse(deleteForCessionario.allowed());
                        assertEquals("dual-scope-cedente-custody-required", deleteForCessionario.reason());
                    });

                    // 19b. Verify AuthzCallerContextFilter binds context per HTTP request, captures incomingHeaderNames, and cleans up in finally
                    org.praxisplatform.authz.host.metadata.AuthzCallerContextFilter servletFilter =
                            ctx.getBean(org.praxisplatform.authz.host.metadata.AuthzCallerContextFilter.class);
                    org.springframework.mock.web.MockHttpServletRequest httpReq =
                            new org.springframework.mock.web.MockHttpServletRequest("GET", "/api/human-resources/afastamentos");
                    httpReq.addHeader("Authorization", "Bearer token-tenant-gov-br");
                    httpReq.addHeader("X-Request-Correlation", "corr-109");
                    org.springframework.mock.web.MockHttpServletResponse httpRes =
                            new org.springframework.mock.web.MockHttpServletResponse();

                    AtomicReference<AuthzCallerContext> observedInsideFilter = new AtomicReference<>();
                    AtomicReference<CollectionExportResult> exportedInsideFilter = new AtomicReference<>();
                    servletFilter.doFilter(httpReq, httpRes, (req, res) -> {
                        observedInsideFilter.set(autoCallerProvider.currentCallerContext());
                        exportedInsideFilter.set(
                                txTemplate.execute(status -> autoWiredService.exportCollection(exportReq))
                        );
                    });
                    assertNotNull(observedInsideFilter.get());
                    assertEquals("tenant-gov-br", observedInsideFilter.get().tenantId());
                    assertTrue(observedInsideFilter.get().incomingHeaderNames().stream()
                                    .anyMatch(h -> h.equalsIgnoreCase("X-Request-Correlation")),
                            "P10.9: AuthzCallerContextFilter must automatically populate incomingHeaderNames from HttpServletRequest");
                    assertFalse(autoCallerProvider.currentCallerContextOptional().isPresent(),
                            "P10.9: AuthzCallerContextFilter must clear ThreadLocal caller context in finally after request completes");

                    CollectionExportResult autoExported = exportedInsideFilter.get();
                    assertNotNull(autoExported);
                    String autoCsvText = new String(autoExported.content(), StandardCharsets.UTF_8);
                    assertFalse(autoCsvText.contains("M54.5"),
                            "Auto-initialized governed resource service must never leak raw CID M54.5 in CSV export (P10.7..P10.9)");
                    assertFalse(autoCsvText.contains("orgCedenteId"),
                            "Auto-initialized governed resource service must strip @DomainGovernance(exportable = false) fields via wrapped CollectionExportExecutor (P10.7..P10.9)");
                    assertTrue(autoCsvText.contains("101"),
                            "Auto-initialized governed resource service must export in-scope record #101 (P10.7..P10.9)");

                    // P10.9-R04 & P10.9-R05: Spoofed authority headers (X-Tenant-Id / X-Bypass-Policy) captured by AuthzCallerContextFilter
                    // must be rejected with UntrustedHeaderSpoofingException on BOTH read (exportCollection) and write (create)!
                    org.springframework.mock.web.MockHttpServletRequest spoofedReq =
                            new org.springframework.mock.web.MockHttpServletRequest("POST", "/api/human-resources/afastamentos");
                    spoofedReq.addHeader("Authorization", "Bearer token-tenant-gov-br");
                    spoofedReq.addHeader("X-Tenant-Id", "tenant-spoofed-by-client");
                    assertThrows(org.praxisplatform.authz.enforcement.context.UntrustedHeaderSpoofingException.class, () ->
                            servletFilter.doFilter(spoofedReq, new org.springframework.mock.web.MockHttpServletResponse(), (req, res) ->
                                    txTemplate.execute(status -> autoWiredService.exportCollection(exportReq))
                            ),
                            "P10.9-R05: Spoofed X-Tenant-Id header captured by AuthzCallerContextFilter must be rejected on read queries"
                    );
                    assertThrows(org.praxisplatform.authz.enforcement.context.UntrustedHeaderSpoofingException.class, () ->
                            servletFilter.doFilter(spoofedReq, new org.springframework.mock.web.MockHttpServletResponse(), (req, res) ->
                                    txTemplate.execute(status -> autoWiredService.create(new AfastamentoAnnotatedCreateDTO(
                                            119L, "tenant-gov-br", 1L, 2L, 100L, "DEFERIDO", null, "CID-M54.5"
                                    )))
                            ),
                            "P10.9-R04: Spoofed X-Tenant-Id header captured by AuthzCallerContextFilter must be rejected on POST/create mutations before STEP_11"
                    );
                    assertFalse(autoCallerProvider.currentCallerContextOptional().isPresent(),
                            "P10.9-R05: AuthzCallerContextFilter must clear ThreadLocal caller context even after UntrustedHeaderSpoofingException");

                    // 20. Fase P10.10: Zero-Boilerplate Governed @WorkflowAction / @ResourceIntent Command Execution
                    // (executeGovernedVersionedCommand & executeGovernedItemCommand) + Dedicated Action/Surface DecisionPoint Routing
                    int outboxBeforeP1010 = jdbcOutbox.listCommittedEntries().size();

                    // 20a. Parameterized command (DesignarSubstitutoCommandDTO without @DomainLineage — inherited from ResponseDTO):
                    // Denied at STEP_11 for pureCedenteCaller, permitted for pureCessionarioCaller!
                    long verBefore20a = autoCallerProvider.callWithContext(pureCedenteCaller, () ->
                            txTemplate.execute(status -> autoWiredService.findById(101L))
                    ).requirePersistedVersion();
                    ResourceVersionUpdatePrecondition<Long> precond20a = new ResourceVersionUpdatePrecondition<>(
                            etagService,
                            etagService.create(blueprint.resourceKey(), 101L, verBefore20a),
                            blueprint.resourceKey(),
                            101L
                    );

                    assertThrows(FieldWriteViolationException.class, () ->
                            autoCallerProvider.callWithContext(pureCedenteCaller, () ->
                                    txTemplate.execute(status ->
                                            autoWiredService.designarSubstituto(101L, new DesignarSubstitutoCommandDTO(9101L), precond20a)
                                    )
                            ),
                            "P10.10: Pure Cedente caller must be blocked at STEP_11 from executing Cessionário-exclusive designarSubstituto"
                    );
                    assertEquals(outboxBeforeP1010, jdbcOutbox.listCommittedEntries().size());

                    ResourceRepresentationResult<AfastamentoAnnotatedResponseDTO> designadoRes =
                            autoCallerProvider.callWithContext(pureCessionarioCaller, () ->
                                    txTemplate.execute(status ->
                                            autoWiredService.designarSubstituto(101L, new DesignarSubstitutoCommandDTO(9101L), precond20a)
                                    )
                            );
                    assertNotNull(designadoRes);
                    assertEquals(verBefore20a + 1L, designadoRes.requirePersistedVersion());
                    assertEquals(9101L, designadoRes.body().substitutoServidorId());
                    assertEquals("***CID-RESTRITO***", designadoRes.body().cidCodigo(),
                            "P10.10: executeGovernedVersionedCommand must return masked ResponseDTO");
                    assertEquals(outboxBeforeP1010 + 1, jdbcOutbox.listCommittedEntries().size(),
                            "P10.10: executeGovernedVersionedCommand must fulfill BEFORE_COMMIT_OUTBOX atomically");

                    // 20b. Non-versioned executeGovernedItemCommand transitions #101 back to DEFERIDO
                    AfastamentoAnnotatedResponseDTO deferidoAgain = autoCallerProvider.callWithContext(pureCedenteCaller, () ->
                            txTemplate.execute(status -> autoWiredService.reverterParaDeferidoSemVersao(101L))
                    );
                    assertNotNull(deferidoAgain);
                    assertEquals("DEFERIDO", deferidoAgain.statusAfastamento());
                    assertEquals("***CID-RESTRITO***", deferidoAgain.cidCodigo());
                    assertEquals(outboxBeforeP1010 + 2, jdbcOutbox.listCommittedEntries().size());

                    // 20c. Parameterless @WorkflowAction command (commandDto = null, synthesized from operationModifiedAttributes):
                    // Denied at STEP_11 for pureCessionarioCaller, permitted for pureCedenteCaller (DEFERIDO -> HOMOLOGADO)!
                    long verBefore20c = autoCallerProvider.callWithContext(pureCedenteCaller, () ->
                            txTemplate.execute(status -> autoWiredService.findById(101L))
                    ).requirePersistedVersion();
                    ResourceVersionUpdatePrecondition<Long> precond20c = new ResourceVersionUpdatePrecondition<>(
                            etagService,
                            etagService.create(blueprint.resourceKey(), 101L, verBefore20c),
                            blueprint.resourceKey(),
                            101L
                    );
                    assertThrows(FieldWriteViolationException.class, () ->
                            autoCallerProvider.callWithContext(pureCessionarioCaller, () ->
                                    txTemplate.execute(status ->
                                            autoWiredService.homologarSemPayload(101L, precond20c)
                                    )
                            ),
                            "P10.10: Pure Cessionário caller must be blocked at STEP_11 from parameterless Cedente-exclusive homologar-afastamento"
                    );
                    assertEquals(outboxBeforeP1010 + 2, jdbcOutbox.listCommittedEntries().size());

                    ResourceRepresentationResult<AfastamentoAnnotatedResponseDTO> homologadoRes =
                            autoCallerProvider.callWithContext(pureCedenteCaller, () ->
                                    txTemplate.execute(status ->
                                            autoWiredService.homologarSemPayload(101L, precond20c)
                                    )
                            );
                    assertNotNull(homologadoRes);
                    assertEquals(verBefore20c + 1L, homologadoRes.requirePersistedVersion());
                    assertEquals("HOMOLOGADO", homologadoRes.body().statusAfastamento());
                    assertEquals("***CID-RESTRITO***", homologadoRes.body().cidCodigo());
                    assertEquals(outboxBeforeP1010 + 3, jdbcOutbox.listCommittedEntries().size());

                    // 20d (P10.10-R03): Command DTO with request-only workflow parameters (justificativaHomologacao, numeroProcessoSei)
                    // that are NOT on ResponseDTO and have no @DomainLineage: must NOT trigger false-positive AUTHZ_FIELD_WRITE_DEFAULT_DENIED
                    // when operationModifiedAttributes declares the modified entity attribute ("ergon.afastamentos.status_afastamento").
                    autoCallerProvider.callWithContext(pureCedenteCaller, () ->
                            txTemplate.execute(status -> autoWiredService.reverterParaDeferidoSemVersao(101L))
                    );
                    HomologarComJustificativaCommandDTO cmdComJustificativa = new HomologarComJustificativaCommandDTO(
                            "Aprovado pela Junta Médica Oficial",
                            "SEI-2026/000991"
                    );
                    assertThrows(FieldWriteViolationException.class, () ->
                            autoCallerProvider.callWithContext(pureCessionarioCaller, () ->
                                    txTemplate.execute(status ->
                                            autoWiredService.homologarComJustificativa(101L, cmdComJustificativa)
                                    )
                            ),
                            "P10.10-R03: Pure Cessionário caller must still be blocked on declaredModifiedAttrs ('ergon.afastamentos.status_afastamento')"
                    );
                    AfastamentoAnnotatedResponseDTO homologadoComJustificativa = autoCallerProvider.callWithContext(pureCedenteCaller, () ->
                            txTemplate.execute(status ->
                                    autoWiredService.homologarComJustificativa(101L, cmdComJustificativa)
                            )
                    );
                    assertNotNull(homologadoComJustificativa);
                    assertEquals("HOMOLOGADO", homologadoComJustificativa.statusAfastamento());
                    assertEquals("***CID-RESTRITO***", homologadoComJustificativa.cidCodigo());

                    // 20e (P10.10-R01): Action vs. Surface namespace isolation when @WorkflowAction and @UiSurface share the same ID
                    org.praxisplatform.authz.contracts.decisionpoint.DecisionPointDescriptor actionOnlyDp =
                            AfastamentoAuthzPilotBlueprint.createHostBlueprint(
                                    "praxis-ergon-showcase",
                                    "human-resources.afastamentos.action-alocacao",
                                    "ergon.afastamentos"
                            ).decisionPoint();
                    org.praxisplatform.authz.contracts.decisionpoint.DecisionPointDescriptor surfaceOnlyDp =
                            AfastamentoAuthzPilotBlueprint.createHostBlueprint(
                                    "praxis-ergon-showcase",
                                    "human-resources.afastamentos.surface-alocacao",
                                    "ergon.afastamentos"
                            ).decisionPoint();
                    AuthzResourceGovernanceSpec<P102AfastamentoJpaEntity> actionRoutingSpec =
                            AuthzResourceGovernanceSpec.<P102AfastamentoJpaEntity>builder(blueprint.resourceKey())
                                    .decisionPoint(blueprint.decisionPoint())
                                    .factContractDigest(blueprint.factContract().factContractDigest())
                                    .queryAdapter(blueprint.queryProjection(), governanceSpec.fieldBindings())
                                    .actionDecisionPoint("alocacao-organizacional", actionOnlyDp)
                                    .surfaceDecisionPoint("alocacao-organizacional", surfaceOnlyDp)
                                    .tenantField("tenantId")
                                    .build();
                    AuthzResourceOperationAvailabilityProvider.ResourceAvailabilityPolicyBinding isolatedBinding =
                            new AuthzResourceOperationAvailabilityProvider.ResourceAvailabilityPolicyBinding(
                                    blueprint.resourceKey(),
                                    blueprint.decisionPoint(),
                                    blueprint.factContract().factContractDigest(),
                                    null,
                                    Map.of(),
                                    () -> new CallerAvailabilityFactContext(Map.of(), Map.of(), true, true),
                                    snapshot -> Map.of(),
                                    null,
                                    null,
                                    null,
                                    actionRoutingSpec.actionDecisionPoints(),
                                    actionRoutingSpec.surfaceDecisionPoints()
                            );
                    assertEquals(actionOnlyDp, isolatedBinding.resolveActionDecisionPoint("alocacao-organizacional"),
                            "P10.10-R01: resolveActionDecisionPoint must resolve from actionDecisionPoints");
                    assertEquals(surfaceOnlyDp, isolatedBinding.resolveSurfaceDecisionPoint("alocacao-organizacional"),
                            "P10.10-R01: resolveSurfaceDecisionPoint must resolve from surfaceDecisionPoints without colliding with actionDecisionPoints");
                    assertEquals(blueprint.decisionPoint(), isolatedBinding.resolveSurfaceDecisionPoint("unmapped-surface"),
                            "P10.10-R01: resolveSurfaceDecisionPoint must fall back to default DecisionPointDescriptor when surface ID is not overridden");

                    // 20f (P10.10-R02): Deterministic ThreadLocal cleanup on mid-mutation / precondition failure
                    ResourceVersionUpdatePrecondition<Long> stalePrecond20f = new ResourceVersionUpdatePrecondition<>(
                            etagService,
                            etagService.create(blueprint.resourceKey(), 101L, 0L),
                            blueprint.resourceKey(),
                            101L
                    );
                    autoCallerProvider.runWithContext(pureCedenteCaller, () ->
                            txTemplate.executeWithoutResult(status -> {
                                assertThrows(org.praxisplatform.uischema.concurrency.ResourceVersionPreconditionException.class, () ->
                                        autoWiredService.homologarSemPayload(101L, stalePrecond20f),
                                        "P10.10-R02: Stale If-Match precondition must throw ResourceVersionPreconditionException (412)"
                                );
                                assertFalse(serviceSupport.hasActiveQueryContext(),
                                        "P10.10-R02: Stale If-Match failure after findEntityForMutation must immediately clean up activeQueryContext even before transaction completion");
                                assertFalse(serviceSupport.hasActiveMutationContext(),
                                        "P10.10-R02: Stale If-Match failure must leave no activeMutationContext residue");
                            })
                    );

                    assertThrows(IllegalStateException.class, () ->
                            autoCallerProvider.callWithContext(pureCedenteCaller, () ->
                                    autoWiredService.executeFailingCommandAfterStep11(101L)
                            )
                    );
                    assertFalse(serviceSupport.hasActiveQueryContext(),
                            "P10.10-R02: Command failing inside entityMutator after STEP_11 outside @Transactional must clean up activeQueryContext");
                    assertFalse(serviceSupport.hasActiveMutationContext(),
                            "P10.10-R02: Command failing inside entityMutator after STEP_11 outside @Transactional must clean up activeMutationContext");

                    // 20g (P10.10-R04 & P10.10-R05): Verify ResourceTenantContextResolver bean & createGovernedCommandExecutor helper
                    org.praxisplatform.uischema.customfields.ResourceTenantContextResolver tenantResolver =
                            ctx.getBean(org.praxisplatform.uischema.customfields.ResourceTenantContextResolver.class);
                    assertTrue(tenantResolver.resolveTenant().isEmpty(),
                            "P10.10-R04: ResourceTenantContextResolver must return Optional.empty() when no AuthzCallerContext is bound");
                    Optional<String> resolvedAuthzTenant = autoCallerProvider.callWithContext(
                            pureCedenteCaller,
                            tenantResolver::resolveTenant
                    );
                    assertEquals(Optional.of("tenant-gov-br"), resolvedAuthzTenant,
                            "P10.10-R04: ResourceTenantContextResolver must resolve authoritative tenantId from AuthzCallerContextProvider");

                    GovernedResourceCommandExecutor helperExecutor = autoWiredService.createGovernedCommandExecutor(
                            cmdReq -> ResourceCommandExecutionResult.success(cmdReq, 101L, Map.of("ok", true), Map.of()),
                            autoAvailability
                    );
                    ResourceCommandExecutionResult helperDenied = autoCallerProvider.callWithContext(pureCedenteCaller, () ->
                            helperExecutor.execute(ResourceCommandExecutionRequest.item(
                                    blueprint.resourceKey(),
                                    "/api/human-resources/afastamentos",
                                    "designar-substituto",
                                    101L,
                                    new DesignarSubstitutoCommandDTO(9101L),
                                    ResourceCommandResponsePolicy.READ_AFTER_WRITE
                            ))
                    );
                    assertEquals(ResourceCommandOutcome.PERMISSION_DENIED, helperDenied.outcome(),
                            "P10.10-R05: createGovernedCommandExecutor must enforce dual-scope availability on item command");

                    // 21. Fase P10.11: Zero-Boilerplate Reactive Determinations, AI Context Grounding,
                    // Governed Assisted Duplicate-Draft (executeGovernedDuplicateDraft), and 3-arg bulkDomainAdapter
                    int outboxBeforeP1011 = jdbcOutbox.listCommittedEntries().size();

                    // 21a. Auto-registered ReactiveDeterminationDefinitionProvider aggregates service defineReactiveDeterminations()
                    assertTrue(ctx.containsBean("authzGovernedServicesReactiveDeterminationProvider"),
                            "P10.11: PraxisAuthzHostBridgeAutoConfiguration must auto-register authzGovernedServicesReactiveDeterminationProvider");
                    org.praxisplatform.uischema.determination.ReactiveDeterminationDefinitionProvider autoDetProvider =
                            ctx.getBean("authzGovernedServicesReactiveDeterminationProvider",
                                    org.praxisplatform.uischema.determination.ReactiveDeterminationDefinitionProvider.class);
                    assertEquals(1, autoDetProvider.definitions().size());
                    assertEquals("det-substituto-preview-spec", autoDetProvider.definitions().iterator().next().id());

                    // 21b. evaluateGovernedItemDetermination masks cidCodigo on #101, rejects out-of-scope #102 & cross-tenant #103, and writes 0 outbox entries
                    Map<String, Object> itemDet101 = autoCallerProvider.callWithContext(pureCedenteCaller, () ->
                            txTemplate.execute(status ->
                                    autoWiredService.evaluateGovernedItemDetermination(101L, entity ->
                                            autoWiredService.prepareUpdateValidationDraft(
                                                    101L,
                                                    entity,
                                                    new AfastamentoAnnotatedUpdateDTO(9202L, entity.cidCodigo)
                                            )
                                    )
                            )
                    );
                    assertNotNull(itemDet101);
                    assertEquals("***CID-RESTRITO***", itemDet101.get("cidCodigo"),
                            "P10.11: evaluateGovernedItemDetermination must mask restricted cidCodigo via live OPA TARGET evaluation");
                    assertEquals(outboxBeforeP1011, jdbcOutbox.listCommittedEntries().size(),
                            "P10.11: evaluateGovernedItemDetermination must never write BEFORE_COMMIT_OUTBOX entries");
                    assertFalse(serviceSupport.hasActiveQueryContext());

                    assertThrows(SecurityException.class, () ->
                            autoCallerProvider.callWithContext(pureCedenteCaller, () ->
                                    txTemplate.execute(status ->
                                            autoWiredService.evaluateGovernedItemDetermination(102L, entity -> Map.of("ok", true))
                                    )
                            ),
                            "P10.11: evaluateGovernedItemDetermination must fail closed on out-of-scope #102"
                    );
                    assertThrows(SecurityException.class, () ->
                            autoCallerProvider.callWithContext(pureCedenteCaller, () ->
                                    txTemplate.execute(status ->
                                            autoWiredService.evaluateGovernedItemDetermination(103L, entity -> Map.of("ok", true))
                                    )
                            ),
                            "P10.11: evaluateGovernedItemDetermination must fail closed on cross-tenant #103"
                    );

                    // 21c. evaluateGovernedDraftDetermination masks in-scope candidate and rejects out-of-scope candidate
                    P102AfastamentoJpaEntity inScopeCandidate = new P102AfastamentoJpaEntity(
                            990L, "tenant-gov-br", 1L, 2L, 100L, "RASCUNHO", 9303L, "CID-G43.9"
                    );
                    Map<String, Object> draftDetOut = autoCallerProvider.callWithContext(pureCedenteCaller, () ->
                            autoWiredService.evaluateGovernedDraftDetermination(inScopeCandidate, () ->
                                    new AfastamentoAnnotatedResponseDTO(
                                            inScopeCandidate.id,
                                            inScopeCandidate.tenantId,
                                            inScopeCandidate.cedenteOrgaoId,
                                            inScopeCandidate.cessionarioOrgaoId,
                                            inScopeCandidate.lotacaoSetorId,
                                            inScopeCandidate.statusAfastamento,
                                            inScopeCandidate.substitutoServidorId,
                                            inScopeCandidate.cidCodigo
                                    )
                            )
                    );
                    assertEquals(9303L, draftDetOut.get("substitutoServidorId"));
                    assertEquals("***CID-RESTRITO***", draftDetOut.get("cidCodigo"));

                    P102AfastamentoJpaEntity outOfScopeCandidate = new P102AfastamentoJpaEntity(
                            991L, "tenant-gov-br", 1L, 2L, 999L, "RASCUNHO", 9303L, "CID-G43.9"
                    );
                    assertThrows(SecurityException.class, () ->
                            autoCallerProvider.callWithContext(pureCedenteCaller, () ->
                                    autoWiredService.evaluateGovernedDraftDetermination(outOfScopeCandidate, () -> Map.of("ok", true))
                            ),
                            "P10.11: evaluateGovernedDraftDetermination must fail closed on out-of-scope candidate entity"
                    );

                    // 21d. projectGovernedItemAiContext & projectAiGovernanceMetadata
                    SanitizedAiToolProjection itemAi101 = autoCallerProvider.callWithContext(pureCedenteCaller, () ->
                            txTemplate.execute(status -> autoWiredService.projectGovernedItemAiContext(101L))
                    );
                    assertNotNull(itemAi101);
                    assertFalse(itemAi101.detachedPayload().containsKey("cidCodigo"),
                            "P10.11: projectGovernedItemAiContext must completely suppress LGPD_SENSITIVE_DATA cidCodigo");
                    assertTrue(itemAi101.suppressedAiAttributeIds().contains("ergon.afastamentos.cid_codigo"));
                    assertEquals(blueprint.bundleArtifact().runtimeHead().runtimeRevision(), itemAi101.runtimeRevision());
                    assertEquals(8, autoWiredService.projectAiGovernanceMetadata().size());

                    // 21e. executeGovernedDuplicateDraft (DuplicateDraftResourceService governance):
                    // - For pureCedenteCaller: strips cidCodigo (LGPD_SENSITIVE_DATA) AND Cessionário-exclusive substitutoServidorId
                    //   to null so the Cedente caller can immediately persist the duplicated draft without hitting 403 at STEP_11!
                    AfastamentoAnnotatedCreateDTO cedenteDraft = autoCallerProvider.callWithContext(pureCedenteCaller, () ->
                            txTemplate.execute(status -> autoWiredService.duplicateDraft(101L))
                    );
                    assertNotNull(cedenteDraft);
                    assertEquals("tenant-gov-br", cedenteDraft.tenantId());
                    assertEquals(1L, cedenteDraft.orgCedenteId());
                    assertEquals(2L, cedenteDraft.orgCessionariaId());
                    assertEquals(100L, cedenteDraft.lotacaoSetorId());
                    assertEquals("RASCUNHO", cedenteDraft.statusAfastamento());
                    assertEquals(null, cedenteDraft.cidCodigo(),
                            "P10.11: executeGovernedDuplicateDraft must strip LGPD_SENSITIVE_DATA / masked cidCodigo to null");
                    assertEquals(null, cedenteDraft.substitutoServidorId(),
                            "P10.11: executeGovernedDuplicateDraft must strip Cessionário-exclusive substitutoServidorId to null for pureCedenteCaller");
                    assertEquals(outboxBeforeP1011, jdbcOutbox.listCommittedEntries().size(),
                            "P10.11: executeGovernedDuplicateDraft must be non-persistent and write zero outbox entries");

                    // Submitting the sanitized duplicate draft (with new ID 120L) succeeds for pureCedenteCaller!
                    AfastamentoAnnotatedCreateDTO readyToCreateFromDraft = new AfastamentoAnnotatedCreateDTO(
                            120L,
                            cedenteDraft.tenantId(),
                            cedenteDraft.orgCedenteId(),
                            cedenteDraft.orgCessionariaId(),
                            cedenteDraft.lotacaoSetorId(),
                            cedenteDraft.statusAfastamento(),
                            cedenteDraft.substitutoServidorId(),
                            cedenteDraft.cidCodigo()
                    );
                    var createdFromDraft = autoCallerProvider.callWithContext(pureCedenteCaller, () ->
                            txTemplate.execute(status -> autoWiredService.create(readyToCreateFromDraft))
                    );
                    assertNotNull(createdFromDraft);
                    assertEquals(120L, createdFromDraft.id());
                    autoCallerProvider.runWithContext(pureCedenteCaller, () ->
                            txTemplate.executeWithoutResult(status -> autoWiredService.deleteById(120L))
                    );

                    // For pureCessionarioCaller: preserves substitutoServidorId=9101L and strips Cedente-exclusive statusAfastamento & cidCodigo!
                    AfastamentoAnnotatedCreateDTO cessionarioDraft = autoCallerProvider.callWithContext(pureCessionarioCaller, () ->
                            txTemplate.execute(status -> autoWiredService.duplicateDraft(101L))
                    );
                    assertNotNull(cessionarioDraft);
                    assertEquals(9101L, cessionarioDraft.substitutoServidorId(),
                            "P10.11: executeGovernedDuplicateDraft must retain Cessionário-permitted substitutoServidorId for pureCessionarioCaller");
                    assertEquals(null, cessionarioDraft.statusAfastamento(),
                            "P10.11: executeGovernedDuplicateDraft must strip Cedente-exclusive statusAfastamento for pureCessionarioCaller");
                    assertEquals(null, cessionarioDraft.cidCodigo());

                    // For caller holding neither Cedente nor Cessionário custody on #101: both discovery and execution fail closed!
                    AuthzCallerContext noCustodyCaller = AuthzCallerContext.of(
                            "tenant-gov-br",
                            Map.of(
                                    "subject.principalId", "usr-gestor-101",
                                    "subject.organizationUnitIds", List.of(100L),
                                    "subject.cedenteOrgaoIds", List.of(99L),
                                    "subject.cessionarioOrgaoIds", List.of(99L)
                            )
                    );
                    autoCallerProvider.runWithContext(noCustodyCaller, () -> {
                        AvailabilityDecision dupDraftNoCustody = autoAvailability.evaluate(
                                ResourceOperationAvailabilityContext.item(
                                        blueprint.resourceKey(), "/api/human-resources/afastamentos", "duplicate-draft", 101L
                                )
                        );
                        assertFalse(dupDraftNoCustody.allowed(),
                                "P10.11: duplicate-draft discovery must fail closed when caller holds neither Cedente nor Cessionário custody");
                        assertEquals("dual-scope-custody-denied", dupDraftNoCustody.reason());

                        SecurityException dupDraftExecEx = assertThrows(SecurityException.class, () ->
                                txTemplate.execute(status -> autoWiredService.duplicateDraft(101L))
                        );
                        assertTrue(dupDraftExecEx.getMessage().contains("AUTHZ_DUPLICATE_DRAFT_CUSTODY_DENIED"));
                    });

                    // 21f. 3-arg bulkDomainAdapter automatically resolves ResourceVersionScope from AuthzCallerContextProvider
                    AuthzGovernedBulkDomainResourceAdapter<Long, AfastamentoFilterDTO> autoScopedBulkAdapter =
                            autoWiredService.bulkDomainAdapter(bulkMapper, beanValidator, etagService);
                    List<Long> autoBulkSelected = autoCallerProvider.callWithContext(pureCedenteCaller, () ->
                            txTemplate.execute(status ->
                                    autoScopedBulkAdapter.selectBulkIdentities(
                                            new AfastamentoFilterDTO(),
                                            List.of(101L, 102L),
                                            List.of(),
                                            50
                                    )
                            )
                    );
                    assertTrue(autoBulkSelected.contains(101L));
                    assertFalse(autoBulkSelected.contains(102L));

                    // 22. Fase P10.12: AuthzHostReadinessReviewer & AUTHZ-HOST-ADOPTION-GUIDE.md
                    // 22a. Auto-configured AuthzHostReadinessReviewer passes AfastamentoDeclarativeService with zero issues
                    assertTrue(ctx.containsBean("authzHostReadinessReviewer"),
                            "P10.12: PraxisAuthzHostBridgeAutoConfiguration must auto-register AuthzHostReadinessReviewer");
                    AuthzHostReadinessReviewer readinessReviewer = ctx.getBean(AuthzHostReadinessReviewer.class);
                    AuthzHostReadinessReviewer.ReadinessReport cleanReport =
                            readinessReviewer.reviewMutableService(autoWiredService);
                    assertTrue(cleanReport.isReady(), "P10.12: AfastamentoDeclarativeService must have zero errors");
                    assertTrue(cleanReport.isClean(), "P10.12: AfastamentoDeclarativeService must have zero warnings");
                    cleanReport.assertZeroIssues();

                    // 22b. Reviewing manual-override ConciseAfastamentoRadarReadOnlyService emits AUTHZ-HOST-001-MANUAL-OVERRIDE-MODE warning
                    AuthzHostReadinessReviewer.ReadinessReport manualModeReport =
                            readinessReviewer.reviewAll(List.of(radarReadOnlyService), List.of(autoWiredService));
                    assertEquals(2, manualModeReport.reviewedServiceCount());
                    assertTrue(manualModeReport.isReady(), "Manual override mode is a warning, not a blocking error");
                    assertEquals(1, manualModeReport.warnings().size());
                    assertEquals("AUTHZ-HOST-001-MANUAL-OVERRIDE-MODE", manualModeReport.warnings().get(0).ruleCode());

                    // 22c. Reviewing a misconfigured AuthzResourceGovernanceSpec detects AUTHZ-HOST-003..007 defects
                    DualScopeDelegationSpec brokenDualScope = new DualScopeDelegationSpec(
                            "BROKEN_DUAL_SCOPE",
                            "resource.orgCedenteId",
                            "resource.orgCessionariaId",
                            Set.of("ergon.afastamentos.status_afastamento", "ergon.afastamentos.unmapped_cedente_attr"),
                            Set.of("ergon.afastamentos.substituto_servidor_id", "ergon.afastamentos.unmapped_cessionario_attr")
                    );
                    AuthzResourceGovernanceSpec<P102AfastamentoJpaEntity> brokenSpec =
                            AuthzResourceGovernanceSpec.<P102AfastamentoJpaEntity>builder(blueprint.resourceKey())
                                    .decisionPoint(blueprint.decisionPoint())
                                    .factContractDigest("sha256:drifted-digest-mismatch")
                                    .queryAdapter(
                                            blueprint.queryProjection(),
                                            List.of(new QueryAdapterFieldBinding(
                                                    blueprint.resourceKey(),
                                                    "resource.lotacaoSetorId",
                                                    "ergon.afastamentos.lotacao_setor_id",
                                                    "e.nonExistentJpaField",
                                                    RelationTraversalStrategy.INNER_JOIN_SCALAR,
                                                    true
                                            ))
                                    )
                                    .tenantField("nonExistentTenantField")
                                    .stateField("nonExistentStateField")
                                    .mandatoryScopeAnchorAttributeIds(Set.of("ergon.afastamentos.non_existent_anchor"))
                                    .dualScopeDelegationSpec(brokenDualScope)
                                    .operationModifiedAttributes("empty-op", Set.of())
                                    .operationModifiedAttributes("bad-op", Set.of("ergon.afastamentos.unknown_op_attr"))
                                    .build();

                    AuthzHostReadinessReviewer reviewerWithRegistry = new AuthzHostReadinessReviewer(
                            ctx.getBean(MetadataDtoGovernanceIntrospector.class),
                            new org.praxisplatform.authz.seams.RuntimeDecisionPointRegistry(
                                    blueprint.admissionRecords(),
                                    blueprint.coordinates()
                            )
                    );
                    AuthzHostReadinessReviewer.ReadinessReport brokenReport = reviewerWithRegistry.reviewGovernanceSpec(
                            brokenSpec,
                            P102AfastamentoJpaEntity.class,
                            AfastamentoAnnotatedResponseDTO.class,
                            AfastamentoAnnotatedCreateDTO.class,
                            AfastamentoAnnotatedUpdateDTO.class
                    );
                    assertFalse(brokenReport.isReady());
                    Set<String> detectedRuleCodes = brokenReport.issues().stream()
                            .map(AuthzHostReadinessReviewer.ReadinessIssue::ruleCode)
                            .collect(java.util.stream.Collectors.toSet());
                    assertTrue(detectedRuleCodes.contains("AUTHZ-HOST-003-MISSING-MANDATORY-SCOPE-ANCHOR"));
                    assertTrue(detectedRuleCodes.contains("AUTHZ-HOST-004-MISSING-DECLARATIVE-CUSTODY-RULES"));
                    assertTrue(detectedRuleCodes.contains("AUTHZ-HOST-004-UNMAPPED-DUAL-SCOPE-ATTRIBUTE"));
                    assertTrue(detectedRuleCodes.contains("AUTHZ-HOST-005-EMPTY-OPERATION-ATTRIBUTES"));
                    assertTrue(detectedRuleCodes.contains("AUTHZ-HOST-005-UNKNOWN-OPERATION-ATTRIBUTE"));
                    assertTrue(detectedRuleCodes.contains("AUTHZ-HOST-006-INVALID-ENTITY-FIELD-PATH"));
                    assertTrue(detectedRuleCodes.contains("AUTHZ-HOST-006-INVALID-QUERY-BINDING-PATH"));
                    assertTrue(detectedRuleCodes.contains("AUTHZ-HOST-007-FACT-DIGEST-MISMATCH"));
                    IllegalStateException readinessEx = assertThrows(
                            IllegalStateException.class,
                            brokenReport::assertReady
                    );
                    assertTrue(readinessEx.getMessage().contains("AUTHZ_HOST_READINESS_FAILED"));

                    // 22d. Verify META-INF/praxis/AUTHZ-HOST-ADOPTION-GUIDE.md is packaged on the classpath
                    try (var guideStream = Thread.currentThread().getContextClassLoader()
                            .getResourceAsStream("META-INF/praxis/AUTHZ-HOST-ADOPTION-GUIDE.md")) {
                        assertNotNull(guideStream, "P10.12: META-INF/praxis/AUTHZ-HOST-ADOPTION-GUIDE.md must be packaged in praxis-authz-starter");
                        String guideText = new String(guideStream.readAllBytes(), StandardCharsets.UTF_8);
                        assertTrue(guideText.contains("AuthzHostReadinessReviewer"));
                        assertTrue(guideText.contains("AuthzResourceGovernanceSpec"));
                        assertTrue(guideText.contains("ReactiveDeterminationDefinition.forCrudResource"));
                    }

                    // 22e. Critical Review P10.12-R01..R06:
                    // - 3-arg evaluateGovernedItemDetermination / evaluateGovernedDraftDetermination overloads
                    // - AUTHZ-HOST-007 digest mismatch detected even without RuntimeDecisionPointRegistry
                    Map<String, Object> itemDet3Arg = autoCallerProvider.callWithContext(pureCedenteCaller, () ->
                            txTemplate.execute(status ->
                                    autoWiredService.evaluateGovernedItemDetermination(
                                            101L,
                                            "det-substituto-preview-spec",
                                            entity -> autoWiredService.prepareUpdateValidationDraft(
                                                    101L,
                                                    entity,
                                                    new AfastamentoAnnotatedUpdateDTO(9202L, entity.cidCodigo)
                                            )
                                    )
                            )
                    );
                    assertEquals("***CID-RESTRITO***", itemDet3Arg.get("cidCodigo"));

                    P102AfastamentoJpaEntity draftDetEntity = new P102AfastamentoJpaEntity(
                            998L, "tenant-gov-br", 1L, 2L, 100L, "RASCUNHO", 9303L, "CID-G43.9"
                    );
                    Map<String, Object> draftDet3Arg = autoCallerProvider.callWithContext(pureCedenteCaller, () ->
                            autoWiredService.evaluateGovernedDraftDetermination(
                                    draftDetEntity,
                                    "det-substituto-preview-spec",
                                    () -> new AfastamentoAnnotatedResponseDTO(
                                            draftDetEntity.id,
                                            draftDetEntity.tenantId,
                                            draftDetEntity.cedenteOrgaoId,
                                            draftDetEntity.cessionarioOrgaoId,
                                            draftDetEntity.lotacaoSetorId,
                                            draftDetEntity.statusAfastamento,
                                            draftDetEntity.substitutoServidorId,
                                            draftDetEntity.cidCodigo
                                    )
                            )
                    );
                    assertEquals("***CID-RESTRITO***", draftDet3Arg.get("cidCodigo"));

                    AuthzHostReadinessReviewer.ReadinessReport registrylessBrokenReport =
                            readinessReviewer.reviewGovernanceSpec(
                                    brokenSpec,
                                    P102AfastamentoJpaEntity.class,
                                    AfastamentoAnnotatedResponseDTO.class,
                                    AfastamentoAnnotatedCreateDTO.class,
                                    AfastamentoAnnotatedUpdateDTO.class
                            );
                    assertTrue(
                            registrylessBrokenReport.issues().stream()
                                    .anyMatch(i -> "AUTHZ-HOST-007-FACT-DIGEST-MISMATCH".equals(i.ruleCode())),
                            "P10.12-R05: AUTHZ-HOST-007 must detect factContractDigest mismatch against decisionPoint.factContractRef() even without RuntimeDecisionPointRegistry"
                    );

                    // 23. Fase P10.13: Automatic FieldLineageCatalogEntry Derivation, WriteDTO Governance Inheritance,
                    // RuntimeDecisionPointRegistry + SemanticDecisionPointCatalogService Synchronization, and AUTHZ-HOST-009
                    // 23a. deriveFieldLineageCatalogEntries across ResponseDTO (8), CreateDTO (8), and UpdateDTO (2) = 18 entries
                    List<org.praxisplatform.authz.catalog.FieldLineageCatalogEntry> derivedLineage =
                            autoWiredService.deriveFieldLineageCatalogEntries();
                    assertEquals(18, derivedLineage.size(),
                            "P10.13: deriveFieldLineageCatalogEntries must cover all 8 ResponseDTO + 8 CreateDTO + 2 UpdateDTO properties");
                    assertTrue(derivedLineage.stream().allMatch(org.praxisplatform.authz.catalog.FieldLineageCatalogEntry::explicitGovernanceDeclared),
                            "P10.13: All CreateDTO and UpdateDTO properties must inherit explicitGovernanceDeclared=true from ResponseDTO");

                    List<org.praxisplatform.authz.catalog.FieldLineageCatalogEntry> cidEntries = derivedLineage.stream()
                            .filter(e -> "ergon.afastamentos.cid_codigo".equals(e.attributeId()))
                            .toList();
                    assertEquals(3, cidEntries.size());
                    for (org.praxisplatform.authz.catalog.FieldLineageCatalogEntry cidEntry : cidEntries) {
                        assertEquals("SENSITIVE_PERSONAL", cidEntry.sensitivityClassification(),
                                "P10.13: cidCodigo on " + cidEntry.operationRole() + " must inherit SENSITIVE_PERSONAL");
                        assertEquals("DENIED", cidEntry.aiUsageMode(),
                                "P10.13: cidCodigo on " + cidEntry.operationRole() + " must inherit DENIED aiUsageMode");
                        assertFalse(cidEntry.exportable(),
                                "P10.13: cidCodigo on " + cidEntry.operationRole() + " must inherit exportable=false");
                        assertEquals(Set.of(FieldUseCategory.VALUE), cidEntry.allowedUseCategories(),
                                "P10.13: cidCodigo on " + cidEntry.operationRole() + " must restrict allowedUseCategories to VALUE");
                    }

                    // 23b. introspectWriteDto inherits aiContextDeniedAttributeIds, nonExportableFieldNames, and baselineFieldUseDirectives
                    MetadataDtoGovernanceIntrospector introspectorBean = ctx.getBean(MetadataDtoGovernanceIntrospector.class);
                    IntrospectedDtoGovernanceContract inheritedCreateContract = introspectorBean.introspectWriteDto(
                            AfastamentoAnnotatedCreateDTO.class,
                            AfastamentoAnnotatedResponseDTO.class,
                            blueprint.resourceKey()
                    );
                    assertTrue(inheritedCreateContract.aiContextDeniedAttributeIds().contains("ergon.afastamentos.cid_codigo"),
                            "P10.13: introspectWriteDto must inherit aiContextDeniedAttributeIds from ResponseDTO");
                    assertTrue(inheritedCreateContract.nonExportableFieldNames().contains("ergon.afastamentos.cedente_orgao_id"),
                            "P10.13: introspectWriteDto must inherit nonExportableFieldNames from ResponseDTO");
                    assertFalse(inheritedCreateContract.baselineFieldUseDirectives().isEmpty(),
                            "P10.13: introspectWriteDto must inherit baselineFieldUseDirectives from ResponseDTO");

                    // 23c. synchronizeCatalogAndRegistryIfSupported enriches RuntimeDecisionPointRegistry and SemanticDecisionPointCatalogService
                    MethodBindingAdmissionRecord emptyLineageRecord = new MethodBindingAdmissionRecord(
                            blueprint.serviceKey(),
                            blueprint.decisionPoint(),
                            blueprint.enforcementBinding(),
                            Set.of(org.praxisplatform.authz.catalog.AdmittedInvocationChannel.REST_ENDPOINT),
                            true,
                            List.of()
                    );
                    org.praxisplatform.authz.seams.RuntimeDecisionPointRegistry syncRegistry =
                            new org.praxisplatform.authz.seams.RuntimeDecisionPointRegistry(
                                    List.of(emptyLineageRecord),
                                    blueprint.coordinates()
                            );
                    org.praxisplatform.authz.catalog.SemanticDecisionPointCatalogService syncCatalog =
                            new org.praxisplatform.authz.catalog.SemanticDecisionPointCatalogService(
                                    new org.praxisplatform.authz.autoconfigure.PraxisAuthzProperties(),
                                    List.of(emptyLineageRecord)
                            );
                    autoWiredService.synchronizeCatalogAndRegistryIfSupported(syncRegistry, syncCatalog);

                    org.praxisplatform.authz.seams.RuntimeDecisionPointRegistry.RegisteredDecisionPointContext enrichedRegCtx =
                            syncRegistry.requireRegisteredPoint(blueprint.decisionPoint().identity().pointKey());
                    assertNotNull(enrichedRegCtx.dualScopeSpec(),
                            "P10.13: synchronizeCatalogAndRegistryIfSupported must populate DualScopeDelegationSpec in RuntimeDecisionPointRegistry");
                    assertTrue(enrichedRegCtx.mandatoryScopeAnchorAttributes().contains("ergon.afastamentos.lotacao_setor_id"),
                            "P10.13: synchronizeCatalogAndRegistryIfSupported must populate mandatoryScopeAnchorAttributes in RuntimeDecisionPointRegistry");
                    assertEquals(18, enrichedRegCtx.admissionRecord().fieldLineageEntries().size(),
                            "P10.13: synchronizeCatalogAndRegistryIfSupported must enrich admissionRecord fieldLineageEntries in RuntimeDecisionPointRegistry");

                    org.praxisplatform.authz.catalog.PapCatalogViewResponse papView = syncCatalog.queryCatalogForPap(
                            new org.praxisplatform.authz.catalog.PapCatalogQueryRequest(
                                    "admin-pap-1",
                                    Set.of("praxis:authz:pap:catalog:read"),
                                    Set.of(blueprint.serviceKey()),
                                    blueprint.serviceKey()
                            )
                    );
                    assertTrue(papView.rejectedPointDiagnostics().isEmpty(),
                            "P10.13: Enriched PAP catalog record must pass all P41..P64 catalog validations with zero diagnostics");
                    assertEquals(1, papView.admittedDecisionPoints().size());
                    assertEquals(18, papView.fieldLineageByPointKey()
                            .get(blueprint.decisionPoint().identity().pointKey()).size());

                    // 23d. AUTHZ-HOST-009 detects missing explicit @DomainGovernance on unannotated DTO and contradictory governance across DTO roles
                    AuthzHostReadinessReviewer.ReadinessReport unannotatedDtoReport = readinessReviewer.reviewGovernanceSpec(
                            governanceSpec,
                            P102AfastamentoJpaEntity.class,
                            DesignarSubstitutoCommandDTO.class,
                            null,
                            null
                    );
                    assertTrue(
                            unannotatedDtoReport.issues().stream()
                                    .anyMatch(i -> "AUTHZ-HOST-009-MISSING-EXPLICIT-GOVERNANCE".equals(i.ruleCode())),
                            "P10.13: AUTHZ-HOST-009 must detect DTO properties lacking explicit @DomainGovernance"
                    );

                    AuthzHostReadinessReviewer.ReadinessReport contradictoryDtoReport = readinessReviewer.reviewGovernanceSpec(
                            governanceSpec,
                            P102AfastamentoJpaEntity.class,
                            AfastamentoAnnotatedResponseDTO.class,
                            AfastamentoAnnotatedCreateDTO.class,
                            ContradictoryGovernanceUpdateDTO.class
                    );
                    assertTrue(
                            contradictoryDtoReport.issues().stream()
                                    .anyMatch(i -> "AUTHZ-HOST-009-CONTRADICTORY-LINEAGE-GOVERNANCE".equals(i.ruleCode())),
                            "P10.13: AUTHZ-HOST-009 must detect contradictory @DomainGovernance between ResponseDTO and UpdateDTO for the same attributeId"
                    );

                    // 24. Fase P10.14 — Self-Contained AuthzResourceGovernanceSpec, AuthzHostPolicyBootstrapBuilder, and Startup Readiness Gate
                    // 24a. Self-contained AuthzResourceGovernanceSpec derives FactContract, QueryableResourceProjection, DecisionPointDescriptor, and factContractDigest automatically
                    org.praxisplatform.authz.host.metadata.AuthzResourceGovernanceSpec<P102AfastamentoJpaEntity> selfContainedSpec =
                            org.praxisplatform.authz.host.metadata.AuthzResourceGovernanceSpec
                                    .<P102AfastamentoJpaEntity>builder(blueprint.resourceKey())
                                    .serviceKey(blueprint.serviceKey())
                                    .scalarFieldBinding(
                                            "resource.lotacaoSetorId",
                                            "ergon.afastamentos.lotacao_setor_id",
                                            "lotacaoSetorId"
                                    )
                                    .resourceSensitiveFact(
                                            "resource.cidCodigo",
                                            "ergon.afastamentos.cid_codigo",
                                            org.praxisplatform.authz.contracts.context.FactValueType.STRING,
                                            "HEALTH_DATA",
                                            "OFFICIAL_HEALTH_EXPERTISE"
                                    )
                                    .dualScopeDelegationSpec(blueprint.dualScopeSpec())
                                    .stateField("statusAfastamento")
                                    .cedenteCustody("cedenteOrgaoId", "subject.cedenteOrgaoIds")
                                    .cessionarioCustody("cessionarioOrgaoId", "subject.cessionarioOrgaoIds")
                                    .operationModifiedAttributes(Map.of(
                                            "homologar-afastamento", Set.of("ergon.afastamentos.status_afastamento"),
                                            "designar-substituto", Set.of("ergon.afastamentos.substituto_servidor_id"),
                                            "alterar-cid-medico", Set.of("ergon.afastamentos.cid_codigo")
                                    ))
                                    .mandatoryScopeAnchorAttributeIds(Set.of(
                                            "ergon.afastamentos.id",
                                            "ergon.afastamentos.tenant_id",
                                            "ergon.afastamentos.cedente_orgao_id",
                                            "ergon.afastamentos.cessionario_orgao_id",
                                            "ergon.afastamentos.lotacao_setor_id"
                                    ))
                                    .tenantField("tenantId")
                                    .build();

                    assertNotNull(selfContainedSpec.factContract(),
                            "P10.14-A: Self-contained AuthzResourceGovernanceSpec must derive FactContract automatically");
                    assertNotNull(selfContainedSpec.queryProjection(),
                            "P10.14-A: Self-contained AuthzResourceGovernanceSpec must derive QueryableResourceProjection automatically");
                    assertNotNull(selfContainedSpec.decisionPoint(),
                            "P10.14-A: Self-contained AuthzResourceGovernanceSpec must derive DecisionPointDescriptor automatically");
                    assertEquals(
                            selfContainedSpec.factContract().factContractDigest(),
                            selfContainedSpec.factContractDigest(),
                            "P10.14-A: Derived factContractDigest must match FactContract.factContractDigest()"
                    );
                    assertEquals(
                            blueprint.decisionPoint().identity().pointKey(),
                            selfContainedSpec.decisionPoint().identity().pointKey(),
                            "P10.14-A: Default derived decision point key must match canonical resourceOperation(serviceKey, resourceKey, 'filter')"
                    );
                    assertTrue(
                            selfContainedSpec.factContract().descriptorsByPath().containsKey("subject.cedenteOrgaoIds")
                                    && selfContainedSpec.factContract().descriptorsByPath().containsKey("subject.cessionarioOrgaoIds")
                                    && selfContainedSpec.factContract().descriptorsByPath().containsKey("resource.orgCedenteId")
                                    && selfContainedSpec.factContract().descriptorsByPath().containsKey("resource.orgCessionariaId"),
                            "P10.14-R01: Auto-derived FactContract must include cedente/cessionário custody subject facts and dual-scope resource anchor facts"
                    );
                    Map<String, Object> extractedDualScopeFacts = selfContainedSpec.extractEntityTargetFacts(
                            new P102AfastamentoJpaEntity(701L, "tenant-gov-br", 10L, 20L, 100L, "DEFERIDO", 9101L, "CID-A00")
                    );
                    assertEquals(10L, extractedDualScopeFacts.get("resource.orgCedenteId"),
                            "P10.14-R01: extractEntityTargetFacts must automatically populate dualScopeDelegationSpec.cedenteFactPath()");
                    assertEquals(20L, extractedDualScopeFacts.get("resource.orgCessionariaId"),
                            "P10.14-R01: extractEntityTargetFacts must automatically populate dualScopeDelegationSpec.cessionarioFactPath()");

                    // 24b. AuthzHostPolicyBootstrapBuilder compiles OPA bundle, coordinates, and 18 introspected FieldLineageCatalogEntry items
                    org.praxisplatform.authz.host.metadata.AuthzHostPolicyBootstrapBuilder.AuthzHostPolicyBootstrapBundle bootstrapBundle =
                            org.praxisplatform.authz.host.metadata.AuthzHostPolicyBootstrapBuilder
                                    .forService(blueprint.serviceKey())
                                    .addResourceSpec(
                                            selfContainedSpec,
                                            AfastamentoAnnotatedResponseDTO.class,
                                            AfastamentoAnnotatedCreateDTO.class,
                                            AfastamentoAnnotatedUpdateDTO.class
                                    )
                                    .addOrganizationalScopePolicy(
                                            selfContainedSpec,
                                            "rule-allow-lotacao-bootstrap",
                                            "resource.lotacaoSetorId",
                                            "subject.organizationUnitIds",
                                            Map.of("ergon.afastamentos.cid_codigo", "***CID-RESTRITO***")
                                    )
                                    .build(introspectorBean);

                    assertEquals(1, bootstrapBundle.admissionRecords().size(),
                            "P10.14-B: AuthzHostPolicyBootstrapBuilder must produce 1 MethodBindingAdmissionRecord for the registered resource");
                    assertEquals(18, bootstrapBundle.admissionRecords().get(0).fieldLineageEntries().size(),
                            "P10.14-B: AuthzHostPolicyBootstrapBuilder must introspect all 18 FieldLineageCatalogEntry items from DTO annotations");
                    assertNotNull(bootstrapBundle.localOpaTransport());
                    assertNotNull(bootstrapBundle.coordinates());

                    // P10.14-R03: Single @Bean AuthzHostPolicyBootstrapBundle auto-wires HostRuntimePolicyCoordinates, OpaClientTransport,
                    // RuntimeDecisionPointRegistry, SemanticDecisionPointCatalogService, and HostPolicyCompatibilityStartupVerifier
                    new ApplicationContextRunner()
                            .withConfiguration(AutoConfigurations.of(PraxisAuthzAutoConfiguration.class))
                            .withBean(
                                    org.praxisplatform.authz.host.metadata.AuthzHostPolicyBootstrapBuilder.AuthzHostPolicyBootstrapBundle.class,
                                    () -> bootstrapBundle
                            )
                            .run(bundleCtx -> {
                                assertEquals(null, bundleCtx.getStartupFailure(),
                                        "P10.14-R03: Single AuthzHostPolicyBootstrapBundle bean must satisfy all PraxisAuthzAutoConfiguration startup checks");
                                org.praxisplatform.authz.compatibility.HostPolicyCompatibilityStartupVerifier verifier =
                                        bundleCtx.getBean(org.praxisplatform.authz.compatibility.HostPolicyCompatibilityStartupVerifier.class);
                                assertTrue(verifier.currentStatus().ready(),
                                        "P10.14-R03: HostPolicyCompatibilityStartupVerifier must report ready=true from single AuthzHostPolicyBootstrapBundle bean");
                                org.praxisplatform.authz.seams.RuntimeDecisionPointRegistry autoRegistry =
                                        bundleCtx.getBean(org.praxisplatform.authz.seams.RuntimeDecisionPointRegistry.class);
                                assertEquals(18, autoRegistry.requireRegisteredPoint(selfContainedSpec.decisionPoint().identity().pointKey())
                                        .admissionRecord().fieldLineageEntries().size());
                            });

                    // P10.14-R04: synchronizeCatalogAndRegistryIfSupported harmonizes pre-populated blueprint admissionRecords (HEALTH_SENSITIVE / concept:health:icd10)
                    org.praxisplatform.authz.catalog.SemanticDecisionPointCatalogService blueprintCatalog =
                            new org.praxisplatform.authz.catalog.SemanticDecisionPointCatalogService(
                                    new org.praxisplatform.authz.autoconfigure.PraxisAuthzProperties(),
                                    blueprint.admissionRecords()
                            );
                    autoWiredService.synchronizeCatalogAndRegistryIfSupported(null, blueprintCatalog);
                    org.praxisplatform.authz.catalog.PapCatalogViewResponse harmonizedPapView =
                            blueprintCatalog.queryCatalogForPap(new org.praxisplatform.authz.catalog.PapCatalogQueryRequest(
                                    "admin-pap-1",
                                    Set.of("praxis:authz:pap:catalog:read"),
                                    Set.of(blueprint.serviceKey()),
                                    blueprint.serviceKey()
                            ));
                    assertTrue(harmonizedPapView.rejectedPointDiagnostics().isEmpty(),
                            "P10.14-R04: Harmonized pre-populated blueprint admissionRecords must pass PAP catalog validation with zero diagnostics");

                    // P10.14-R05: AUTHZ-HOST-009-DERIVED-GOVERNANCE-WIDENING detects derived field widening exportability/AI usage relative to upstream attributeId
                    AuthzHostReadinessReviewer.ReadinessReport derivedWideningReport = readinessReviewer.reviewGovernanceSpec(
                            governanceSpec,
                            P102AfastamentoJpaEntity.class,
                            AfastamentoAnnotatedResponseDTO.class,
                            AfastamentoAnnotatedCreateDTO.class,
                            DerivedWideningUpdateDTO.class
                    );
                    assertTrue(
                            derivedWideningReport.issues().stream()
                                    .anyMatch(i -> "AUTHZ-HOST-009-DERIVED-GOVERNANCE-WIDENING".equals(i.ruleCode())),
                            "P10.14-R05: AUTHZ-HOST-009 must detect derived attribute widening exportability/AI usage relative to upstream restricted attribute"
                    );

                    AuthzHostReadinessReviewer.ReadinessReport selfContainedReport = readinessReviewer.reviewGovernanceSpec(
                            selfContainedSpec,
                            P102AfastamentoJpaEntity.class,
                            AfastamentoAnnotatedResponseDTO.class,
                            AfastamentoAnnotatedCreateDTO.class,
                            AfastamentoAnnotatedUpdateDTO.class
                    );
                    selfContainedReport.assertZeroIssues();

                    // 24c. Startup readiness gate (praxis.authz.readiness-gate.verify-on-startup=true & fail-on-warning=true)
                    jakarta.persistence.EntityManagerFactory rawEmf = Objects.requireNonNull(emfBean.getObject());
                    jakarta.persistence.EntityManagerFactory nonClosingEmfProxy =
                            (jakarta.persistence.EntityManagerFactory) java.lang.reflect.Proxy.newProxyInstance(
                                    jakarta.persistence.EntityManagerFactory.class.getClassLoader(),
                                    new Class<?>[]{jakarta.persistence.EntityManagerFactory.class},
                                    (proxy, method, args) -> "close".equals(method.getName()) ? null : method.invoke(rawEmf, args)
                            );
                    // 1) Passes when only SpecDrivenAfastamentoGovernedService is registered
                    new ApplicationContextRunner()
                            .withConfiguration(AutoConfigurations.of(PraxisAuthzHostBridgeAutoConfiguration.class))
                            .withPropertyValues(
                                    "praxis.authz.readiness-gate.verify-on-startup=true",
                                    "praxis.authz.readiness-gate.fail-on-warning=true"
                            )
                            .withBean(jakarta.persistence.EntityManagerFactory.class, () -> nonClosingEmfProxy)
                            .withBean(DetachedDtoMaskingProcessor.class, DetachedDtoMaskingProcessor::new)
                            .withBean(MetadataResourceAuthorizationSeam.class, () -> seam)
                            .withBean(CollectionExportExecutor.class, () -> new DefaultCollectionExportExecutor(List.of(new CsvCollectionExportEngine())))
                            .withBean("authzCallerContextProvider", ThreadLocalAuthzCallerContextProvider.class, () -> callerContextProvider)
                            .withBean(SpecDrivenAfastamentoGovernedService.class, () -> autoWiredService)
                            .run(cleanStartupCtx -> {
                                assertEquals(null, cleanStartupCtx.getStartupFailure(),
                                        "P10.14-C: Startup readiness gate must succeed when all governed services have zero issues");
                            });

                    // 2) Fails closed on startup when fail-on-warning=true and a manual-override service (AUTHZ-HOST-001 warning) is registered
                    new ApplicationContextRunner()
                            .withConfiguration(AutoConfigurations.of(PraxisAuthzHostBridgeAutoConfiguration.class))
                            .withPropertyValues(
                                    "praxis.authz.readiness-gate.verify-on-startup=true",
                                    "praxis.authz.readiness-gate.fail-on-warning=true"
                            )
                            .withBean(jakarta.persistence.EntityManagerFactory.class, () -> nonClosingEmfProxy)
                            .withBean(DetachedDtoMaskingProcessor.class, DetachedDtoMaskingProcessor::new)
                            .withBean(MetadataResourceAuthorizationSeam.class, () -> seam)
                            .withBean(CollectionExportExecutor.class, () -> new DefaultCollectionExportExecutor(List.of(new CsvCollectionExportEngine())))
                            .withBean("authzCallerContextProvider", ThreadLocalAuthzCallerContextProvider.class, () -> callerContextProvider)
                            .withBean(ConciseAfastamentoRadarReadOnlyService.class, () -> radarReadOnlyService)
                            .run(failedContext -> {
                                assertNotNull(failedContext.getStartupFailure(),
                                        "P10.14-C: Startup readiness gate must fail closed when verify-on-startup=true and fail-on-warning=true with AUTHZ-HOST-001 warning");
                                String msg = failedContext.getStartupFailure().getMessage()
                                        + (failedContext.getStartupFailure().getCause() != null
                                        ? " " + failedContext.getStartupFailure().getCause().getMessage()
                                        : "");
                                assertTrue(
                                        msg.contains("AUTHZ-HOST-001-MANUAL-OVERRIDE-MODE"),
                                        "P10.14-C: Startup failure message must report AUTHZ-HOST-001-MANUAL-OVERRIDE-MODE"
                                );
                            });

                    // =========================================================================
                    // 25. Fase P10.15 — Automatic FilterDTO/Sort FIELD_USE Extraction, Default
                    //     JDBC Outbox Auto-Wiring, Service/Action/Surface Bootstrap Builder,
                    //     Early Filter Anti-Spoofing & Readiness Gate 10 (P10.15-A .. P10.15-E)
                    // =========================================================================

                    // 25a. P10.15-A: Automatic FILTER & SORT FIELD_USE extraction from FilterDTO, Pageable, and CollectionExportRequest
                    autoCallerProvider.runWithContext(
                            AuthzCallerContext.of(
                                    "tenant-gov-br",
                                    Map.of(
                                            "subject.principalId", "usr-gestor-101",
                                            "subject.organizationUnitIds", List.of(100L)
                                    )
                            ),
                            () -> {
                                // 1) Direct FilterDTO property targeting restricted cidCodigo fails closed without manual withRequestedQueryFieldUses
                                AfastamentoFilterDTO cidFilter = new AfastamentoFilterDTO();
                                cidFilter.cidCodigo = "F32.1";
                                FieldUseViolationException filterCidEx = assertThrows(
                                        FieldUseViolationException.class,
                                        () -> txTemplate.execute(status -> autoWiredService.filter(cidFilter, PageRequest.of(0, 10))),
                                        "P10.15-A: Filtering by @Filterable cidCodigo must automatically extract FieldUseCategory.FILTER and fail closed"
                                );
                                assertEquals(FieldUseCategory.FILTER, filterCidEx.getCategory());
                                assertTrue(filterCidEx.getForbiddenAttributeIds().contains("ergon.afastamentos.cid_codigo"));

                                // 2) Omnibox @Filterable(relations = {"statusAfastamento", "cidCodigo"}) fails closed when populated
                                AfastamentoFilterDTO omniboxCidFilter = new AfastamentoFilterDTO();
                                omniboxCidFilter.buscaAmplaComCid = "F32";
                                FieldUseViolationException omniboxEx = assertThrows(
                                        FieldUseViolationException.class,
                                        () -> txTemplate.execute(status -> autoWiredService.filter(omniboxCidFilter, PageRequest.of(0, 10))),
                                        "P10.15-A: Omnibox @Filterable(relations = {..., cidCodigo}) must fail closed against oracle probing"
                                );
                                assertEquals(FieldUseCategory.FILTER, omniboxEx.getCategory());
                                assertTrue(omniboxEx.getForbiddenAttributeIds().contains("ergon.afastamentos.cid_codigo"));

                                // 3) Pageable Sort.by("cidCodigo") fails closed without manual withRequestedQueryFieldUses
                                FieldUseViolationException sortCidEx = assertThrows(
                                        FieldUseViolationException.class,
                                        () -> txTemplate.execute(status -> autoWiredService.filter(
                                                new AfastamentoFilterDTO(),
                                                PageRequest.of(0, 10, org.springframework.data.domain.Sort.by("cidCodigo"))
                                        )),
                                        "P10.15-A: Sorting by cidCodigo via Pageable must automatically extract FieldUseCategory.SORT and fail closed"
                                );
                                assertEquals(FieldUseCategory.SORT, sortCidEx.getCategory());
                                assertTrue(sortCidEx.getForbiddenAttributeIds().contains("ergon.afastamentos.cid_codigo"));

                                // 4) CollectionExportRequest with sort=List.of("cidCodigo,asc") fails closed
                                CollectionExportRequest<AfastamentoFilterDTO> exportWithCidSort = new CollectionExportRequest<>(
                                        "table", "tbl-afastamentos", "/api/human-resources/afastamentos",
                                        CollectionExportFormat.CSV, CollectionExportScope.ALL,
                                        null, null, new AfastamentoFilterDTO(), List.of("cidCodigo,asc"), null, null,
                                        true, false, 100, "afastamentos.csv", null, null, Map.of()
                                );
                                FieldUseViolationException exportSortEx = assertThrows(
                                        FieldUseViolationException.class,
                                        () -> txTemplate.execute(status -> autoWiredService.exportCollection(exportWithCidSort)),
                                        "P10.15-A: CollectionExportRequest sorting by cidCodigo must fail closed"
                                );
                                assertEquals(FieldUseCategory.SORT, exportSortEx.getCategory());
                                assertTrue(exportSortEx.getForbiddenAttributeIds().contains("ergon.afastamentos.cid_codigo"));

                                // 5) Allowed filter + sort on statusAfastamento succeeds and masks cidCodigo
                                AfastamentoFilterDTO allowedFilter = new AfastamentoFilterDTO();
                                allowedFilter.statusAfastamento = "HOMOLOGADO";
                                Page<AfastamentoAnnotatedResponseDTO> allowedPage = txTemplate.execute(status ->
                                        autoWiredService.filter(
                                                allowedFilter,
                                                PageRequest.of(0, 10, org.springframework.data.domain.Sort.by("statusAfastamento"))
                                        )
                                );
                                assertNotNull(allowedPage);
                                assertEquals(1, allowedPage.getTotalElements());
                                assertEquals("***CID-RESTRITO***", allowedPage.getContent().getFirst().cidCodigo());
                            }
                    );

                    // 25b. P10.15-B: Default-enabled JdbcTransactionalAuditOutbox & configurable JdbcAuditOutboxRelayExecutor
                    new ApplicationContextRunner()
                            .withConfiguration(AutoConfigurations.of(PraxisAuthzAutoConfiguration.class))
                            .withPropertyValues(
                                    "praxis.authz.outbox.relay-batch-size=25",
                                    "praxis.authz.outbox.max-delivery-attempts=7"
                            )
                            .withBean(org.springframework.jdbc.core.JdbcOperations.class, () -> jdbcTemplate)
                            .withBean(org.praxisplatform.authz.outbox.AuditOutboxDeliverySinkPort.class, () -> record -> true)
                            .withBean(
                                    org.praxisplatform.authz.host.metadata.AuthzHostPolicyBootstrapBuilder.AuthzHostPolicyBootstrapBundle.class,
                                    () -> bootstrapBundle
                            )
                            .run(outboxCtx -> {
                                assertEquals(null, outboxCtx.getStartupFailure());
                                org.praxisplatform.authz.enforcement.obligation.TransactionalAuditOutboxPort outboxBean =
                                        outboxCtx.getBean(org.praxisplatform.authz.enforcement.obligation.TransactionalAuditOutboxPort.class);
                                assertTrue(
                                        outboxBean instanceof JdbcTransactionalAuditOutbox,
                                        "P10.15-B: TransactionalAuditOutboxPort must default to JdbcTransactionalAuditOutbox when JdbcOperations is present"
                                );
                                org.praxisplatform.authz.outbox.JdbcAuditOutboxRelayExecutor relayExecutor =
                                        outboxCtx.getBean(org.praxisplatform.authz.outbox.JdbcAuditOutboxRelayExecutor.class);
                                assertEquals(25, relayExecutor.getDefaultBatchSize());
                                assertEquals(7, relayExecutor.getDefaultMaxAttempts());
                                org.praxisplatform.authz.outbox.JdbcAuditOutboxRelayExecutor.RelayBatchResult summary =
                                        relayExecutor.drainPendingBatch(Instant.now());
                                assertNotNull(summary);
                            });

                    // 25c. P10.15-C & P10.15-E: AuthzHostPolicyBootstrapBuilder .addGovernedService, .addActionPolicy, .addSurfacePolicy
                    //      and AuthzHostReadinessReviewer Gate 10 (AUTHZ-HOST-010)
                    org.praxisplatform.authz.contracts.decisionpoint.DecisionPointDescriptor primaryDp = selfContainedSpec.decisionPoint();
                    org.praxisplatform.authz.contracts.decisionpoint.DecisionPointDescriptor homologarActionDp =
                            new org.praxisplatform.authz.contracts.decisionpoint.DecisionPointDescriptor(
                                    org.praxisplatform.authz.contracts.decisionpoint.DecisionPointDescriptor.SCHEMA_VERSION_V1,
                                    org.praxisplatform.authz.contracts.decisionpoint.DecisionPointIdentity.workflowAction(
                                            blueprint.serviceKey(),
                                            blueprint.resourceKey(),
                                            "homologar-afastamento"
                                    ),
                                    org.praxisplatform.authz.contracts.decisionpoint.DecisionKind.AUTHORIZATION,
                                    org.praxisplatform.authz.contracts.decisionpoint.DecisionResultContractKind.GATE,
                                    null,
                                    "EXECUTE_ACTION",
                                    "POST",
                                    "/api/human-resources/afastamentos/{id}/actions/homologar-afastamento",
                                    Set.of(org.praxisplatform.authz.contracts.decisionpoint.EvaluationMode.TARGET),
                                    Set.of(
                                            org.praxisplatform.authz.contracts.decisionpoint.EnforcementCapability.ACCESS,
                                            org.praxisplatform.authz.contracts.decisionpoint.EnforcementCapability.FIELD_WRITE
                                    ),
                                    Set.of(),
                                    primaryDp.obligationSupport(),
                                    primaryDp.factContractRef(),
                                    null,
                                    null,
                                    null,
                                    primaryDp.legalPurpose(),
                                    primaryDp.legalBasisRef(),
                                    primaryDp.provenance(),
                                    org.praxisplatform.authz.contracts.digest.CanonicalDigestCalculator.computeDigest(
                                            org.praxisplatform.authz.contracts.digest.DigestDomainKind.DEFINITION_FINGERPRINT,
                                            blueprint.serviceKey() + "|" + blueprint.resourceKey() + "|action:homologar-afastamento|v1"
                                    )
                            );

                    org.praxisplatform.authz.contracts.decisionpoint.DecisionPointDescriptor fichaSurfaceDp =
                            new org.praxisplatform.authz.contracts.decisionpoint.DecisionPointDescriptor(
                                    org.praxisplatform.authz.contracts.decisionpoint.DecisionPointDescriptor.SCHEMA_VERSION_V1,
                                    org.praxisplatform.authz.contracts.decisionpoint.DecisionPointIdentity.resourceOperation(
                                            blueprint.serviceKey(),
                                            blueprint.resourceKey(),
                                            "surface-ficha-medica-360"
                                    ),
                                    org.praxisplatform.authz.contracts.decisionpoint.DecisionKind.AUTHORIZATION,
                                    org.praxisplatform.authz.contracts.decisionpoint.DecisionResultContractKind.GATE,
                                    null,
                                    "READ_PROJECTION",
                                    "GET",
                                    "/api/human-resources/afastamentos/{id}/surfaces/ficha-medica-360",
                                    Set.of(org.praxisplatform.authz.contracts.decisionpoint.EvaluationMode.TARGET),
                                    Set.of(
                                            org.praxisplatform.authz.contracts.decisionpoint.EnforcementCapability.ACCESS,
                                            org.praxisplatform.authz.contracts.decisionpoint.EnforcementCapability.MASK
                                    ),
                                    Set.of(),
                                    primaryDp.obligationSupport(),
                                    primaryDp.factContractRef(),
                                    null,
                                    null,
                                    null,
                                    primaryDp.legalPurpose(),
                                    primaryDp.legalBasisRef(),
                                    primaryDp.provenance(),
                                    org.praxisplatform.authz.contracts.digest.CanonicalDigestCalculator.computeDigest(
                                            org.praxisplatform.authz.contracts.digest.DigestDomainKind.DEFINITION_FINGERPRINT,
                                            blueprint.serviceKey() + "|" + blueprint.resourceKey() + "|surface:ficha-medica-360|v1"
                                    )
                            );

                    AuthzResourceGovernanceSpec<P102AfastamentoJpaEntity> fullActionSurfaceSpec =
                            AuthzResourceGovernanceSpec.<P102AfastamentoJpaEntity>builder(blueprint.resourceKey())
                                    .serviceKey(blueprint.serviceKey())
                                    .decisionPoint(selfContainedSpec.decisionPoint())
                                    .factContract(selfContainedSpec.factContract())
                                    .scalarFieldBinding(
                                            "resource.lotacaoSetorId",
                                            "ergon.afastamentos.lotacao_setor_id",
                                            "lotacaoSetorId"
                                    )
                                    .resourceSensitiveFact(
                                            "resource.cidCodigo",
                                            "ergon.afastamentos.cid_codigo",
                                            org.praxisplatform.authz.contracts.context.FactValueType.STRING,
                                            "HEALTH_DATA",
                                            "OFFICIAL_HEALTH_EXPERTISE"
                                    )
                                    .dualScopeDelegationSpec(blueprint.dualScopeSpec())
                                    .stateField("statusAfastamento")
                                    .cedenteCustody("cedenteOrgaoId", "subject.cedenteOrgaoIds")
                                    .cessionarioCustody("cessionarioOrgaoId", "subject.cessionarioOrgaoIds")
                                    .mandatoryScopeAnchorAttributeIds(Set.of(
                                            "ergon.afastamentos.id",
                                            "ergon.afastamentos.tenant_id",
                                            "ergon.afastamentos.cedente_orgao_id",
                                            "ergon.afastamentos.cessionario_orgao_id",
                                            "ergon.afastamentos.lotacao_setor_id"
                                    ))
                                    .actionDecisionPoint("homologar-afastamento", homologarActionDp)
                                    .surfaceDecisionPoint("ficha-medica-360", fichaSurfaceDp)
                                    .operationModifiedAttributes(
                                            "homologar-afastamento",
                                            Set.of("ergon.afastamentos.status_afastamento")
                                    )
                                    .tenantField("tenantId")
                                    .build();

                    SpecDrivenAfastamentoGovernedService fullGovernedService = new SpecDrivenAfastamentoGovernedService(
                            repository,
                            serviceSupport,
                            fullActionSurfaceSpec,
                            callerContextProvider,
                            sharedEm
                    );

                    org.praxisplatform.authz.host.metadata.AuthzHostPolicyBootstrapBuilder.AuthzHostPolicyBootstrapBundle fullBundle =
                            org.praxisplatform.authz.host.metadata.AuthzHostPolicyBootstrapBuilder
                                    .forService(blueprint.serviceKey())
                                    .addGovernedService(fullGovernedService)
                                    .addOrganizationalScopePolicy(
                                            fullActionSurfaceSpec,
                                            "rule-primary-org-scope",
                                            "resource.lotacaoSetorId",
                                            "subject.organizationUnitIds",
                                            Map.of("ergon.afastamentos.cid_codigo", "***CID-RESTRITO***")
                                    )
                                    .addActionPolicy(
                                            fullActionSurfaceSpec,
                                            "homologar-afastamento",
                                            "rule-action-homologar",
                                            Map.of("in", List.of(
                                                    Map.of("var", "resource.lotacaoSetorId"),
                                                    Map.of("var", "subject.organizationUnitIds")
                                            )),
                                            Set.of("ergon.afastamentos.status_afastamento")
                                    )
                                    .addSurfacePolicy(
                                            fullActionSurfaceSpec,
                                            "ficha-medica-360",
                                            "rule-surface-ficha-360",
                                            Map.of("!=", List.of(Map.of("var", "subject.principalId"), "")),
                                            Map.of("ergon.afastamentos.cid_codigo", "***CID-RESTRITO-360***")
                                    )
                                    .build(introspectorBean);

                    assertEquals(3, fullBundle.policies().size(),
                            "P10.15-C: Bootstrap bundle must compile 3 policies (primary, action, surface)");
                    assertEquals(3, fullBundle.admissionRecords().size(),
                            "P10.15-C: Bootstrap bundle must emit 3 MethodBindingAdmissionRecords (primary, action, surface)");
                    assertEquals(3, fullBundle.coordinates().bindingsByPointKey().size(),
                            "P10.15-C: HostRuntimePolicyCoordinates must bind all 3 decision points");

                    // P10.15-E: Gate 10 passes with zero issues when all 3 decision points are in coordinates and operationModifiedAttributes is declared
                    AuthzHostReadinessReviewer reviewerWithFullCoordinates = new AuthzHostReadinessReviewer(
                            introspectorBean,
                            null,
                            fullBundle.coordinates()
                    );
                    reviewerWithFullCoordinates.reviewMutableService(fullGovernedService).assertZeroIssues();

                    // P10.15-E: Gate 10 detects AUTHZ-HOST-010-MISSING-COORDINATES-BINDING when coordinates lack custom action/surface bindings
                    AuthzHostReadinessReviewer reviewerWithPartialCoordinates = new AuthzHostReadinessReviewer(
                            introspectorBean,
                            null,
                            bootstrapBundle.coordinates()
                    );
                    AuthzHostReadinessReviewer.ReadinessReport missingCoordReport =
                            reviewerWithPartialCoordinates.reviewMutableService(fullGovernedService);
                    assertFalse(missingCoordReport.isReady());
                    assertEquals(
                            2,
                            missingCoordReport.errors().stream()
                                    .filter(i -> "AUTHZ-HOST-010-MISSING-COORDINATES-BINDING".equals(i.ruleCode()))
                                    .count(),
                            "P10.15-E: AUTHZ-HOST-010 must flag both custom action and surface decision points when missing from HostRuntimePolicyCoordinates"
                    );

                    // P10.15-E: Gate 10 detects AUTHZ-HOST-010-UNDECLARED-CUSTOM-ACTION-ATTRIBUTES when FIELD_WRITE action omits operationModifiedAttributes
                    AuthzResourceGovernanceSpec<P102AfastamentoJpaEntity> specWithoutActionAttrs =
                            AuthzResourceGovernanceSpec.<P102AfastamentoJpaEntity>builder(blueprint.resourceKey())
                                    .serviceKey(blueprint.serviceKey())
                                    .decisionPoint(selfContainedSpec.decisionPoint())
                                    .factContract(selfContainedSpec.factContract())
                                    .scalarFieldBinding(
                                            "resource.lotacaoSetorId",
                                            "ergon.afastamentos.lotacao_setor_id",
                                            "lotacaoSetorId"
                                    )
                                    .mandatoryScopeAnchorAttributeIds(Set.of(
                                            "ergon.afastamentos.id",
                                            "ergon.afastamentos.tenant_id",
                                            "ergon.afastamentos.cedente_orgao_id",
                                            "ergon.afastamentos.cessionario_orgao_id",
                                            "ergon.afastamentos.lotacao_setor_id"
                                    ))
                                    .actionDecisionPoint("homologar-afastamento", homologarActionDp)
                                    .tenantField("tenantId")
                                    .build();
                    AuthzHostReadinessReviewer.ReadinessReport undeclaredActionAttrReport =
                            readinessReviewer.reviewGovernanceSpec(
                                    specWithoutActionAttrs,
                                    P102AfastamentoJpaEntity.class,
                                    AfastamentoAnnotatedResponseDTO.class,
                                    AfastamentoAnnotatedCreateDTO.class,
                                    AfastamentoAnnotatedUpdateDTO.class
                            );
                    assertTrue(
                            undeclaredActionAttrReport.warnings().stream()
                                    .anyMatch(i -> "AUTHZ-HOST-010-UNDECLARED-CUSTOM-ACTION-ATTRIBUTES".equals(i.ruleCode())),
                            "P10.15-E: AUTHZ-HOST-010 must warn when a custom FIELD_WRITE action decision point omits operationModifiedAttributes"
                    );

                    // 25d. P10.15-D: AuthzCallerContextFilter rejects authority-spoofing headers at the HTTP boundary
                    //      even when resolver returns Optional.empty() (unauthenticated request)
                    org.praxisplatform.authz.host.metadata.AuthzCallerContextFilter unauthenticatedFilter =
                            new org.praxisplatform.authz.host.metadata.AuthzCallerContextFilter(
                                    req -> Optional.empty(),
                                    callerContextProvider
                            );
                    org.springframework.mock.web.MockHttpServletRequest spoofedUnauthReq =
                            new org.springframework.mock.web.MockHttpServletRequest("GET", "/api/human-resources/afastamentos/schemas");
                    spoofedUnauthReq.addHeader("X-Praxis-Authz-Roles", "SUPER_ADMIN");
                    org.springframework.mock.web.MockHttpServletResponse spoofedUnauthRes =
                            new org.springframework.mock.web.MockHttpServletResponse();
                    AtomicBoolean chainInvokedOnSpoof = new AtomicBoolean(false);
                    assertThrows(
                            org.praxisplatform.authz.enforcement.context.UntrustedHeaderSpoofingException.class,
                            () -> unauthenticatedFilter.doFilter(
                                    spoofedUnauthReq,
                                    spoofedUnauthRes,
                                    (req, res) -> chainInvokedOnSpoof.set(true)
                            ),
                            "P10.15-D: AuthzCallerContextFilter must immediately block spoofed authority headers even on unauthenticated requests"
                    );
                    assertFalse(
                            chainInvokedOnSpoof.get(),
                            "P10.15-D: FilterChain must never be invoked when an authority-spoofing header is present"
                    );

                    // 25e. P10.15-R01 .. P10.15-R04: Comprehensive Enterprise Review Regressions
                    // P10.15-R01: selectBulkIdentities (both on service and on AuthzGovernedBulkDomainResourceAdapter)
                    // blocks FilterDTO oracle probing on restricted cidCodigo before SQL
                    callerContextProvider.runWithContext(
                            AuthzCallerContext.of(
                                    "tenant-gov-br",
                                    Map.of(
                                            "subject.principalId", "usr-gestor-101",
                                            "subject.organizationUnitIds", List.of(100L)
                                    )
                            ),
                            () -> {
                                AfastamentoFilterDTO filterByCid = new AfastamentoFilterDTO();
                                filterByCid.cidCodigo = "F32.1";
                                FieldUseViolationException bulkFilterEx = assertThrows(
                                        FieldUseViolationException.class,
                                        () -> txTemplate.execute(status ->
                                                autoWiredService.selectBulkIdentities(filterByCid, null, List.of(), 100)
                                        ),
                                        "P10.15-R01: selectBulkIdentities must block FilterDTO probing on restricted cidCodigo"
                                );
                                assertEquals(
                                        org.praxisplatform.authz.contracts.decisionpoint.FieldUseCategory.FILTER,
                                        bulkFilterEx.getCategory()
                                );
                                assertTrue(bulkFilterEx.getForbiddenAttributeIds().contains("ergon.afastamentos.cid_codigo"));

                                // P10.15-R02: groupByStats (grouping by allowed statusAfastamento, filtering by restricted cidCodigo),
                                // filterOptions, and filterByCursor all block FilterDTO probing on restricted cidCodigo
                                FieldUseViolationException statsFilterEx = assertThrows(
                                        FieldUseViolationException.class,
                                        () -> txTemplate.execute(status ->
                                                autoWiredService.groupByStats(
                                                        new GroupByStatsRequest<>(
                                                                filterByCid,
                                                                "statusAfastamento",
                                                                new StatsMetricRequest(StatsMetric.COUNT, null),
                                                                10,
                                                                StatsBucketOrder.KEY_ASC
                                                        )
                                                )
                                        ),
                                        "P10.15-R02: groupByStats must block FilterDTO probing on restricted cidCodigo even when grouping by an allowed dimension"
                                );
                                assertEquals(
                                        org.praxisplatform.authz.contracts.decisionpoint.FieldUseCategory.FILTER,
                                        statsFilterEx.getCategory()
                                );

                                assertThrows(
                                        FieldUseViolationException.class,
                                        () -> txTemplate.execute(status ->
                                                autoWiredService.filterOptions(filterByCid, PageRequest.of(0, 10))
                                        ),
                                        "P10.15-R02: filterOptions must block FilterDTO probing on restricted cidCodigo"
                                );
                                assertThrows(
                                        FieldUseViolationException.class,
                                        () -> txTemplate.execute(status ->
                                                autoWiredService.filterByCursor(
                                                        filterByCid,
                                                        org.springframework.data.domain.Sort.by("id"),
                                                        null,
                                                        null,
                                                        10
                                                )
                                        ),
                                        "P10.15-R02: filterByCursor must block FilterDTO probing on restricted cidCodigo"
                                );
                            }
                    );

                    // P10.15-R03: Declarative .workflowAction(...) and .uiSurface(...) on AuthzResourceGovernanceSpec.Builder
                    // synthesize DecisionPointDescriptors and operationModifiedAttributes with zero 20-arg boilerplate
                    AuthzResourceGovernanceSpec<P102AfastamentoJpaEntity> zeroBoilerplateActionSurfaceSpec =
                            AuthzResourceGovernanceSpec.<P102AfastamentoJpaEntity>builder(blueprint.resourceKey())
                                    .serviceKey(blueprint.serviceKey())
                                    .scalarFieldBinding(
                                            "resource.lotacaoSetorId",
                                            "ergon.afastamentos.lotacao_setor_id",
                                            "lotacaoSetorId"
                                    )
                                    .resourceSensitiveFact(
                                            "resource.cidCodigo",
                                            "ergon.afastamentos.cid_codigo",
                                            org.praxisplatform.authz.contracts.context.FactValueType.STRING,
                                            "HEALTH_DATA",
                                            "OFFICIAL_HEALTH_EXPERTISE"
                                    )
                                    .dualScopeDelegationSpec(blueprint.dualScopeSpec())
                                    .stateField("statusAfastamento")
                                    .cedenteCustody("cedenteOrgaoId", "subject.cedenteOrgaoIds")
                                    .cessionarioCustody("cessionarioOrgaoId", "subject.cessionarioOrgaoIds")
                                    .mandatoryScopeAnchorAttributeIds(Set.of(
                                            "ergon.afastamentos.id",
                                            "ergon.afastamentos.tenant_id",
                                            "ergon.afastamentos.cedente_orgao_id",
                                            "ergon.afastamentos.cessionario_orgao_id",
                                            "ergon.afastamentos.lotacao_setor_id"
                                    ))
                                    .workflowAction(
                                            "homologar-afastamento",
                                            Set.of("ergon.afastamentos.status_afastamento")
                                    )
                                    .uiSurface("ficha-medica-360")
                                    .tenantField("tenantId")
                                    .build();
                    assertTrue(
                            zeroBoilerplateActionSurfaceSpec.actionDecisionPoints().containsKey("homologar-afastamento"),
                            "P10.15-R03: .workflowAction(...) must auto-synthesize action DecisionPointDescriptor"
                    );
                    assertTrue(
                            zeroBoilerplateActionSurfaceSpec.surfaceDecisionPoints().containsKey("ficha-medica-360"),
                            "P10.15-R03: .uiSurface(...) must auto-synthesize surface DecisionPointDescriptor"
                    );
                    assertEquals(
                            Set.of("ergon.afastamentos.status_afastamento"),
                            zeroBoilerplateActionSurfaceSpec.operationModifiedAttributes().get("homologar-afastamento")
                    );
                    readinessReviewer.reviewGovernanceSpec(
                            zeroBoilerplateActionSurfaceSpec,
                            P102AfastamentoJpaEntity.class,
                            AfastamentoAnnotatedResponseDTO.class,
                            AfastamentoFilterDTO.class,
                            AfastamentoAnnotatedCreateDTO.class,
                            AfastamentoAnnotatedUpdateDTO.class
                    ).assertZeroIssues();

                    // P10.15-R04: AuthzHostReadinessReviewer detects broken @Filterable relation paths on FilterDTO
                    AuthzHostReadinessReviewer.ReadinessReport brokenFilterReport =
                            readinessReviewer.reviewGovernanceSpec(
                                    zeroBoilerplateActionSurfaceSpec,
                                    P102AfastamentoJpaEntity.class,
                                    AfastamentoAnnotatedResponseDTO.class,
                                    BrokenPathAfastamentoFilterDTO.class,
                                    AfastamentoAnnotatedCreateDTO.class,
                                    AfastamentoAnnotatedUpdateDTO.class
                            );
                    assertFalse(brokenFilterReport.isReady());
                    assertTrue(
                            brokenFilterReport.errors().stream()
                                    .anyMatch(i -> "AUTHZ-HOST-006-INVALID-FILTERABLE-ENTITY-PATH".equals(i.ruleCode())),
                            "P10.15-R04: AUTHZ-HOST-006 must fail when @Filterable on FilterDTO references a non-existent JPA entity path"
                    );

                    // 26. Fase P10.16 (P10.16-A .. P10.16-C):
                    // - P10.16-A: Declarative .bulkWorkflowAction + .addBulkActionPolicy + executeGovernedBulkCommand + AUTHZ-HOST-010-BULK-ACTION-MISSING-QUERY-PROJECTION
                    // - P10.16-B: Explainable Availability Diagnostics in AvailabilityDecision.metadata()
                    // - P10.16-C: Declarative AuthzPolicySimulationHarness & MatrixRunner
                    AuthzResourceGovernanceSpec<P102AfastamentoJpaEntity> p1016Spec =
                            AuthzResourceGovernanceSpec.<P102AfastamentoJpaEntity>builder(blueprint.resourceKey())
                                    .serviceKey(blueprint.serviceKey())
                                    .scalarFieldBinding(
                                            "resource.lotacaoSetorId",
                                            "ergon.afastamentos.lotacao_setor_id",
                                            "lotacaoSetorId"
                                    )
                                    .resourceSensitiveFact(
                                            "resource.cidCodigo",
                                            "ergon.afastamentos.cid_codigo",
                                            org.praxisplatform.authz.contracts.context.FactValueType.STRING,
                                            "HEALTH_DATA",
                                            "OFFICIAL_HEALTH_EXPERTISE"
                                    )
                                    .dualScopeDelegationSpec(blueprint.dualScopeSpec())
                                    .stateField("statusAfastamento")
                                    .cedenteCustody("cedenteOrgaoId", "subject.cedenteOrgaoIds")
                                    .cessionarioCustody("cessionarioOrgaoId", "subject.cessionarioOrgaoIds")
                                    .mandatoryScopeAnchorAttributeIds(Set.of(
                                            "ergon.afastamentos.id",
                                            "ergon.afastamentos.tenant_id",
                                            "ergon.afastamentos.cedente_orgao_id",
                                            "ergon.afastamentos.cessionario_orgao_id",
                                            "ergon.afastamentos.lotacao_setor_id"
                                    ))
                                    .workflowAction(
                                            "homologar-afastamento",
                                            Set.of("ergon.afastamentos.status_afastamento")
                                    )
                                    .workflowAction(
                                            "designar-substituto",
                                            Set.of("ergon.afastamentos.substituto_servidor_id")
                                    )
                                    .bulkWorkflowAction(
                                            "homologar-lote",
                                            Set.of("ergon.afastamentos.status_afastamento")
                                    )
                                    .uiSurface("ficha-medica-360")
                                    .tenantField("tenantId")
                                    .build();

                    org.praxisplatform.authz.contracts.decisionpoint.DecisionPointDescriptor bulkActionDp =
                            p1016Spec.actionDecisionPoints().get("homologar-lote");
                    assertNotNull(bulkActionDp, "P10.16-A: .bulkWorkflowAction must synthesize DecisionPointDescriptor");
                    assertTrue(
                            bulkActionDp.evaluationModes().containsAll(Set.of(
                                    org.praxisplatform.authz.contracts.decisionpoint.EvaluationMode.SEARCH,
                                    org.praxisplatform.authz.contracts.decisionpoint.EvaluationMode.TARGET
                            )),
                            "P10.16-A: Bulk workflow action DecisionPointDescriptor must support both SEARCH and TARGET modes"
                    );
                    assertNotNull(
                            bulkActionDp.queryProjectionRef(),
                            "P10.16-A: Bulk workflow action DecisionPointDescriptor must inherit QueryableProjectionRef"
                    );

                    org.praxisplatform.authz.host.metadata.AuthzHostPolicyBootstrapBuilder.AuthzHostPolicyBootstrapBundle p1016Bundle =
                            org.praxisplatform.authz.host.metadata.AuthzHostPolicyBootstrapBuilder
                                    .forService(blueprint.serviceKey())
                                    .addResourceSpec(
                                            p1016Spec,
                                            AfastamentoAnnotatedResponseDTO.class,
                                            AfastamentoAnnotatedCreateDTO.class,
                                            AfastamentoAnnotatedUpdateDTO.class
                                    )
                                    .addOrganizationalScopePolicy(
                                            p1016Spec,
                                            "rule-primary-org-scope",
                                            "resource.lotacaoSetorId",
                                            "subject.organizationUnitIds",
                                            Map.of("ergon.afastamentos.cid_codigo", "***CID-RESTRITO***")
                                    )
                                    .addActionPolicy(
                                            p1016Spec,
                                            "homologar-afastamento",
                                            "rule-act-homologar",
                                            Map.of("in", List.of(
                                                    Map.of("var", "resource.lotacaoSetorId"),
                                                    Map.of("var", "subject.organizationUnitIds")
                                            )),
                                            Set.of("ergon.afastamentos.status_afastamento")
                                    )
                                    .addActionPolicy(
                                            p1016Spec,
                                            "designar-substituto",
                                            "rule-act-designar",
                                            Map.of("in", List.of(
                                                    Map.of("var", "resource.lotacaoSetorId"),
                                                    Map.of("var", "subject.organizationUnitIds")
                                            )),
                                            Set.of("ergon.afastamentos.substituto_servidor_id")
                                    )
                                    .addBulkActionPolicy(
                                            p1016Spec,
                                            "homologar-lote",
                                            "rule-bulk-act-homologar",
                                            "resource.lotacaoSetorId",
                                            "subject.organizationUnitIds",
                                            Set.of("ergon.afastamentos.status_afastamento")
                                    )
                                    .addSurfacePolicy(
                                            p1016Spec,
                                            "ficha-medica-360",
                                            "rule-surface-ficha-360",
                                            Map.of("!=", List.of(Map.of("var", "subject.principalId"), "")),
                                            Map.of("ergon.afastamentos.cid_codigo", "***CID-RESTRITO-360***")
                                    )
                                    .build(introspectorBean);

                    MetadataResourceAuthorizationSeam p1016Seam = new MetadataResourceAuthorizationSeam(
                            new OpaAuthorizationProviderAdapter(
                                    p1016Bundle.localOpaTransport(),
                                    new SameInstanceSearchRevisionGuard()
                            ),
                            new FieldUseQueryGuard(),
                            new DtoWriteIntentExtractor(),
                            new FieldWriteAuthorizer(),
                            maskingProcessor,
                            new ObligationBarrierCoordinator(new DefaultObligationHandlerRegistry(), jdbcOutbox),
                            telemetryPublisher
                    );
                    AuthzGovernedResourceServiceSupport p1016ServiceSupport =
                            new AuthzGovernedResourceServiceSupport(p1016Seam, maskingProcessor, introspectorBean);
                    SpecDrivenAfastamentoGovernedService p1016Service = new SpecDrivenAfastamentoGovernedService(
                            repository,
                            p1016ServiceSupport,
                            p1016Spec,
                            callerContextProvider,
                            sharedEm
                    );
                    p1016Service.useDeclarativeCustody.set(true);

                    AuthzHostReadinessReviewer p1016Reviewer = new AuthzHostReadinessReviewer(
                            introspectorBean,
                            null,
                            p1016Bundle.coordinates()
                    );
                    p1016Reviewer.reviewMutableService(p1016Service).assertZeroIssues();

                    // P10.16-A: Verify AUTHZ-HOST-010-BULK-ACTION-MISSING-QUERY-PROJECTION when a bulk action omits queryProjectionRef
                    org.praxisplatform.authz.contracts.decisionpoint.DecisionPointDescriptor brokenBulkDp =
                            new org.praxisplatform.authz.contracts.decisionpoint.DecisionPointDescriptor(
                                    org.praxisplatform.authz.contracts.decisionpoint.DecisionPointDescriptor.SCHEMA_VERSION_V1,
                                    org.praxisplatform.authz.contracts.decisionpoint.DecisionPointIdentity.workflowAction(
                                            blueprint.serviceKey(),
                                            blueprint.resourceKey(),
                                            "bulk-sem-qp"
                                    ),
                                    org.praxisplatform.authz.contracts.decisionpoint.DecisionKind.AUTHORIZATION,
                                    org.praxisplatform.authz.contracts.decisionpoint.DecisionResultContractKind.GATE,
                                    null,
                                    "EXECUTE_BULK_ACTION",
                                    "POST",
                                    "/api/human-resources/afastamentos/actions/bulk-sem-qp",
                                    Set.of(
                                            org.praxisplatform.authz.contracts.decisionpoint.EvaluationMode.TARGET
                                    ),
                                    Set.of(
                                            org.praxisplatform.authz.contracts.decisionpoint.EnforcementCapability.ACCESS,
                                            org.praxisplatform.authz.contracts.decisionpoint.EnforcementCapability.DATA_SCOPE
                                    ),
                                    Set.of(),
                                    null,
                                    p1016Spec.decisionPoint().factContractRef(),
                                    null,
                                    null,
                                    null,
                                    "STATUTORY_LEGAL_OBLIGATION",
                                    "LGPD:ART_7_III",
                                    null,
                                    org.praxisplatform.authz.contracts.digest.CanonicalDigestCalculator.computeDigest(
                                            org.praxisplatform.authz.contracts.digest.DigestDomainKind.DEFINITION_FINGERPRINT,
                                            "broken-bulk-dp|v1"
                                    )
                            );
                    AuthzResourceGovernanceSpec<P102AfastamentoJpaEntity> brokenBulkSpec =
                            AuthzResourceGovernanceSpec.<P102AfastamentoJpaEntity>builder(blueprint.resourceKey())
                                    .serviceKey(blueprint.serviceKey())
                                    .scalarFieldBinding(
                                            "resource.lotacaoSetorId",
                                            "ergon.afastamentos.lotacao_setor_id",
                                            "lotacaoSetorId"
                                    )
                                    .mandatoryScopeAnchorAttributeIds(Set.of(
                                            "ergon.afastamentos.id",
                                            "ergon.afastamentos.tenant_id",
                                            "ergon.afastamentos.cedente_orgao_id",
                                            "ergon.afastamentos.cessionario_orgao_id",
                                            "ergon.afastamentos.lotacao_setor_id"
                                    ))
                                    .actionDecisionPoint("bulk-sem-qp", brokenBulkDp)
                                    .tenantField("tenantId")
                                    .build();
                    AuthzHostReadinessReviewer.ReadinessReport brokenBulkReport =
                            readinessReviewer.reviewGovernanceSpec(
                                    brokenBulkSpec,
                                    P102AfastamentoJpaEntity.class,
                                    AfastamentoAnnotatedResponseDTO.class,
                                    AfastamentoFilterDTO.class,
                                    AfastamentoAnnotatedCreateDTO.class,
                                    AfastamentoAnnotatedUpdateDTO.class
                            );
                    assertFalse(brokenBulkReport.isReady());
                    assertTrue(
                            brokenBulkReport.errors().stream()
                                    .anyMatch(i -> "AUTHZ-HOST-010-BULK-ACTION-MISSING-QUERY-PROJECTION".equals(i.ruleCode())),
                            "P10.16-A: AUTHZ-HOST-010 must flag bulk action decision point missing QueryableProjectionRef"
                    );

                    // P10.16-A: Verify executeGovernedBulkCommand in PER_ITEM mode across [101L, 102L, 999999L]
                    int outboxBeforeBulkCmd = jdbcOutbox.listCommittedEntries().size();
                    callerContextProvider.runWithContext(pureCedenteCaller, () -> {
                        List<AuthzGovernedBulkDomainResourceAdapter.BulkCohortItemOutcome<Long>> bulkOutcomes =
                                txTemplate.execute(status -> p1016Service.homologarEmLote(
                                        List.of(101L, 102L, 999999L),
                                        org.praxisplatform.authz.contracts.binding.BatchAuthorizationMode.PER_ITEM
                                ));
                        assertNotNull(bulkOutcomes);
                        assertEquals(3, bulkOutcomes.size());
                        assertTrue(bulkOutcomes.get(0).committed(), "P10.16-A: Item #101 must commit in PER_ITEM bulk command");
                        assertEquals("COMMITTED", bulkOutcomes.get(0).reasonCode());
                        assertFalse(bulkOutcomes.get(1).committed(), "P10.16-A: Out-of-scope item #102 must be rejected in PER_ITEM bulk command");
                        assertEquals("ACCESS_OR_SCOPE_DENIED", bulkOutcomes.get(1).reasonCode());
                        assertFalse(bulkOutcomes.get(2).committed(), "P10.16-A: Missing item #999999L must be rejected with ENTITY_NOT_FOUND");
                        assertEquals("ENTITY_NOT_FOUND", bulkOutcomes.get(2).reasonCode());
                    });
                    assertEquals(
                            outboxBeforeBulkCmd + 1,
                            jdbcOutbox.listCommittedEntries().size(),
                            "P10.16-A: executeGovernedBulkCommand must record exactly 1 BEFORE_COMMIT_OUTBOX entry for the 1 committed item"
                    );

                    // P10.16-B & P10.16-C: Verify explainable availability diagnostics & AuthzPolicySimulationHarness matrix
                    org.praxisplatform.authz.host.metadata.AuthzPolicySimulationHarness<
                            P102AfastamentoJpaEntity,
                            AfastamentoAnnotatedResponseDTO> simulationHarness =
                            org.praxisplatform.authz.host.metadata.AuthzPolicySimulationHarness.forResource(
                                    p1016Spec,
                                    p1016Bundle,
                                    AfastamentoAnnotatedResponseDTO.class
                            );

                    P102AfastamentoJpaEntity simEntity101 = repository.findById(101L).orElseThrow();
                    P102AfastamentoJpaEntity simEntity102 = repository.findById(102L).orElseThrow();
                    P102AfastamentoJpaEntity simEntity103 = repository.findById(103L).orElseThrow();
                    AfastamentoAnnotatedResponseDTO rawDto101 = new AfastamentoAnnotatedResponseDTO(
                            simEntity101.id,
                            simEntity101.tenantId,
                            simEntity101.cedenteOrgaoId,
                            simEntity101.cessionarioOrgaoId,
                            simEntity101.lotacaoSetorId,
                            simEntity101.statusAfastamento,
                            simEntity101.substitutoServidorId,
                            simEntity101.cidCodigo
                    );

                    // P10.16-B: Explainable diagnostics on dual-scope denial, tenant mismatch, missing state, and allowed action
                    org.praxisplatform.authz.host.metadata.AuthzPolicySimulationHarness.AvailabilitySimulationOutcome cedenteDesignarOutcome =
                            simulationHarness.simulateItemAvailability(pureCedenteCaller, "designar-substituto", simEntity101)
                                    .assertDenied("dual-scope-custody-denied")
                                    .assertDeniedCategory("DUAL_SCOPE_CUSTODY_DENIED");
                    assertEquals("CEDENTE_ONLY", cedenteDesignarOutcome.dualScopeCustodyRole());
                    assertEquals(
                            List.of("ergon.afastamentos.substituto_servidor_id"),
                            cedenteDesignarOutcome.forbiddenWriteAttributeIds(),
                            "P10.16-B: AvailabilityDecision.metadata() must include forbiddenWriteAttributeIds on dual-scope write denial"
                    );
                    assertEquals("designar-substituto", cedenteDesignarOutcome.metadata().get("operationId"));
                    assertEquals("ITEM", cedenteDesignarOutcome.metadata().get("evaluationScope"));

                    simulationHarness.simulateItemAvailability(pureCedenteCaller, "view", simEntity103)
                            .assertDenied("hard-scope-tenant-mismatch")
                            .assertDeniedCategory("TENANT_HARD_SCOPE_MISMATCH");

                    simulationHarness.simulateItemAvailability(pureCedenteCaller, "view", null)
                            .assertDenied("resource-state-not-found")
                            .assertDeniedCategory("RESOURCE_STATE_UNAVAILABLE");

                    org.praxisplatform.authz.host.metadata.AuthzPolicySimulationHarness.AvailabilitySimulationOutcome cedenteHomologarOutcome =
                            simulationHarness.simulateItemAvailability(pureCedenteCaller, "homologar-afastamento", simEntity101)
                                    .assertAllowed();
                    assertEquals("CEDENTE_ONLY", cedenteHomologarOutcome.dualScopeCustodyRole());
                    assertTrue(
                            cedenteHomologarOutcome.policyReasonCodes().contains("ALLOW_ACTION_HOMOLOGAR_AFASTAMENTO"),
                            "P10.16-B: Allowed action availability metadata must include matched policyReasonCodes"
                    );

                    // P10.16-C: Full tabular matrix verification across Cedente, Cessionário, collection bulk action, target read, and 360° surface read
                    org.praxisplatform.authz.host.metadata.AuthzPolicySimulationHarness.MatrixVerificationReport matrixReport =
                            simulationHarness.matrix()
                                    .expectItemAvailability("Cedente pode homologar #101", pureCedenteCaller, "homologar-afastamento", simEntity101, true, null)
                                    .expectItemAvailability("Cedente nao pode designar substituto em #101", pureCedenteCaller, "designar-substituto", simEntity101, false, "dual-scope-custody-denied")
                                    .expectItemAvailability("Cedente pode excluir #101", pureCedenteCaller, "delete", simEntity101, true, null)
                                    .expectItemAvailability("Cessionario pode designar substituto em #101", pureCessionarioCaller, "designar-substituto", simEntity101, true, null)
                                    .expectItemAvailability("Cessionario nao pode homologar #101", pureCessionarioCaller, "homologar-afastamento", simEntity101, false, "dual-scope-custody-denied")
                                    .expectItemAvailability("Cessionario nao pode excluir #101", pureCessionarioCaller, "delete", simEntity101, false, "dual-scope-cedente-custody-required")
                                    .expectItemAvailability("Item #102 fora de lotacao negado pelo OPA", pureCedenteCaller, "view", simEntity102, false, "policy-gate-denied")
                                    .expectItemAvailability("Item #103 outro tenant negado por hard-scope", pureCedenteCaller, "view", simEntity103, false, "hard-scope-tenant-mismatch")
                                    .expectCollectionAvailability("Cedente pode acionar homologar-lote na colecao", pureCedenteCaller, "homologar-lote", true, null)
                                    .expectTargetReadAllowed("Leitura de #101 mascara cidCodigo", pureCedenteCaller, simEntity101, rawDto101, Set.of("ergon.afastamentos.cid_codigo"))
                                    .expectSurfaceReadAllowed("Surface ficha-medica-360 mascara cidCodigo", pureCedenteCaller, "ficha-medica-360", simEntity101, rawDto101, Set.of("ergon.afastamentos.cid_codigo"))
                                    .verifyAll();
                    assertEquals(11, matrixReport.totalScenarios());
                    assertTrue(matrixReport.allPassed());
                    assertEquals(
                            "***CID-RESTRITO-360***",
                            simulationHarness.simulateSurfaceRead(pureCedenteCaller, "ficha-medica-360", simEntity101, rawDto101)
                                    .assertAllowed()
                                    .assertAttributeMasked("ergon.afastamentos.cid_codigo")
                                    .maskedResponse()
                                    .cidCodigo(),
                            "P10.16-C: simulateSurfaceRead must apply surface-specific mask replacement '***CID-RESTRITO-360***'"
                    );

                    // 26b. Fase P10.16 Comprehensive Review Regressions (P10.16-R01 .. P10.16-R05):
                    // P10.16-R01: Custom surface 'ficha-medica-360' (whose rule only checks subject.principalId != '')
                    // MUST be denied on out-of-scope item #102 (lotacaoSetorId = 999L) both in availability discovery and simulateSurfaceRead!
                    simulationHarness.simulateItemAvailability(pureCedenteCaller, "ficha-medica-360", simEntity102)
                            .assertDenied("policy-gate-denied")
                            .assertDeniedCategory("POLICY_GATE_DENIED");
                    simulationHarness.simulateSurfaceRead(pureCedenteCaller, "ficha-medica-360", simEntity102, rawDto101)
                            .assertDenied();

                    // P10.16-R02: In PER_ITEM bulk command, if entityMutator modifies a managed entity (#101) and then throws
                    // a domain validation RuntimeException, the dirty entity MUST be detached so Hibernate dirty checking
                    // never flushes the rejected mutation when the transaction commits!
                    String statusBeforeFailedMutator = repository.findById(101L).orElseThrow().statusAfastamento;
                    int outboxBeforeFailedMutator = jdbcOutbox.listCommittedEntries().size();
                    callerContextProvider.runWithContext(pureCedenteCaller, () -> {
                        List<AuthzGovernedBulkDomainResourceAdapter.BulkCohortItemOutcome<Long>> failedMutatorOutcomes =
                                txTemplate.execute(status -> p1016Service.homologarEmLoteComFalhaValidacao(
                                        List.of(101L),
                                        org.praxisplatform.authz.contracts.binding.BatchAuthorizationMode.PER_ITEM
                                ));
                        assertEquals(1, failedMutatorOutcomes.size());
                        assertFalse(failedMutatorOutcomes.getFirst().committed());
                        assertEquals("DOMAIN_VALIDATION_REJECTED", failedMutatorOutcomes.getFirst().reasonCode());
                    });
                    assertEquals(
                            statusBeforeFailedMutator,
                            repository.findById(101L).orElseThrow().statusAfastamento,
                            "P10.16-R02: Rejected PER_ITEM entity mutation must be detached from JPA PersistenceContext and never flushed on commit"
                    );
                    assertEquals(
                            outboxBeforeFailedMutator,
                            jdbcOutbox.listCommittedEntries().size(),
                            "P10.16-R02: Rejected PER_ITEM entity mutation must not record any BEFORE_COMMIT_OUTBOX entry"
                    );

                    // P10.16-R03: addBulkActionPolicy must fail fast at build time when given an item-only .workflowAction(...)
                    assertThrows(
                            IllegalArgumentException.class,
                            () -> org.praxisplatform.authz.host.metadata.AuthzHostPolicyBootstrapBuilder
                                    .forService(blueprint.serviceKey())
                                    .addBulkActionPolicy(
                                            p1016Spec,
                                            "homologar-afastamento", // registered via .workflowAction(...) without SEARCH / queryProjectionRef
                                            "rule-invalid-bulk",
                                            "resource.lotacaoSetorId",
                                            "subject.organizationUnitIds",
                                            Set.of("ergon.afastamentos.status_afastamento")
                                    ),
                            "P10.16-R03: addBulkActionPolicy must reject an action registered via item-only .workflowAction(...)"
                    );

                    // P10.16-R04: AuthzResourceOperationAvailabilityProvider must return fail-closed 'caller-context-missing'
                    // (CALLER_CONTEXT_MISSING) instead of throwing an unhandled SecurityException when no AuthzCallerContext is bound
                    AvailabilityDecision missingCallerDecision = autoAvailability.evaluate(
                            ResourceOperationAvailabilityContext.collection(
                                    blueprint.resourceKey(),
                                    "/api/human-resources/afastamentos",
                                    "filter"
                            )
                    );
                    assertFalse(missingCallerDecision.allowed(), "P10.16-R04: Missing caller context must fail closed");
                    assertEquals("caller-context-missing", missingCallerDecision.reason());
                    assertEquals("CALLER_CONTEXT_MISSING", missingCallerDecision.metadata().get("denialCategory"));

                    // P10.16-R05: simulateBulkCommand and MatrixRunner.expectBulkCommand verify mixed cohort [101L, 102L, 103L] in memory
                    List<AuthzGovernedBulkDomainResourceAdapter.BulkCohortItemOutcome<Long>> simBulkOutcomes =
                            simulationHarness.simulateBulkCommand(
                                    pureCedenteCaller,
                                    "homologar-lote",
                                    List.of(simEntity101, simEntity102, simEntity103),
                                    e -> e.id,
                                    org.praxisplatform.authz.contracts.binding.BatchAuthorizationMode.PER_ITEM
                            );
                    assertEquals(3, simBulkOutcomes.size());
                    assertTrue(simBulkOutcomes.get(0).committed());
                    assertFalse(simBulkOutcomes.get(1).committed());
                    assertFalse(simBulkOutcomes.get(2).committed());

                    simulationHarness.matrix()
                            .expectBulkCommand(
                                    "Coorte mista [101, 102, 103] em PER_ITEM",
                                    pureCedenteCaller,
                                    "homologar-lote",
                                    List.of(simEntity101, simEntity102, simEntity103),
                                    e -> e.id,
                                    org.praxisplatform.authz.contracts.binding.BatchAuthorizationMode.PER_ITEM,
                                    List.of(true, false, false)
                            )
                            .verifyAll();

                    // =========================================================================
                    // 27. Fase P10.17: Governed DuplicateDraft (P10.17-A), Dynamic Export
                    //     Column & Value-Deny Sanitization, and In-Memory Simulation (P10.17-B)
                    // =========================================================================
                    Map<String, Object> rawDuplicateDraft = new java.util.LinkedHashMap<>();
                    rawDuplicateDraft.put("version", 7L);
                    rawDuplicateDraft.put("orgCedenteId", 1L);
                    rawDuplicateDraft.put("orgCessionariaId", 2L);
                    rawDuplicateDraft.put("lotacaoSetorId", 100L);
                    rawDuplicateDraft.put("statusAfastamento", "DEFERIDO");
                    rawDuplicateDraft.put("substitutoServidorId", 5001L);
                    rawDuplicateDraft.put("cidCodigo", "M54.5");

                    var dupDraftOutcome = simulationHarness.simulateDuplicateDraft(
                            pureCedenteCaller,
                            simEntity101,
                            rawDuplicateDraft
                    );
                    dupDraftOutcome
                            .assertAllowed()
                            .assertAttributeStripped("version")
                            .assertAttributeStripped("cidCodigo")
                            .assertAttributeStripped("ergon.afastamentos.cid_codigo")
                            .assertAttributeStripped("substitutoServidorId")
                            .assertAttributeStripped("ergon.afastamentos.substituto_servidor_id")
                            .assertAttributePreserved("orgCedenteId")
                            .assertAttributePreserved("orgCessionariaId")
                            .assertAttributePreserved("lotacaoSetorId")
                            .assertAttributePreserved("statusAfastamento");
                    org.junit.jupiter.api.Assertions.assertNull(dupDraftOutcome.sanitizedDraft().get("version"));
                    org.junit.jupiter.api.Assertions.assertNull(dupDraftOutcome.sanitizedDraft().get("cidCodigo"));
                    org.junit.jupiter.api.Assertions.assertNull(dupDraftOutcome.sanitizedDraft().get("substitutoServidorId"));
                    assertEquals(1L, dupDraftOutcome.sanitizedDraft().get("orgCedenteId"));
                    assertEquals(2L, dupDraftOutcome.sanitizedDraft().get("orgCessionariaId"));
                    assertEquals(100L, dupDraftOutcome.sanitizedDraft().get("lotacaoSetorId"));

                    // Out-of-scope entity 102 must be denied in simulateDuplicateDraft
                    simulationHarness.simulateDuplicateDraft(pureCedenteCaller, simEntity102, rawDuplicateDraft)
                            .assertDenied("policy-gate-denied");

                    // Simulate CollectionExport across [simEntity101, simEntity102, simEntity103]
                    var exportSimOutcome = simulationHarness.simulateCollectionExport(
                            pureCedenteCaller,
                            List.of(simEntity101, simEntity102, simEntity103),
                            e -> new AfastamentoAnnotatedResponseDTO(
                                    e.id,
                                    e.tenantId,
                                    e.cedenteOrgaoId,
                                    e.cessionarioOrgaoId,
                                    e.lotacaoSetorId,
                                    e.statusAfastamento,
                                    e.substitutoServidorId,
                                    e.cidCodigo
                            )
                    );
                    exportSimOutcome
                            .assertAllowed()
                            .assertRowCount(1) // Only simEntity101 is in pureCedenteCaller's organizational scope!
                            .assertFieldExcluded("orgCedenteId") // exportable = false inherited from P102AfastamentoJpaEntity.cedenteOrgaoId
                            .assertFieldExcluded("cidCodigo") // LGPD_SENSITIVE_DATA has exportable = false by default
                            .assertAttributeMasked("ergon.afastamentos.cid_codigo");
                    assertFalse(exportSimOutcome.exportedRows().getFirst().containsKey("orgCedenteId"));
                    assertFalse(exportSimOutcome.exportedRows().getFirst().containsKey("cidCodigo"));
                    assertEquals("HOMOLOGADO", exportSimOutcome.exportedRows().getFirst().get("statusAfastamento"));

                    // Verify AuthzGovernedCollectionExportExecutor strips dynamic VALUE+DENY columns from defaultFields and rows
                    org.praxisplatform.uischema.exporting.CollectionExportExecutor dynamicDeniedExportExecutor =
                            new org.praxisplatform.authz.host.metadata.AuthzGovernedCollectionExportExecutor(
                                    new DefaultCollectionExportExecutor(List.of(new CsvCollectionExportEngine())),
                                    new DetachedDtoMaskingProcessor(),
                                    p1016Service.getGovernanceContract(),
                                    List::of,
                                    () -> Set.of("ergon.afastamentos.substituto_servidor_id")
                            );
                    var dynamicExportResult = dynamicDeniedExportExecutor.export(
                            exportReq,
                            List.of(rawDto101),
                            List.of(
                                    new org.praxisplatform.uischema.exporting.CollectionExportField("statusAfastamento", "Status", true, true, "string", "statusAfastamento"),
                                    new org.praxisplatform.uischema.exporting.CollectionExportField("orgCedenteId", "Cedente", true, true, "number", "orgCedenteId"),
                                    new org.praxisplatform.uischema.exporting.CollectionExportField("substitutoServidorId", "Substituto", true, true, "number", "substitutoServidorId")
                            ),
                            (row, field) -> row.statusAfastamento(),
                            Map.of()
                    );
                    assertEquals(1, dynamicExportResult.metadata().get("valueDeniedAttributeCount"));
                    String dynamicCsvText = new String(dynamicExportResult.content(), StandardCharsets.UTF_8);
                    assertFalse(dynamicCsvText.contains("substitutoServidorId"),
                            "P10.17-A: Dynamic VALUE+DENY column must be stripped from exported fields and rows");
                    assertFalse(dynamicCsvText.contains("5001"),
                            "P10.17-A: Dynamic VALUE+DENY value must never appear in exported CSV");
                    assertFalse(dynamicCsvText.contains("orgCedenteId"),
                            "P10.17-A: Non-exportable column must be stripped from exported fields and rows");

                    // Verify MatrixRunner.expectDuplicateDraft and expectCollectionExport
                    simulationHarness.matrix()
                            .expectDuplicateDraft(
                                    "Cedente clona 101 com sanitização de CID e partição Cessionário",
                                    pureCedenteCaller,
                                    simEntity101,
                                    rawDuplicateDraft,
                                    true,
                                    Set.of("cidCodigo", "substitutoServidorId", "version")
                            )
                            .expectDuplicateDraft(
                                    "Cedente negado ao clonar 102 fora de escopo",
                                    pureCedenteCaller,
                                    simEntity102,
                                    rawDuplicateDraft,
                                    false,
                                    null
                            )
                            .expectCollectionExport(
                                    "Exportação em lote Cedente retorna apenas 101 e exclui orgCedenteId",
                                    pureCedenteCaller,
                                    List.of(simEntity101, simEntity102, simEntity103),
                                    e -> new AfastamentoAnnotatedResponseDTO(
                                            e.id,
                                            e.tenantId,
                                            e.cedenteOrgaoId,
                                            e.cessionarioOrgaoId,
                                            e.lotacaoSetorId,
                                            e.statusAfastamento,
                                            e.substitutoServidorId,
                                            e.cidCodigo
                                    ),
                                    1,
                                    Set.of("orgCedenteId")
                            )
                            .verifyAll();

                    // =========================================================================
                    // 28. Fase P10.18 — simulateReactiveDetermination, simulateAiContextProjection & simulateQueryFieldUse
                    // =========================================================================
                    Map<String, Object> rawDeterminationMap = new java.util.LinkedHashMap<>();
                    rawDeterminationMap.put("cidCodigo", "J11");
                    rawDeterminationMap.put("statusAfastamento", "HOMOLOGADO");
                    rawDeterminationMap.put("diasCalculados", 15);

                    var detSimOutcome = simulationHarness.simulateReactiveDetermination(
                            pureCedenteCaller,
                            simEntity101,
                            rawDeterminationMap
                    );
                    detSimOutcome
                            .assertAllowed()
                            .assertAttributeMasked("ergon.afastamentos.cid_codigo")
                            .assertKeyPresentWithValue("cidCodigo", "***CID-RESTRITO***")
                            .assertKeyPresentWithValue("diasCalculados", 15);

                    // Out-of-scope entity 102 must be denied in simulateReactiveDetermination
                    simulationHarness.simulateReactiveDetermination(
                            pureCedenteCaller,
                            simEntity102,
                            rawDeterminationMap
                    ).assertDenied("policy-gate-denied");

                    // Simulate AI Context / Tool Grounding projection on entity 101
                    var aiSimOutcome = simulationHarness.simulateAiContextProjection(
                            pureCedenteCaller,
                            simEntity101,
                            rawDto101
                    );
                    aiSimOutcome
                            .assertAllowed()
                            .assertColumnAllowed("statusAfastamento")
                            .assertAttributeSuppressed("cidCodigo")
                            .assertAttributeSuppressed("ergon.afastamentos.cid_codigo");
                    assertFalse(aiSimOutcome.detachedPayload().containsKey("cidCodigo"),
                            "P10.18-A: AI context projection must completely suppress LGPD_SENSITIVE_DATA / aiAllowed=false attributes");

                    // Out-of-scope entity 102 must be denied in simulateAiContextProjection
                    simulationHarness.simulateAiContextProjection(
                            pureCedenteCaller,
                            simEntity102,
                            rawDto101
                    ).assertDenied("policy-gate-denied");

                    // Simulate QueryFieldUse: filtering on statusAfastamento is ALLOWED, filtering/sorting on cidCodigo is DENIED
                    simulationHarness.simulateQueryFieldUse(
                            pureCedenteCaller,
                            Map.of(FieldUseCategory.FILTER, Set.of("statusAfastamento"))
                    ).assertAllowed();

                    simulationHarness.simulateQueryFieldUse(
                            pureCedenteCaller,
                            Map.of(FieldUseCategory.FILTER, Set.of("cidCodigo"))
                    ).assertViolated(FieldUseCategory.FILTER, "ergon.afastamentos.cid_codigo");

                    simulationHarness.simulateQueryFieldUse(
                            pureCedenteCaller,
                            Map.of(FieldUseCategory.SORT, Set.of("cidCodigo"))
                    ).assertViolated(FieldUseCategory.SORT, "ergon.afastamentos.cid_codigo");

                    // Simulate FilterDTO + Sort automatic extraction via simulateFilterAndSortFieldUse
                    AfastamentoFilterDTO allowedFilterDto = new AfastamentoFilterDTO();
                    allowedFilterDto.statusAfastamento = "HOMOLOGADO";
                    simulationHarness.simulateFilterAndSortFieldUse(
                            pureCedenteCaller,
                            allowedFilterDto,
                            org.springframework.data.domain.Sort.by("statusAfastamento")
                    ).assertAllowed();

                    AfastamentoFilterDTO deniedFilterDto = new AfastamentoFilterDTO();
                    deniedFilterDto.cidCodigo = "J11";
                    simulationHarness.simulateFilterAndSortFieldUse(
                            pureCedenteCaller,
                            deniedFilterDto,
                            org.springframework.data.domain.Sort.unsorted()
                    ).assertViolated(FieldUseCategory.FILTER, "ergon.afastamentos.cid_codigo");

                    // Verify MatrixRunner.expectReactiveDetermination, expectAiContextProjection & expectQueryFieldUse
                    simulationHarness.matrix()
                            .expectReactiveDetermination(
                                    "Determinação reativa em 101 permitida com máscara de CID",
                                    pureCedenteCaller,
                                    simEntity101,
                                    rawDeterminationMap,
                                    true,
                                    Set.of("ergon.afastamentos.cid_codigo")
                            )
                            .expectReactiveDetermination(
                                    "Determinação reativa em 102 fora de escopo negada",
                                    pureCedenteCaller,
                                    simEntity102,
                                    rawDeterminationMap,
                                    false,
                                    null
                            )
                            .expectAiContextProjection(
                                    "Projeção AI em 101 suprime CID sensível",
                                    pureCedenteCaller,
                                    simEntity101,
                                    rawDto101,
                                    true,
                                    Set.of("cidCodigo", "ergon.afastamentos.cid_codigo")
                            )
                            .expectQueryFieldUse(
                                    "Filtro em statusAfastamento permitido",
                                    pureCedenteCaller,
                                    Map.of(FieldUseCategory.FILTER, Set.of("statusAfastamento")),
                                    true,
                                    null,
                                    null
                            )
                            .expectQueryFieldUse(
                                    "Filtro em cidCodigo sensível bloqueado",
                                    pureCedenteCaller,
                                    Map.of(FieldUseCategory.FILTER, Set.of("cidCodigo")),
                                    false,
                                    FieldUseCategory.FILTER,
                                    "ergon.afastamentos.cid_codigo"
                            )
                            .verifyAll();

                    // =========================================================================
                    // 29. Fase P10.19 — simulateGroupByStats, simulateOptionSource & STEP_11 Write Mutation Simulations
                    // =========================================================================
                    // P10.19-A: Analytics GROUP BY & StatsFieldRegistry discovery filtering
                    simulationHarness.simulateGroupByStats(pureCedenteCaller, "statusAfastamento", Set.of())
                            .assertAllowed();
                    simulationHarness.simulateGroupByStats(pureCedenteCaller, "cidCodigo", Set.of())
                            .assertViolated(FieldUseCategory.GROUP, "ergon.afastamentos.cid_codigo");

                    StatsFieldRegistry rawStatsReg = StatsFieldRegistry.builder()
                            .categoricalGroupByBucket("statusAfastamento", "statusAfastamento")
                            .categoricalGroupByBucket("cidCodigo", "cidCodigo")
                            .build();
                    StatsFieldRegistry filteredStatsReg = simulationHarness.simulateFilteredStatsRegistry(rawStatsReg);
                    assertTrue(filteredStatsReg.descriptors().stream().anyMatch(d -> "statusAfastamento".equals(d.field())));
                    assertFalse(filteredStatsReg.descriptors().stream().anyMatch(d -> "cidCodigo".equals(d.field())),
                            "P10.19-A: Restricted LGPD_SENSITIVE_DATA field cidCodigo must be stripped from StatsFieldRegistry discovery");

                    // P10.19-A: OptionSource simulation (out-of-scope omission + label/extra masking)
                    var optSimOutcome = simulationHarness.simulateOptionSource(
                            pureCedenteCaller,
                            List.of(simEntity101, simEntity102, simEntity103),
                            e -> new OptionDTO<>(
                                    e.id,
                                    "Afastamento #" + e.id + " - " + e.cidCodigo,
                                    Map.of(
                                            "statusAfastamento", e.statusAfastamento,
                                            "cidCodigo", e.cidCodigo,
                                            "displayFields", Map.of("cidCodigo", e.cidCodigo, "statusAfastamento", e.statusAfastamento)
                                    )
                            )
                    );
                    optSimOutcome
                            .assertAllowed()
                            .assertOptionCount(1)
                            .assertOptionAdmitted(101L)
                            .assertOptionOmitted(102L)
                            .assertOptionOmitted(103L)
                            .assertOptionLabel(101L, "Afastamento #101 - ***CID-RESTRITO***");
                    assertEquals("***CID-RESTRITO***", optSimOutcome.options().getFirst().extra().get("cidCodigo"));

                    // P10.19-B: STEP_11 Write Mutation Simulations (CREATE, UPDATE, DELETE, @WorkflowAction)
                    // 1) Pure Cedente can update cidCodigo (Cedente partition), but CANNOT update substitutoServidorId (Cessionário partition)
                    simulationHarness.simulateUpdateMutation(
                            pureCedenteCaller,
                            simEntity101,
                            new AfastamentoAnnotatedUpdateDTO(null, "J12")
                    ).assertAllowed().assertAttributeModified("ergon.afastamentos.cid_codigo");

                    simulationHarness.simulateUpdateMutation(
                            pureCedenteCaller,
                            simEntity101,
                            new AfastamentoAnnotatedUpdateDTO(7777L, null)
                    ).assertDenied("dual-scope-custody-denied")
                            .assertForbiddenWriteAttribute("ergon.afastamentos.substituto_servidor_id");

                    // 2) Pure Cessionário can update substitutoServidorId, but CANNOT update cidCodigo or DELETE entity
                    simulationHarness.simulateUpdateMutation(
                            pureCessionarioCaller,
                            simEntity101,
                            new AfastamentoAnnotatedUpdateDTO(7777L, null)
                    ).assertAllowed().assertAttributeModified("ergon.afastamentos.substituto_servidor_id");

                    simulationHarness.simulateUpdateMutation(
                            pureCessionarioCaller,
                            simEntity101,
                            new AfastamentoAnnotatedUpdateDTO(null, "J99")
                    ).assertDenied("dual-scope-custody-denied")
                            .assertForbiddenWriteAttribute("ergon.afastamentos.cid_codigo");

                    simulationHarness.simulateDeleteMutation(pureCedenteCaller, simEntity101)
                            .assertAllowed();
                    simulationHarness.simulateDeleteMutation(pureCessionarioCaller, simEntity101)
                            .assertDenied("dual-scope-custody-denied");

                    // 3) CREATE missing mandatory scope anchor (lotacaoSetorId = null) must fail closed with scope-anchor-clear-forbidden
                    simulationHarness.simulateCreateMutation(
                            pureCedenteCaller,
                            new AfastamentoAnnotatedCreateDTO(
                                    199L, "tenant-gov-br", 10L, 20L, null, "DEFERIDO", null, "J11"
                            ),
                            simEntity101
                    ).assertDenied("scope-anchor-clear-forbidden");

                    // 4) Item Command Mutation (@WorkflowAction)
                    simulationHarness.simulateItemCommandMutation(
                            pureCedenteCaller,
                            "homologar-afastamento",
                            simEntity101,
                            null
                    ).assertAllowed().assertAttributeModified("ergon.afastamentos.status_afastamento");

                    simulationHarness.simulateItemCommandMutation(
                            pureCedenteCaller,
                            "designar-substituto",
                            simEntity101,
                            new DesignarSubstitutoCommandDTO(8888L)
                    ).assertDenied("dual-scope-custody-denied")
                            .assertForbiddenWriteAttribute("ergon.afastamentos.substituto_servidor_id");

                    // 5) Full MatrixRunner verification for P10.19-A & P10.19-B
                    simulationHarness.matrix()
                            .expectGroupByStats(
                                    "Analytics GROUP BY statusAfastamento permitido",
                                    pureCedenteCaller,
                                    "statusAfastamento",
                                    Set.of(),
                                    true,
                                    null,
                                    null
                            )
                            .expectGroupByStats(
                                    "Analytics GROUP BY cidCodigo bloqueado",
                                    pureCedenteCaller,
                                    "cidCodigo",
                                    Set.of(),
                                    false,
                                    FieldUseCategory.GROUP,
                                    "ergon.afastamentos.cid_codigo"
                            )
                            .expectOptionSource(
                                    "OptionSource admite apenas item 101 em escopo",
                                    pureCedenteCaller,
                                    List.of(simEntity101, simEntity102, simEntity103),
                                    e -> new OptionDTO<>(e.id, "Item " + e.id, Map.of("cidCodigo", e.cidCodigo)),
                                    Set.of(101L)
                            )
                            .expectCreateMutation(
                                    "CREATE sem âncora obrigatória lotacaoSetorId falha fail-closed",
                                    pureCedenteCaller,
                                    new AfastamentoAnnotatedCreateDTO(
                                            199L, "tenant-gov-br", 10L, 20L, null, "DEFERIDO", null, "J11"
                                    ),
                                    simEntity101,
                                    false,
                                    "scope-anchor-clear-forbidden"
                            )
                            .expectUpdateMutation(
                                    "Cedente atualiza cidCodigo com sucesso",
                                    pureCedenteCaller,
                                    simEntity101,
                                    new AfastamentoAnnotatedUpdateDTO(null, "J12"),
                                    true,
                                    null
                            )
                            .expectUpdateMutation(
                                    "Cedente bloqueado ao atualizar substitutoServidorId do Cessionário",
                                    pureCedenteCaller,
                                    simEntity101,
                                    new AfastamentoAnnotatedUpdateDTO(7777L, null),
                                    false,
                                    "dual-scope-custody-denied"
                            )
                            .expectDeleteMutation(
                                    "Cedente pode excluir registro",
                                    pureCedenteCaller,
                                    simEntity101,
                                    true,
                                    null
                            )
                            .expectDeleteMutation(
                                    "Cessionário bloqueado ao excluir registro com atributos exclusivos do Cedente",
                                    pureCessionarioCaller,
                                    simEntity101,
                                    false,
                                    "dual-scope-custody-denied"
                            )
                            .expectItemCommandMutation(
                                    "Cessionário executa designar-substituto em 101",
                                    pureCessionarioCaller,
                                    "designar-substituto",
                                    simEntity101,
                                    new DesignarSubstitutoCommandDTO(8888L),
                                    true,
                                    null
                            )
                            .verifyAll();

                    // =========================================================================
                    // 30. Fase P10.20 — Analytical Modalities (TimeSeries, Distribution, Comparison)
                    //     with FilterDTO & Bulk Cohort Simulations (REJECT_ALL vs PER_ITEM)
                    // =========================================================================
                    AfastamentoFilterDTO validFilterDto = new AfastamentoFilterDTO();
                    validFilterDto.statusAfastamento = "DEFERIDO";

                    AfastamentoFilterDTO restrictedCidFilterDto = new AfastamentoFilterDTO();
                    restrictedCidFilterDto.cidCodigo = "J11";

                    // P10.20-B: Analytics with FilterDTO (GroupBy, TimeSeries, Distribution, Comparison)
                    simulationHarness.simulateGroupByStats(pureCedenteCaller, "statusAfastamento", Set.of(), validFilterDto)
                            .assertAllowed();
                    simulationHarness.simulateGroupByStats(pureCedenteCaller, "statusAfastamento", Set.of(), restrictedCidFilterDto)
                            .assertViolated(FieldUseCategory.FILTER, "ergon.afastamentos.cid_codigo");

                    simulationHarness.simulateTimeSeriesStats(pureCedenteCaller, "statusAfastamento", Set.of(), validFilterDto)
                            .assertAllowed();
                    simulationHarness.simulateTimeSeriesStats(pureCedenteCaller, "cidCodigo", Set.of(), validFilterDto)
                            .assertViolated(FieldUseCategory.GROUP, "ergon.afastamentos.cid_codigo");

                    simulationHarness.simulateDistributionStats(pureCedenteCaller, "statusAfastamento", null, validFilterDto)
                            .assertAllowed();
                    simulationHarness.simulateDistributionStats(pureCedenteCaller, "statusAfastamento", "cidCodigo", validFilterDto)
                            .assertViolated(FieldUseCategory.AGGREGATE, "ergon.afastamentos.cid_codigo");

                    simulationHarness.simulateComparisonStats(
                            pureCedenteCaller,
                            "statusAfastamento",
                            Set.of(),
                            validFilterDto,
                            validFilterDto
                    ).assertAllowed();

                    simulationHarness.simulateComparisonStats(
                            pureCedenteCaller,
                            "statusAfastamento",
                            Set.of(),
                            validFilterDto,
                            restrictedCidFilterDto
                    ).assertViolated(FieldUseCategory.FILTER, "ergon.afastamentos.cid_codigo");

                    // P10.20-B: Bulk Cohort Simulations (BulkUpdate, BulkPerItemUpdate, BulkDelete, BulkCommand)
                    // 1) Uniform Bulk Update Cohort: [101L (in-scope), 102L (out-of-scope), 103L (cross-tenant)]
                    simulationHarness.simulateBulkUpdateCohort(
                            pureCedenteCaller,
                            List.of(simEntity101, simEntity102, simEntity103),
                            e -> e.id,
                            new AfastamentoAnnotatedUpdateDTO(null, "J12"),
                            org.praxisplatform.authz.contracts.binding.BatchAuthorizationMode.PER_ITEM
                    )
                            .assertCommittedCount(1)
                            .assertItemCommitted(101L)
                            .assertItemRejected(102L, "ACCESS_OR_SCOPE_DENIED")
                            .assertItemRejected(103L, "ACCESS_OR_SCOPE_DENIED");

                    simulationHarness.simulateBulkUpdateCohort(
                            pureCedenteCaller,
                            List.of(simEntity101, simEntity102, simEntity103),
                            e -> e.id,
                            new AfastamentoAnnotatedUpdateDTO(null, "J12"),
                            org.praxisplatform.authz.contracts.binding.BatchAuthorizationMode.REJECT_ALL
                    )
                            .assertBatchAborted("ACCESS_OR_SCOPE_DENIED")
                            .assertItemRejected(101L, "BATCH_ABORTED")
                            .assertItemRejected(102L, "ACCESS_OR_SCOPE_DENIED");

                    // 2) Per-Item Bulk Update Cohort: 101L gets allowed cidCodigo update, or forbidden substitutoServidorId update
                    simulationHarness.simulateBulkPerItemUpdateCohort(
                            pureCedenteCaller,
                            List.of(simEntity101),
                            e -> e.id,
                            Map.of(101L, new AfastamentoAnnotatedUpdateDTO(null, "J15")),
                            org.praxisplatform.authz.contracts.binding.BatchAuthorizationMode.REJECT_ALL
                    ).assertAllCommitted().assertItemCommitted(101L);

                    simulationHarness.simulateBulkPerItemUpdateCohort(
                            pureCedenteCaller,
                            List.of(simEntity101),
                            e -> e.id,
                            Map.of(101L, new AfastamentoAnnotatedUpdateDTO(9999L, null)),
                            org.praxisplatform.authz.contracts.binding.BatchAuthorizationMode.PER_ITEM
                    ).assertCommittedCount(0).assertItemRejected(101L, "FIELD_WRITE_DENIED");

                    // 3) Bulk Delete Cohort: Pure Cessionário cannot delete (requires Cedente custody)
                    simulationHarness.simulateBulkDeleteCohort(
                            pureCessionarioCaller,
                            List.of(simEntity101),
                            e -> e.id,
                            org.praxisplatform.authz.contracts.binding.BatchAuthorizationMode.PER_ITEM
                    ).assertCommittedCount(0).assertItemRejected(101L, "FIELD_WRITE_DENIED");

                    simulationHarness.simulateBulkDeleteCohort(
                            pureCedenteCaller,
                            List.of(simEntity101),
                            e -> e.id,
                            org.praxisplatform.authz.contracts.binding.BatchAuthorizationMode.REJECT_ALL
                    ).assertAllCommitted().assertItemCommitted(101L);

                    // 4) Bulk Command Cohort with commandDto at STEP_11
                    simulationHarness.simulateBulkCommandCohort(
                            pureCedenteCaller,
                            "homologar-lote",
                            List.of(simEntity101, simEntity102),
                            e -> e.id,
                            null,
                            org.praxisplatform.authz.contracts.binding.BatchAuthorizationMode.PER_ITEM
                    )
                            .assertCommittedCount(1)
                            .assertItemCommitted(101L)
                            .assertItemRejected(102L, "ACCESS_OR_SCOPE_DENIED");

                    // 5) MatrixRunner verification for P10.20-B
                    simulationHarness.matrix()
                            .expectTimeSeriesStats(
                                    "TimeSeries válido em statusAfastamento",
                                    pureCedenteCaller,
                                    "statusAfastamento",
                                    Set.of(),
                                    validFilterDto,
                                    true,
                                    null,
                                    null
                            )
                            .expectDistributionStats(
                                    "Distribution bloqueado quando métrica usa cidCodigo",
                                    pureCedenteCaller,
                                    "statusAfastamento",
                                    "cidCodigo",
                                    validFilterDto,
                                    false,
                                    FieldUseCategory.AGGREGATE,
                                    "ergon.afastamentos.cid_codigo"
                            )
                            .expectComparisonStats(
                                    "Comparison bloqueado quando filtro de comparação usa cidCodigo",
                                    pureCedenteCaller,
                                    "statusAfastamento",
                                    Set.of(),
                                    validFilterDto,
                                    restrictedCidFilterDto,
                                    false,
                                    FieldUseCategory.FILTER,
                                    "ergon.afastamentos.cid_codigo"
                            )
                            .expectBulkUpdateCohort(
                                    "BulkUpdate PER_ITEM confirma 101L e rejeita 102L",
                                    pureCedenteCaller,
                                    List.of(simEntity101, simEntity102),
                                    e -> e.id,
                                    new AfastamentoAnnotatedUpdateDTO(null, "J12"),
                                    org.praxisplatform.authz.contracts.binding.BatchAuthorizationMode.PER_ITEM,
                                    false,
                                    Set.of(101L)
                            )
                            .expectBulkUpdateCohort(
                                    "BulkUpdate REJECT_ALL aborta coorte quando 102L está fora de escopo",
                                    pureCedenteCaller,
                                    List.of(simEntity101, simEntity102),
                                    e -> e.id,
                                    new AfastamentoAnnotatedUpdateDTO(null, "J12"),
                                    org.praxisplatform.authz.contracts.binding.BatchAuthorizationMode.REJECT_ALL,
                                    true,
                                    Set.of()
                            )
                            .expectBulkDeleteCohort(
                                    "BulkDelete REJECT_ALL para Cedente em [101L] confirma 101L",
                                    pureCedenteCaller,
                                    List.of(simEntity101),
                                    e -> e.id,
                                    org.praxisplatform.authz.contracts.binding.BatchAuthorizationMode.REJECT_ALL,
                                    false,
                                    Set.of(101L)
                            )
                            .expectBulkCommandCohort(
                                    "BulkCommandCohort PER_ITEM em homologar-lote confirma 101L",
                                    pureCedenteCaller,
                                    "homologar-lote",
                                    List.of(simEntity101, simEntity102),
                                    e -> e.id,
                                    null,
                                    org.praxisplatform.authz.contracts.binding.BatchAuthorizationMode.PER_ITEM,
                                    false,
                                    Set.of(101L)
                            )
                            .verifyAll();

                    // =========================================================================
                    // 31. Fase P10.21 — Architectural Readiness Gates AUTHZ-HOST-011 / AUTHZ-HOST-012
                    //     and Simulation of 2-Phase Bulk Proposal/Confirm & Header Anti-Spoofing
                    // =========================================================================
                    // 31a. P10.21-A: AUTHZ-HOST-011 (invalid stats entity path & VALUE+DENY stats field)
                    //      and AUTHZ-HOST-012 (VALUE+DENY @Filterable field on FilterDTO)
                    StatsFieldRegistry brokenAndSecretStatsReg = StatsFieldRegistry.builder()
                            .categoricalGroupByBucket("statusAfastamento", "statusAfastamento")
                            .categoricalGroupByBucket("campoInexistenteStats", "campoInexistenteStats")
                            .categoricalGroupByBucket("webhookToken", "statusAfastamento")
                            .build();
                    AuthzHostReadinessReviewer.ReadinessReport host011And012Report =
                            readinessReviewer.reviewGovernanceSpec(
                                    selfContainedSpec,
                                    P102AfastamentoJpaEntity.class,
                                    SecretTokenAfastamentoResponseDTO.class,
                                    SecretTokenAfastamentoFilterDTO.class,
                                    null,
                                    null,
                                    brokenAndSecretStatsReg
                            );
                    assertFalse(host011And012Report.isReady());
                    assertTrue(
                            host011And012Report.errors().stream()
                                    .anyMatch(i -> "AUTHZ-HOST-011-INVALID-STATS-ENTITY-PATH".equals(i.ruleCode())),
                            "P10.21-A: AUTHZ-HOST-011 must reject StatsFieldDescriptor referencing non-existent JPA entity path"
                    );
                    assertTrue(
                            host011And012Report.errors().stream()
                                    .anyMatch(i -> "AUTHZ-HOST-011-VALUE-DENIED-STATS-FIELD".equals(i.ruleCode())),
                            "P10.21-A: AUTHZ-HOST-011 must reject StatsFieldDescriptor referencing a VALUE+DENY (SECRET) attribute"
                    );
                    assertTrue(
                            host011And012Report.errors().stream()
                                    .anyMatch(i -> "AUTHZ-HOST-012-VALUE-DENIED-FILTERABLE-FIELD".equals(i.ruleCode())),
                            "P10.21-A: AUTHZ-HOST-012 must reject @Filterable property referencing a VALUE+DENY (SECRET) attribute"
                    );

                    // 31b. P10.21-B: simulateTwoPhaseBulkProposalAndConfirm (preview masking, anti-confused-deputy, policy digest continuity)
                    java.util.function.Function<P102AfastamentoJpaEntity, AfastamentoAnnotatedResponseDTO> rawSimDtoMapper =
                            e -> new AfastamentoAnnotatedResponseDTO(
                                    e.id, e.tenantId, e.cedenteOrgaoId, e.cessionarioOrgaoId,
                                    e.lotacaoSetorId, e.statusAfastamento, e.substitutoServidorId, e.cidCodigo
                            );
                    simulationHarness.simulateTwoPhaseBulkProposalAndConfirm(
                            pureCedenteCaller,
                            pureCedenteCaller,
                            "digest-v1",
                            "digest-v1",
                            List.of(simEntity101),
                            e -> e.id,
                            rawSimDtoMapper,
                            new AfastamentoAnnotatedUpdateDTO(null, "J12"),
                            org.praxisplatform.authz.contracts.binding.BatchAuthorizationMode.REJECT_ALL
                    )
                            .assertProposalAndConfirmAllowed()
                            .assertProposalPreview(101L, preview ->
                                    preview.allowed() && "***CID-RESTRITO***".equals(preview.maskedResponse().cidCodigo())
                            );

                    AuthzCallerContext otherPrincipalCaller = AuthzCallerContext.of(
                            "tenant-gov-br",
                            Map.of(
                                    "subject.principalId", "usr-outro-gestor-999",
                                    "subject.organizationUnitIds", List.of(100L),
                                    "subject.cedenteOrgaoIds", List.of(1L),
                                    "subject.cessionarioOrgaoIds", List.of()
                            ),
                            true,
                            false
                    );
                    simulationHarness.simulateTwoPhaseBulkProposalAndConfirm(
                            pureCedenteCaller,
                            otherPrincipalCaller,
                            "digest-v1",
                            "digest-v1",
                            List.of(simEntity101),
                            e -> e.id,
                            rawSimDtoMapper,
                            new AfastamentoAnnotatedUpdateDTO(null, "J12"),
                            org.praxisplatform.authz.contracts.binding.BatchAuthorizationMode.REJECT_ALL
                    )
                            .assertConfirmDenied("AUTHZ_BULK_CONFUSED_DEPUTY_DENIED");

                    simulationHarness.simulateTwoPhaseBulkProposalAndConfirm(
                            pureCedenteCaller,
                            pureCedenteCaller,
                            "digest-v1",
                            "digest-v2-rotated",
                            List.of(simEntity101),
                            e -> e.id,
                            rawSimDtoMapper,
                            new AfastamentoAnnotatedUpdateDTO(null, "J12"),
                            org.praxisplatform.authz.contracts.binding.BatchAuthorizationMode.REJECT_ALL
                    )
                            .assertConfirmDenied("AUTHZ_BULK_POLICY_REVOKED_OR_ROTATED");

                    // 31c. P10.21-B: simulateHeaderSpoofingGuard (UntrustedRequestHeaderGuard)
                    AuthzCallerContext cleanHeadersCaller = new AuthzCallerContext(
                            "tenant-gov-br",
                            pureCedenteCaller.subjectAndEnvironmentFacts(),
                            Map.of(),
                            Set.of("Authorization", "Accept", "X-Request-Id"),
                            Map.of(),
                            true,
                            false
                    );
                    simulationHarness.simulateHeaderSpoofingGuard(cleanHeadersCaller)
                            .assertAllowed();

                    AuthzCallerContext spoofedHeadersCaller = new AuthzCallerContext(
                            "tenant-gov-br",
                            pureCedenteCaller.subjectAndEnvironmentFacts(),
                            Map.of(),
                            Set.of("Authorization", "X-Praxis-Authz-Roles"),
                            Map.of(),
                            true,
                            false
                    );
                    simulationHarness.simulateHeaderSpoofingGuard(spoofedHeadersCaller)
                            .assertSpoofingRejected("X-Praxis-Authz-Roles");

                    // 31d. MatrixRunner verification for P10.21-B
                    simulationHarness.matrix()
                            .expectTwoPhaseBulkConfirm(
                                    "Bulk 2 fases válido para mesmo principal e mesmo digest",
                                    pureCedenteCaller,
                                    pureCedenteCaller,
                                    "digest-v1",
                                    "digest-v1",
                                    List.of(simEntity101),
                                    e -> e.id,
                                    rawSimDtoMapper,
                                    new AfastamentoAnnotatedUpdateDTO(null, "J12"),
                                    org.praxisplatform.authz.contracts.binding.BatchAuthorizationMode.REJECT_ALL,
                                    true,
                                    null
                            )
                            .expectTwoPhaseBulkConfirm(
                                    "Bulk 2 fases bloqueia Confused Deputy",
                                    pureCedenteCaller,
                                    otherPrincipalCaller,
                                    "digest-v1",
                                    "digest-v1",
                                    List.of(simEntity101),
                                    e -> e.id,
                                    rawSimDtoMapper,
                                    new AfastamentoAnnotatedUpdateDTO(null, "J12"),
                                    org.praxisplatform.authz.contracts.binding.BatchAuthorizationMode.REJECT_ALL,
                                    false,
                                    "AUTHZ_BULK_CONFUSED_DEPUTY_DENIED"
                            )
                            .expectBulkPerItemUpdateCohort(
                                    "Bulk PER_ITEM_UPDATE cohort admite item 101 e rejeita item 102 para Cedente",
                                    pureCedenteCaller,
                                    List.of(simEntity101, simEntity102),
                                    e -> e.id,
                                    Map.of(
                                            101L, new AfastamentoAnnotatedUpdateDTO(null, "J13"),
                                            102L, new AfastamentoAnnotatedUpdateDTO(null, "J13")
                                    ),
                                    org.praxisplatform.authz.contracts.binding.BatchAuthorizationMode.PER_ITEM,
                                    false,
                                    Set.of(101L)
                            )
                            .expectTwoPhaseBulkConfirm(
                                    "Bulk 2 fases bloqueia confirmação com header forjado X-Praxis-Authz-Roles",
                                    pureCedenteCaller,
                                    spoofedHeadersCaller,
                                    "digest-v1",
                                    "digest-v1",
                                    List.of(simEntity101),
                                    e -> e.id,
                                    rawSimDtoMapper,
                                    new AfastamentoAnnotatedUpdateDTO(null, "J12"),
                                    org.praxisplatform.authz.contracts.binding.BatchAuthorizationMode.REJECT_ALL,
                                    false,
                                    "UNTRUSTED_AUTHORITY_HEADER_SPOOFING"
                            )
                            .expectHeaderSpoofingGuard(
                                    "Headers padrão permitidos",
                                    cleanHeadersCaller,
                                    true,
                                    null
                            )
                            .expectHeaderSpoofingGuard(
                                    "Header X-Praxis-Authz-Roles bloqueado",
                                    spoofedHeadersCaller,
                                    false,
                                    "X-Praxis-Authz-Roles"
                            )
                            .verifyAll();

                    simulationHarness.simulateTwoPhaseBulkPerItemProposalAndConfirm(
                            pureCedenteCaller,
                            pureCedenteCaller,
                            "digest-v1",
                            "digest-v1",
                            List.of(simEntity101, simEntity102),
                            e -> e.id,
                            rawSimDtoMapper,
                            Map.of(
                                    101L, new AfastamentoAnnotatedUpdateDTO(null, "J13"),
                                    102L, new AfastamentoAnnotatedUpdateDTO(null, "J13")
                            ),
                            org.praxisplatform.authz.contracts.binding.BatchAuthorizationMode.PER_ITEM
                    )
                            .assertConfirmAllowed(Set.of(101L));

                    // =========================================================================
                    // 32. Fase P10.22: AUTHZ-HOST-013 (CollectionExportField allowlist audit),
                    //     simulateFilteredExportFields, simulateDraftReactiveDetermination,
                    //     and MatrixRunner (expectSurfaceRead / expectReactiveDetermination /
                    //     expectDraftReactiveDetermination)
                    // =========================================================================
                    List<org.praxisplatform.uischema.exporting.CollectionExportField> invalidExportFields = List.of(
                            new org.praxisplatform.uischema.exporting.CollectionExportField(
                                    "statusAfastamento", "Status", true, true, "String", "statusAfastamento", null, null
                            ),
                            new org.praxisplatform.uischema.exporting.CollectionExportField(
                                    "orgCedenteId", "Órgão Cedente", true, true, "Long", "orgCedenteId", null, null
                            ),
                            new org.praxisplatform.uischema.exporting.CollectionExportField(
                                    "webhookToken", "Token", true, true, "String", "webhookToken", null, null
                            ),
                            new org.praxisplatform.uischema.exporting.CollectionExportField(
                                    "campoFantasma", "Fantasma", true, true, "String", "campoInexistenteDto", null, null
                            )
                    );
                    var p1022Report = readinessReviewer.reviewGovernanceSpec(
                            selfContainedSpec,
                            P102AfastamentoJpaEntity.class,
                            SecretTokenAfastamentoResponseDTO.class,
                            AfastamentoFilterDTO.class,
                            null,
                            null,
                            null,
                            invalidExportFields
                    );
                    assertFalse(p1022Report.isReady());
                    assertTrue(
                            p1022Report.issues().stream()
                                    .anyMatch(i -> "AUTHZ-HOST-013-INVALID-EXPORT-FIELD-PATH".equals(i.ruleCode())),
                            "P10.22-A: AUTHZ-HOST-013 must reject CollectionExportField referencing non-existent DTO path"
                    );
                    assertTrue(
                            p1022Report.issues().stream()
                                    .anyMatch(i -> "AUTHZ-HOST-013-NON-EXPORTABLE-FIELD-IN-EXPORT-ALLOWLIST".equals(i.ruleCode())),
                            "P10.22-A: AUTHZ-HOST-013 must flag non-exportable field in raw export allowlist"
                    );
                    assertTrue(
                            p1022Report.issues().stream()
                                    .anyMatch(i -> "AUTHZ-HOST-013-VALUE-DENIED-EXPORT-FIELD".equals(i.ruleCode())),
                            "P10.22-A: AUTHZ-HOST-013 must reject VALUE+DENY (SECRET) field in raw export allowlist"
                    );

                    List<org.praxisplatform.uischema.exporting.CollectionExportField> filteredExportFields =
                            simulationHarness.simulateFilteredExportFields(List.of(
                                    new org.praxisplatform.uischema.exporting.CollectionExportField(
                                            "statusAfastamento", "Status", true, true, "String", "statusAfastamento", null, null
                                    ),
                                    new org.praxisplatform.uischema.exporting.CollectionExportField(
                                            "cidCodigo", "CID", true, true, "String", "cidCodigo", null, null
                                    )
                            ));
                    assertEquals(
                            List.of("statusAfastamento"),
                            filteredExportFields.stream()
                                    .map(org.praxisplatform.uischema.exporting.CollectionExportField::key)
                                    .toList()
                    );

                    simulationHarness.simulateDraftReactiveDetermination(
                            pureCedenteCaller,
                            Map.of("lotacaoSetorId", 100L, "statusAfastamento", "HOMOLOGADO"),
                            Map.of("statusAfastamento", "HOMOLOGADO", "cidCodigo", "J11")
                    )
                            .assertAllowed()
                            .assertKeyPresentWithValue("statusAfastamento", "HOMOLOGADO")
                            .assertAttributeMasked("ergon.afastamentos.cid_codigo");

                    simulationHarness.simulateDraftReactiveDetermination(
                            spoofedHeadersCaller,
                            Map.of("lotacaoSetorId", 100L, "statusAfastamento", "HOMOLOGADO"),
                            Map.of("statusAfastamento", "HOMOLOGADO")
                    )
                            .assertDenied("UNTRUSTED_AUTHORITY_HEADER_SPOOFING");

                    simulationHarness.matrix()
                            .expectSurfaceRead(
                                    "Surface detail mascara cidCodigo para Cedente",
                                    pureCedenteCaller,
                                    "detail",
                                    simEntity101,
                                    rawSimDtoMapper.apply(simEntity101),
                                    true,
                                    Set.of("ergon.afastamentos.cid_codigo")
                            )
                            .expectReactiveDetermination(
                                    "ReactiveDetermination item mascara cidCodigo",
                                    pureCedenteCaller,
                                    "reactive-determination",
                                    simEntity101,
                                    Map.of("statusAfastamento", "HOMOLOGADO", "cidCodigo", "J11"),
                                    true,
                                    Set.of("ergon.afastamentos.cid_codigo")
                            )
                            .expectDraftReactiveDetermination(
                                    "DraftReactiveDetermination mascara cidCodigo",
                                    pureCedenteCaller,
                                    "reactive-determination",
                                    Map.of("lotacaoSetorId", 100L, "statusAfastamento", "HOMOLOGADO"),
                                    Map.of("statusAfastamento", "HOMOLOGADO", "cidCodigo", "J11"),
                                    true,
                                    Set.of("ergon.afastamentos.cid_codigo")
                            )
                            .verifyAll();

                    // =========================================================================
                    // 33. Fase P10.23: AUTHZ-HOST-014 (OptionSourceRegistry & EntityLookupDescriptor audit),
                    //     simulateCursorFilter, and MatrixRunner (expectCollectionExport /
                    //     expectOptionSource / expectCursorFilter)
                    // =========================================================================
                    EntityLookupDescriptor brokenAndSecretLookup = new EntityLookupDescriptor(
                            blueprint.resourceKey(),
                            "id",
                            List.of("statusAfastamento", "webhookToken", "caminhoInexistenteLookup"),
                            "statusAfastamento",
                            null,
                            null,
                            List.of("statusAfastamento"),
                            Map.of(),
                            new LookupSelectionPolicy(
                                    null,
                                    "statusFantasmaInexistente",
                                    List.of("DEFERIDO"),
                                    List.of("REVOGADO"),
                                    true,
                                    "Inativo",
                                    "Inválido"
                            ),
                            LookupCapabilities.standardDirectory(),
                            null
                    );
                    OptionSourceRegistry brokenAndSecretOptionRegistry = OptionSourceRegistry.builder()
                            .add(
                                    P102AfastamentoJpaEntity.class,
                                    new OptionSourceDescriptor(
                                            "afastamentoSecretLookup",
                                            OptionSourceType.RESOURCE_ENTITY,
                                            "/api/human-resources/afastamentos",
                                            "afastamentoId",
                                            "id",
                                            "statusAfastamento",
                                            "id",
                                            List.of(),
                                            Map.of(),
                                            OptionSourcePolicy.defaults(),
                                            brokenAndSecretLookup
                                    )
                            )
                            .build();
                    var p1023Report = readinessReviewer.reviewGovernanceSpec(
                            selfContainedSpec,
                            P102AfastamentoJpaEntity.class,
                            SecretTokenAfastamentoResponseDTO.class,
                            AfastamentoFilterDTO.class,
                            null,
                            null,
                            null,
                            null,
                            brokenAndSecretOptionRegistry
                    );
                    assertFalse(p1023Report.isReady());
                    assertTrue(
                            p1023Report.errors().stream()
                                    .anyMatch(i -> "AUTHZ-HOST-014-INVALID-OPTION-SOURCE-PATH".equals(i.ruleCode())),
                            "P10.23-A: AUTHZ-HOST-014 must reject OptionSource/EntityLookupDescriptor referencing non-existent property path"
                    );
                    assertTrue(
                            p1023Report.errors().stream()
                                    .anyMatch(i -> "AUTHZ-HOST-014-VALUE-DENIED-OPTION-SOURCE-FIELD".equals(i.ruleCode())),
                            "P10.23-A: AUTHZ-HOST-014 must reject OptionSource/EntityLookupDescriptor exposing a VALUE+DENY (SECRET) attribute"
                    );

                    simulationHarness.simulateCursorFilter(
                            pureCedenteCaller,
                            List.of(simEntity101, simEntity102),
                            e -> e.id,
                            rawSimDtoMapper,
                            null,
                            1
                    )
                            .assertAllowedIds(List.of(101L))
                            .assertItem(0, item -> "***CID-RESTRITO***".equals(item.cidCodigo()));

                    simulationHarness.simulateCursorFilter(
                            pureCedenteCaller,
                            List.of(simEntity101, simEntity102),
                            e -> e.id,
                            rawSimDtoMapper,
                            null,
                            Set.of("cidCodigo"),
                            null,
                            null,
                            10
                    )
                            .assertDenied(FieldUseCategory.SORT, "ergon.afastamentos.cid_codigo");

                    simulationHarness.simulateCursorFilter(
                            spoofedHeadersCaller,
                            List.of(simEntity101),
                            e -> e.id,
                            rawSimDtoMapper,
                            null,
                            10
                    )
                            .assertDeniedReason("UNTRUSTED_AUTHORITY_HEADER_SPOOFING");

                    simulationHarness.matrix()
                            .expectCollectionExport(
                                    "CollectionExport exporta apenas item 101 e exclui orgCedenteId e cidCodigo",
                                    pureCedenteCaller,
                                    List.of(simEntity101, simEntity102),
                                    rawSimDtoMapper,
                                    1,
                                    Set.of("orgCedenteId", "cidCodigo")
                            )
                            .expectOptionSource(
                                    "OptionSource admite apenas item 101 em escopo",
                                    pureCedenteCaller,
                                    List.of(simEntity101, simEntity102),
                                    e -> new OptionDTO<>(e.id, e.statusAfastamento, Map.of("cidCodigo", e.cidCodigo)),
                                    null,
                                    org.praxisplatform.uischema.options.service.OptionSourceOperation.FILTER,
                                    List.of(),
                                    Set.of(101L)
                            )
                            .expectCursorFilter(
                                    "CursorFilter retorna item 101 em escopo",
                                    pureCedenteCaller,
                                    List.of(simEntity101, simEntity102),
                                    e -> e.id,
                                    rawSimDtoMapper,
                                    null,
                                    Set.of("statusAfastamento"),
                                    null,
                                    null,
                                    10,
                                    true,
                                    List.of(101L)
                            )
                            .expectCursorFilter(
                                    "CursorFilter bloqueia ordenação por cidCodigo",
                                    pureCedenteCaller,
                                    List.of(simEntity101, simEntity102),
                                    e -> e.id,
                                    rawSimDtoMapper,
                                    null,
                                    Set.of("cidCodigo"),
                                    null,
                                    null,
                                    10,
                                    false,
                                    List.of()
                            )
                            .verifyAll();

                    // =========================================================================
                    // 34. Fase P10.24: AUTHZ-HOST-014 (LookupFilteringDescriptor & dependencyFilterMap),
                    //     simulateLocate, simulateFindAllById, and MatrixRunner (expectLocate / expectFindAllById)
                    // =========================================================================
                    org.praxisplatform.uischema.options.LookupFilteringDescriptor brokenFilteringDescriptor =
                            new org.praxisplatform.uischema.options.LookupFilteringDescriptor(
                                    List.of(
                                            new org.praxisplatform.uischema.options.LookupFilterDefinition(
                                                    "webhookToken",
                                                    "Token",
                                                    "text",
                                                    List.of("equals"),
                                                    "equals",
                                                    null,
                                                    false,
                                                    false
                                            )
                                    ),
                                    Map.of(),
                                    List.of(
                                            new org.praxisplatform.uischema.options.LookupSortOption(
                                                    "sortFantasma",
                                                    "campoSortInexistente",
                                                    "asc",
                                                    "Fantasma"
                                            )
                                    ),
                                    "sortFantasma",
                                    List.of("statusAfastamento"),
                                    "Buscar..."
                            );
                    OptionSourceRegistry brokenFilteringOptionRegistry = OptionSourceRegistry.builder()
                            .add(
                                    P102AfastamentoJpaEntity.class,
                                    new OptionSourceDescriptor(
                                            "afastamentoFilteringLookup",
                                            OptionSourceType.RESOURCE_ENTITY,
                                            "/api/human-resources/afastamentos",
                                            "afastamentoId",
                                            "id",
                                            "statusAfastamento",
                                            "id",
                                            List.of("orgParent"),
                                            Map.of("orgParent", "filtroDependenteInexistente"),
                                            OptionSourcePolicy.defaults(),
                                            null,
                                            brokenFilteringDescriptor,
                                            org.praxisplatform.uischema.options.OptionSourceExecutionMode.JPA
                                    )
                            )
                            .build();
                    var p1024Report = readinessReviewer.reviewGovernanceSpec(
                            selfContainedSpec,
                            P102AfastamentoJpaEntity.class,
                            SecretTokenAfastamentoResponseDTO.class,
                            AfastamentoFilterDTO.class,
                            null,
                            null,
                            null,
                            null,
                            brokenFilteringOptionRegistry
                    );
                    assertFalse(p1024Report.isReady());
                    assertTrue(
                            p1024Report.errors().stream()
                                    .anyMatch(i -> "AUTHZ-HOST-014-INVALID-OPTION-SOURCE-PATH".equals(i.ruleCode())
                                            && i.targetElement().contains("dependencyFilterMap[orgParent]")),
                            "P10.24-A: AUTHZ-HOST-014 must reject invalid dependencyFilterMap target field"
                    );
                    assertTrue(
                            p1024Report.errors().stream()
                                    .anyMatch(i -> "AUTHZ-HOST-014-INVALID-OPTION-SOURCE-PATH".equals(i.ruleCode())
                                            && i.targetElement().contains("sortOptions[campoSortInexistente]")),
                            "P10.24-A: AUTHZ-HOST-014 must reject invalid LookupFilteringDescriptor sortOption field"
                    );
                    assertTrue(
                            p1024Report.errors().stream()
                                    .anyMatch(i -> "AUTHZ-HOST-014-VALUE-DENIED-OPTION-SOURCE-FIELD".equals(i.ruleCode())
                                            && i.targetElement().contains("availableFilters[webhookToken]")),
                            "P10.24-A: AUTHZ-HOST-014 must reject VALUE+DENY (SECRET) field in LookupFilteringDescriptor.availableFilters"
                    );

                    simulationHarness.simulateLocate(
                            pureCedenteCaller,
                            List.of(simEntity101, simEntity102),
                            e -> e.id,
                            rawSimDtoMapper,
                            101L
                    )
                            .assertLocatedAt(0L);

                    simulationHarness.simulateLocate(
                            pureCedenteCaller,
                            List.of(simEntity101, simEntity102),
                            e -> e.id,
                            rawSimDtoMapper,
                            102L
                    )
                            .assertNotFoundOrOutOfScope();

                    simulationHarness.simulateLocate(
                            pureCedenteCaller,
                            List.of(simEntity101, simEntity102),
                            e -> e.id,
                            rawSimDtoMapper,
                            null,
                            Set.of("cidCodigo"),
                            101L
                    )
                            .assertDenied(FieldUseCategory.SORT, "ergon.afastamentos.cid_codigo");

                    simulationHarness.simulateFindAllById(
                            pureCedenteCaller,
                            List.of(simEntity101, simEntity102),
                            e -> e.id,
                            rawSimDtoMapper,
                            List.of(102L, 101L, 999L)
                    )
                            .assertAllowedIds(List.of(101L))
                            .assertItem(0, item -> "***CID-RESTRITO***".equals(item.cidCodigo()));

                    simulationHarness.matrix()
                            .expectLocate(
                                    "Locate encontra item 101 no índice 0",
                                    pureCedenteCaller,
                                    List.of(simEntity101, simEntity102),
                                    e -> e.id,
                                    rawSimDtoMapper,
                                    null,
                                    Set.of("statusAfastamento"),
                                    101L,
                                    true,
                                    java.util.OptionalLong.of(0L)
                            )
                            .expectLocate(
                                    "Locate omite item 102 fora de escopo com OptionalLong.empty()",
                                    pureCedenteCaller,
                                    List.of(simEntity101, simEntity102),
                                    e -> e.id,
                                    rawSimDtoMapper,
                                    null,
                                    Set.of("statusAfastamento"),
                                    102L,
                                    true,
                                    java.util.OptionalLong.empty()
                            )
                            .expectFindAllById(
                                    "FindAllById retorna apenas item 101 autorizado na ordem solicitada",
                                    pureCedenteCaller,
                                    List.of(simEntity101, simEntity102),
                                    e -> e.id,
                                    rawSimDtoMapper,
                                    List.of(102L, 101L),
                                    true,
                                    List.of(101L)
                            )
                            .verifyAll();

                    // =========================================================================
                    // 35. Fase P10.25: AUTHZ-HOST-014-RESTRICTED-OPTION-SOURCE-QUERY-FIELD,
                    //     LookupFilteringDescriptor.defaultFilters audit, symbolic sortKey &
                    //     search guard in OptionSource simulation and MatrixRunner
                    // =========================================================================
                    org.praxisplatform.uischema.options.LookupFilteringDescriptor restrictedQueryFilteringDescriptor =
                            new org.praxisplatform.uischema.options.LookupFilteringDescriptor(
                                    List.of(),
                                    Map.of("defaultFiltroFantasma", "X"),
                                    List.of(
                                            new org.praxisplatform.uischema.options.LookupSortOption(
                                                    "porCidSimbolico",
                                                    "cidCodigo",
                                                    "asc",
                                                    "Por CID"
                                            )
                                    ),
                                    "porCidSimbolico",
                                    List.of("cidCodigo"),
                                    "Buscar..."
                            );
                    OptionSourceDescriptor restrictedQueryOptionDescriptor = new OptionSourceDescriptor(
                            "afastamentoRestrictedQueryLookup",
                            OptionSourceType.RESOURCE_ENTITY,
                            "/api/human-resources/afastamentos",
                            "afastamentoId",
                            "id",
                            "statusAfastamento",
                            "id",
                            List.of(),
                            Map.of(),
                            OptionSourcePolicy.defaults(),
                            null,
                            restrictedQueryFilteringDescriptor,
                            org.praxisplatform.uischema.options.OptionSourceExecutionMode.JPA
                    );
                    OptionSourceRegistry restrictedQueryOptionRegistry = OptionSourceRegistry.builder()
                            .add(P102AfastamentoJpaEntity.class, restrictedQueryOptionDescriptor)
                            .build();
                    var p1025Report = readinessReviewer.reviewGovernanceSpec(
                            selfContainedSpec,
                            P102AfastamentoJpaEntity.class,
                            AfastamentoAnnotatedResponseDTO.class,
                            AfastamentoFilterDTO.class,
                            null,
                            null,
                            null,
                            null,
                            restrictedQueryOptionRegistry
                    );
                    assertFalse(p1025Report.isReady());
                    assertTrue(
                            p1025Report.errors().stream()
                                    .anyMatch(i -> "AUTHZ-HOST-014-INVALID-OPTION-SOURCE-PATH".equals(i.ruleCode())
                                            && i.targetElement().contains("defaultFilters[defaultFiltroFantasma]")),
                            "P10.25-A: AUTHZ-HOST-014 must reject invalid defaultFilters key in LookupFilteringDescriptor"
                    );
                    assertTrue(
                            p1025Report.errors().stream()
                                    .anyMatch(i -> "AUTHZ-HOST-014-RESTRICTED-OPTION-SOURCE-QUERY-FIELD".equals(i.ruleCode())
                                            && i.targetElement().contains("sortOptions[cidCodigo]")),
                            "P10.25-A: AUTHZ-HOST-014 must reject LGPD_SENSITIVE_DATA (SORT+DENY) field in LookupFilteringDescriptor.sortOptions"
                    );
                    assertTrue(
                            p1025Report.errors().stream()
                                    .anyMatch(i -> "AUTHZ-HOST-014-RESTRICTED-OPTION-SOURCE-QUERY-FIELD".equals(i.ruleCode())
                                            && i.targetElement().contains("quickFilterFields(cidCodigo)")),
                            "P10.25-A: AUTHZ-HOST-014 must reject LGPD_SENSITIVE_DATA (FILTER+DENY) field in LookupFilteringDescriptor.quickFilterFields"
                    );

                    simulationHarness.simulateOptionSource(
                            pureCedenteCaller,
                            List.of(simEntity101, simEntity102),
                            e -> new OptionDTO<>(e.id, e.statusAfastamento, Map.of("cidCodigo", e.cidCodigo)),
                            restrictedQueryOptionDescriptor,
                            org.praxisplatform.uischema.options.service.OptionSourceOperation.FILTER,
                            List.of(),
                            List.of(),
                            "porCidSimbolico",
                            null
                    )
                            .assertDenied(FieldUseCategory.SORT, "ergon.afastamentos.cid_codigo");

                    simulationHarness.simulateOptionSource(
                            pureCedenteCaller,
                            List.of(simEntity101, simEntity102),
                            e -> new OptionDTO<>(e.id, e.statusAfastamento, Map.of("cidCodigo", e.cidCodigo)),
                            restrictedQueryOptionDescriptor,
                            org.praxisplatform.uischema.options.service.OptionSourceOperation.FILTER,
                            List.of(),
                            List.of(),
                            "statusAfastamento:asc",
                            "J11"
                    )
                            .assertDenied(FieldUseCategory.FILTER, "ergon.afastamentos.cid_codigo");

                    simulationHarness.matrix()
                            .expectOptionSource(
                                    "OptionSource bloqueia sortKey simbólico porCidSimbolico mapeado para cidCodigo",
                                    pureCedenteCaller,
                                    List.of(simEntity101, simEntity102),
                                    e -> new OptionDTO<>(e.id, e.statusAfastamento, Map.of()),
                                    restrictedQueryOptionDescriptor,
                                    org.praxisplatform.uischema.options.service.OptionSourceOperation.FILTER,
                                    List.of(),
                                    List.of(),
                                    "porCidSimbolico",
                                    null,
                                    false,
                                    Set.of()
                            )
                            .expectOptionSource(
                                    "OptionSource permite sortKey por statusAfastamento",
                                    pureCedenteCaller,
                                    List.of(simEntity101, simEntity102),
                                    e -> new OptionDTO<>(e.id, e.statusAfastamento, Map.of()),
                                    restrictedQueryOptionDescriptor,
                                    org.praxisplatform.uischema.options.service.OptionSourceOperation.FILTER,
                                    List.of(),
                                    List.of(),
                                    "statusAfastamento:asc",
                                    null,
                                    true,
                                    Set.of(101L)
                            )
                            .verifyAll();

                    // =========================================================================
                    // 36. Fase P10.26: AUTHZ-HOST-014-INVALID-OPTION-SOURCE-DEFAULT-SORT,
                    //     searchable labelPropertyPath audit & runtime/simulation fallback,
                    //     implicit defaultSort & symbolic "label"/"id" sort guard, and
                    //     uniform header anti-spoofing across analytics/export/determinations/AI
                    // =========================================================================
                    org.praxisplatform.uischema.options.LookupFilteringDescriptor validStatusSortFiltering =
                            new org.praxisplatform.uischema.options.LookupFilteringDescriptor(
                                    List.of(),
                                    Map.of(),
                                    List.of(
                                            new org.praxisplatform.uischema.options.LookupSortOption(
                                                    "porStatus",
                                                    "statusAfastamento",
                                                    "asc",
                                                    "Por Status"
                                            )
                                    ),
                                    "porStatus",
                                    List.of(),
                                    "Buscar..."
                            );
                    OptionSourceDescriptor searchableRestrictedLabelDescriptor = new OptionSourceDescriptor(
                            "afastamentoCidLabelSearchableLookup",
                            OptionSourceType.LIGHT_LOOKUP,
                            "/api/human-resources/afastamentos",
                            "afastamentoId",
                            "cidCodigo",
                            "cidCodigo",
                            "id",
                            List.of(),
                            Map.of(),
                            new OptionSourcePolicy(
                                    false,
                                    true,
                                    "contains",
                                    0,
                                    25,
                                    100,
                                    true,
                                    false,
                                    "chaveDefaultSortInexistente"
                            ),
                            null,
                            validStatusSortFiltering,
                            org.praxisplatform.uischema.options.OptionSourceExecutionMode.JPA
                    );
                    OptionSourceRegistry p1026OptionRegistry = OptionSourceRegistry.builder()
                            .add(P102AfastamentoJpaEntity.class, searchableRestrictedLabelDescriptor)
                            .build();
                    var p1026Report = readinessReviewer.reviewGovernanceSpec(
                            selfContainedSpec,
                            P102AfastamentoJpaEntity.class,
                            AfastamentoAnnotatedResponseDTO.class,
                            AfastamentoFilterDTO.class,
                            null,
                            null,
                            null,
                            null,
                            p1026OptionRegistry
                    );
                    assertFalse(p1026Report.isReady());
                    assertTrue(
                            p1026Report.errors().stream()
                                    .anyMatch(i -> "AUTHZ-HOST-014-INVALID-OPTION-SOURCE-DEFAULT-SORT".equals(i.ruleCode())
                                            && i.targetElement().contains("defaultSort(chaveDefaultSortInexistente)")),
                            "P10.26-A: AUTHZ-HOST-014 must reject orphan defaultSort not matching any sortOptions key"
                    );
                    assertTrue(
                            p1026Report.errors().stream()
                                    .anyMatch(i -> "AUTHZ-HOST-014-RESTRICTED-OPTION-SOURCE-QUERY-FIELD".equals(i.ruleCode())
                                            && i.targetElement().contains("labelPropertyPath(cidCodigo)")),
                            "P10.26-A: AUTHZ-HOST-014 must reject searchable labelPropertyPath pointing to FILTER+DENY field when searchPropertyPaths is empty"
                    );

                    // P10.26-B: Search fallback to labelPropertyPath (cidCodigo) blocks search="J11" even when searchPropertyPaths/quickFilterFields are empty
                    simulationHarness.simulateOptionSource(
                            pureCedenteCaller,
                            List.of(simEntity101, simEntity102),
                            e -> new OptionDTO<>(e.id, e.cidCodigo, Map.of()),
                            searchableRestrictedLabelDescriptor,
                            org.praxisplatform.uischema.options.service.OptionSourceOperation.FILTER,
                            List.of(),
                            List.of(),
                            "porStatus",
                            "J11"
                    )
                            .assertDenied(FieldUseCategory.FILTER, "ergon.afastamentos.cid_codigo");

                    // P10.26-B: Symbolic sortKey="label" translates to labelPropertyPath (cidCodigo) and blocks SORT
                    simulationHarness.simulateOptionSource(
                            pureCedenteCaller,
                            List.of(simEntity101, simEntity102),
                            e -> new OptionDTO<>(e.id, e.cidCodigo, Map.of()),
                            searchableRestrictedLabelDescriptor,
                            org.praxisplatform.uischema.options.service.OptionSourceOperation.FILTER,
                            List.of(),
                            List.of(),
                            "label:asc",
                            null
                    )
                            .assertDenied(FieldUseCategory.SORT, "ergon.afastamentos.cid_codigo");

                    // P10.26-B: Implicit defaultSort ("porCidSimbolico" -> "cidCodigo") blocks FILTER operation when sortKey is null
                    simulationHarness.simulateOptionSource(
                            pureCedenteCaller,
                            List.of(simEntity101, simEntity102),
                            e -> new OptionDTO<>(e.id, e.statusAfastamento, Map.of()),
                            restrictedQueryOptionDescriptor,
                            org.praxisplatform.uischema.options.service.OptionSourceOperation.FILTER,
                            List.of(),
                            List.of(),
                            null,
                            null
                    )
                            .assertDenied(FieldUseCategory.SORT, "ergon.afastamentos.cid_codigo");

                    // P10.26-B: Uniform header anti-spoofing across Analytics, CollectionExport, ReactiveDetermination, and AiContextProjection
                    assertEquals(
                            "UNTRUSTED_AUTHORITY_HEADER_SPOOFING",
                            simulationHarness.simulateGroupByStats(spoofedHeadersCaller, "statusAfastamento", Set.of()).denialReason()
                    );
                    assertEquals(
                            "UNTRUSTED_AUTHORITY_HEADER_SPOOFING",
                            simulationHarness.simulateCollectionExport(spoofedHeadersCaller, List.of(simEntity101), rawSimDtoMapper).denialReason()
                    );
                    assertEquals(
                            "UNTRUSTED_AUTHORITY_HEADER_SPOOFING",
                            simulationHarness.simulateReactiveDetermination(spoofedHeadersCaller, simEntity101, Map.of("statusAfastamento", "DEFERIDO")).denialReason()
                    );
                    assertEquals(
                            "UNTRUSTED_AUTHORITY_HEADER_SPOOFING",
                            simulationHarness.simulateAiContextProjection(spoofedHeadersCaller, simEntity101, rawSimDtoMapper.apply(simEntity101)).denialReason()
                    );
                });

        emfBean.destroy();
    }

    static final class ConciseAfastamentoRadarReadOnlyService extends AbstractAuthzGovernedReadOnlyResourceService<
            P102AfastamentoJpaEntity,
            AfastamentoAnnotatedResponseDTO,
            Long,
            AfastamentoFilterDTO> {

        private final AfastamentoAuthzPilotBlueprint blueprint;
        private final EntityManager em;

        ConciseAfastamentoRadarReadOnlyService(
                BaseCrudRepository<P102AfastamentoJpaEntity, Long> repository,
                AuthzGovernedResourceServiceSupport serviceSupport,
                AfastamentoAuthzPilotBlueprint blueprint,
                JpaDataScopeAdapter jpaAdapter,
                JpaCriteriaDataScopeTranslator criteriaTranslator,
                EntityManager em
        ) {
            super(
                    repository,
                    P102AfastamentoJpaEntity.class,
                    AfastamentoAnnotatedResponseDTO.class,
                    serviceSupport,
                    blueprint.decisionPoint(),
                    blueprint.factContract().factContractDigest(),
                    jpaAdapter,
                    criteriaTranslator
            );
            this.blueprint = blueprint;
            this.em = em;
        }

        @Override
        protected String resolveResourceKey() {
            return blueprint.resourceKey();
        }

        @Override
        public EntityManager getEntityManager() {
            return em;
        }

        @Override
        protected ResourceMapper<P102AfastamentoJpaEntity, AfastamentoAnnotatedResponseDTO, ?, ?, Long> getRawResourceMapper() {
            return new ResourceMapper<P102AfastamentoJpaEntity, AfastamentoAnnotatedResponseDTO, Object, Object, Long>() {
                @Override
                public AfastamentoAnnotatedResponseDTO toResponse(P102AfastamentoJpaEntity e) {
                    return new AfastamentoAnnotatedResponseDTO(
                            e.id, e.tenantId, e.cedenteOrgaoId, e.cessionarioOrgaoId,
                            e.lotacaoSetorId, e.statusAfastamento, e.substitutoServidorId, e.cidCodigo
                    );
                }

                @Override
                public P102AfastamentoJpaEntity newEntity(Object dto) {
                    throw new UnsupportedOperationException();
                }

                @Override
                public void applyUpdate(P102AfastamentoJpaEntity entity, Object dto) {
                    throw new UnsupportedOperationException();
                }

                @Override
                public Long extractId(P102AfastamentoJpaEntity e) {
                    return e.id;
                }
            };
        }

        @Override
        protected Map<String, Object> resolveSubjectAndEnvironmentFacts() {
            return Map.of(
                    "subject.principalId", "usr-gestor-101",
                    "subject.organizationUnitIds", List.of(100L)
            );
        }

        @Override
        protected ResourceFilterAccessScope<P102AfastamentoJpaEntity> resolveHardScope() {
            return ResourceFilterAccessScope.restricted((root, query, cb) -> cb.equal(root.get("tenantId"), "tenant-gov-br"));
        }

        @Override
        protected String resolveHardScopeJpql() {
            return "e.tenantId = :tenantId";
        }

        @Override
        protected Map<String, Object> resolveHardScopeParams() {
            return Map.of("tenantId", "tenant-gov-br");
        }

        @Override
        protected void verifyEntityAccessAllowed(P102AfastamentoJpaEntity entity) {
            if (!"tenant-gov-br".equals(entity.tenantId) || !Objects.equals(100L, entity.lotacaoSetorId)) {
                throw new SecurityException("Entity #" + entity.id + " is outside authorized DataScopePlan (403)");
            }
        }

        @Override
        protected StatsFieldRegistry defineRawStatsFieldRegistry() {
            return StatsFieldRegistry.builder()
                    .categoricalGroupByBucket("statusAfastamento", "statusAfastamento")
                    .categoricalGroupByBucket("cidCodigo", "cidCodigo")
                    .build();
        }

        @Override
        public boolean supportsCursorPagination() {
            return true;
        }
    }

    static final class ConciseAfastamentoGovernedService extends AbstractAuthzGovernedResourceService<
            P102AfastamentoJpaEntity,
            AfastamentoAnnotatedResponseDTO,
            Long,
            AfastamentoFilterDTO,
            AfastamentoAnnotatedCreateDTO,
            AfastamentoAnnotatedUpdateDTO> {

        private final AfastamentoAuthzPilotBlueprint blueprint;
        private final EntityManager em;
        final AtomicBoolean callerIsCedente = new AtomicBoolean(false);
        final java.util.List<String> executionTrace = new java.util.ArrayList<>();

        ConciseAfastamentoGovernedService(
                BaseCrudRepository<P102AfastamentoJpaEntity, Long> repository,
                AuthzGovernedResourceServiceSupport serviceSupport,
                AfastamentoAuthzPilotBlueprint blueprint,
                JpaDataScopeAdapter jpaAdapter,
                JpaCriteriaDataScopeTranslator criteriaTranslator,
                EntityManager em
        ) {
            super(
                    repository,
                    P102AfastamentoJpaEntity.class,
                    AfastamentoAnnotatedResponseDTO.class,
                    serviceSupport,
                    blueprint.decisionPoint(),
                    blueprint.factContract().factContractDigest(),
                    jpaAdapter,
                    criteriaTranslator
            );
            this.blueprint = blueprint;
            this.em = em;
        }

        @Override
        protected String resolveResourceKey() {
            return blueprint.resourceKey();
        }

        @Override
        public EntityManager getEntityManager() {
            return em;
        }

        @Override
        protected ResourceMapper<
                P102AfastamentoJpaEntity,
                AfastamentoAnnotatedResponseDTO,
                AfastamentoAnnotatedCreateDTO,
                AfastamentoAnnotatedUpdateDTO,
                Long> getRawResourceMapper() {
            return new ResourceMapper<>() {
                @Override
                public AfastamentoAnnotatedResponseDTO toResponse(P102AfastamentoJpaEntity e) {
                    return new AfastamentoAnnotatedResponseDTO(
                            e.id, e.tenantId, e.cedenteOrgaoId, e.cessionarioOrgaoId,
                            e.lotacaoSetorId, e.statusAfastamento, e.substitutoServidorId, e.cidCodigo
                    );
                }

                @Override
                public P102AfastamentoJpaEntity newEntity(AfastamentoAnnotatedCreateDTO dto) {
                    return new P102AfastamentoJpaEntity(
                            dto.id(), dto.tenantId(), dto.orgCedenteId(), dto.orgCessionariaId(),
                            dto.lotacaoSetorId(), dto.statusAfastamento(), dto.substitutoServidorId(), dto.cidCodigo()
                    );
                }

                @Override
                public void applyUpdate(P102AfastamentoJpaEntity e, AfastamentoAnnotatedUpdateDTO dto) {
                    if (dto.substitutoServidorId() != null) {
                        e.substitutoServidorId = dto.substitutoServidorId();
                    }
                    if (dto.cidCodigo() != null) {
                        e.cidCodigo = dto.cidCodigo();
                    }
                }

                @Override
                public Long extractId(P102AfastamentoJpaEntity e) {
                    return e.id;
                }
            };
        }

        @Override
        protected Map<String, Object> resolveSubjectAndEnvironmentFacts() {
            return Map.of(
                    "subject.principalId", "usr-gestor-101",
                    "subject.organizationUnitIds", List.of(100L)
            );
        }

        @Override
        protected Map<String, Object> extractEntityTargetFacts(P102AfastamentoJpaEntity entity) {
            return Map.of("resource.lotacaoSetorId", entity.lotacaoSetorId);
        }

        @Override
        protected ResourceFilterAccessScope<P102AfastamentoJpaEntity> resolveHardScope() {
            return ResourceFilterAccessScope.restricted((root, query, cb) -> cb.equal(root.get("tenantId"), "tenant-gov-br"));
        }

        @Override
        protected String resolveHardScopeJpql() {
            return "e.tenantId = :tenantId";
        }

        @Override
        protected Map<String, Object> resolveHardScopeParams() {
            return Map.of("tenantId", "tenant-gov-br");
        }

        @Override
        protected void verifyEntityAccessAllowed(P102AfastamentoJpaEntity entity) {
            if (!"tenant-gov-br".equals(entity.tenantId) || !Objects.equals(100L, entity.lotacaoSetorId)) {
                throw new SecurityException("Entity #" + entity.id + " is outside authorized DataScopePlan (403)");
            }
        }

        @Override
        protected org.praxisplatform.authz.contracts.policy.DualScopeDelegationSpec resolveDualScopeDelegationSpec() {
            return blueprint.dualScopeSpec();
        }

        @Override
        protected boolean isCallerCedente(P102AfastamentoJpaEntity entity) {
            return callerIsCedente.get();
        }

        @Override
        protected Set<String> resolveMandatoryScopeAnchorAttributeIds() {
            return Set.of(
                    "ergon.afastamentos.id",
                    "ergon.afastamentos.tenant_id",
                    "ergon.afastamentos.cedente_orgao_id",
                    "ergon.afastamentos.cessionario_orgao_id",
                    "ergon.afastamentos.lotacao_setor_id"
            );
        }

        @Override
        protected void hydrateBeforeCreate(AfastamentoAnnotatedCreateDTO dto, P102AfastamentoJpaEntity entity) {
            executionTrace.add("STEP_11_DONE");
            executionTrace.add("HYDRATE_CREATE");
        }

        @Override
        protected void validateCreate(
                ResourceMutationContext context,
                AfastamentoAnnotatedCreateDTO dto,
                P102AfastamentoJpaEntity entity
        ) {
            executionTrace.add("STEP_12_VALIDATE_CREATE");
        }

        @Override
        protected void hydrateBeforeUpdate(Long id, P102AfastamentoJpaEntity existing, AfastamentoAnnotatedUpdateDTO dto) {
            executionTrace.add("STEP_11_DONE");
            executionTrace.add("HYDRATE_UPDATE");
        }

        @Override
        protected com.fasterxml.jackson.databind.JsonNode validateUpdate(
                ResourceMutationContext context,
                Long id,
                P102AfastamentoJpaEntity existing,
                AfastamentoAnnotatedUpdateDTO dto
        ) {
            executionTrace.add("STEP_12_VALIDATE_UPDATE");
            return null;
        }
    }

    /** Unannotated command DTO demonstrating automatic @DomainLineage inheritance from ResponseDTO (Fase P10.10). */
    record DesignarSubstitutoCommandDTO(Long substitutoServidorId) {}

    /** UpdateDTO declaring contradictory PUBLIC governance on restricted cidCodigo (for AUTHZ-HOST-009 test). */
    record ContradictoryGovernanceUpdateDTO(
            @DomainLineage(attributeId = "ergon.afastamentos.cid_codigo")
            @DomainGovernance(
                    classification = DomainClassification.PUBLIC,
                    dataCategory = DomainDataCategory.OPERATIONAL,
                    reason = "Contradictory PUBLIC classification on restricted CID attribute"
            )
            String cidCodigo
    ) {}

    /** UpdateDTO declaring a DERIVED field from restricted cidCodigo that widens exportability/classification (for P10.14-R05 test). */
    record DerivedWideningUpdateDTO(
            @DomainLineage(
                    attributeId = "ergon.afastamentos.resumo_cid_publico",
                    transformation = org.praxisplatform.uischema.annotation.DomainLineageTransformation.DERIVED,
                    sourcePaths = {"ergon.afastamentos.cid_codigo"}
            )
            @DomainGovernance(
                    classification = DomainClassification.PUBLIC,
                    dataCategory = DomainDataCategory.OPERATIONAL,
                    exportable = true,
                    reason = "Illegal derived declassification from restricted CID attribute"
            )
            String resumoCidPublico
    ) {}

    /** Command DTO carrying request-only workflow parameters not present on ResponseDTO (P10.10-R03). */
    record HomologarComJustificativaCommandDTO(String justificativaHomologacao, String numeroProcessoSei) {}

    static final class SpecDrivenAfastamentoGovernedService extends AbstractAuthzGovernedResourceService<
            P102AfastamentoJpaEntity,
            AfastamentoAnnotatedResponseDTO,
            Long,
            AfastamentoFilterDTO,
            AfastamentoAnnotatedCreateDTO,
            AfastamentoAnnotatedUpdateDTO> {

        private final EntityManager em;
        final AtomicBoolean callerIsCedente = new AtomicBoolean(true);
        final AtomicBoolean callerIsCessionario = new AtomicBoolean(true);
        final AtomicBoolean useDeclarativeCustody = new AtomicBoolean(false);

        SpecDrivenAfastamentoGovernedService(
                BaseCrudRepository<P102AfastamentoJpaEntity, Long> repository,
                AuthzGovernedResourceServiceSupport serviceSupport,
                AuthzResourceGovernanceSpec<P102AfastamentoJpaEntity> governanceSpec,
                AuthzCallerContextProvider callerContextProvider,
                EntityManager em
        ) {
            super(
                    repository,
                    P102AfastamentoJpaEntity.class,
                    AfastamentoAnnotatedResponseDTO.class,
                    serviceSupport,
                    governanceSpec,
                    callerContextProvider
            );
            this.em = em;
        }

        @Override
        public EntityManager getEntityManager() {
            return em;
        }

        @Override
        protected ResourceMapper<
                P102AfastamentoJpaEntity,
                AfastamentoAnnotatedResponseDTO,
                AfastamentoAnnotatedCreateDTO,
                AfastamentoAnnotatedUpdateDTO,
                Long> getRawResourceMapper() {
            return new ResourceMapper<>() {
                @Override
                public AfastamentoAnnotatedResponseDTO toResponse(P102AfastamentoJpaEntity e) {
                    return new AfastamentoAnnotatedResponseDTO(
                            e.id, e.tenantId, e.cedenteOrgaoId, e.cessionarioOrgaoId,
                            e.lotacaoSetorId, e.statusAfastamento, e.substitutoServidorId, e.cidCodigo
                    );
                }

                @Override
                public P102AfastamentoJpaEntity newEntity(AfastamentoAnnotatedCreateDTO dto) {
                    return new P102AfastamentoJpaEntity(
                            dto.id(), dto.tenantId(), dto.orgCedenteId(), dto.orgCessionariaId(),
                            dto.lotacaoSetorId(), dto.statusAfastamento(), dto.substitutoServidorId(), dto.cidCodigo()
                    );
                }

                @Override
                public void applyUpdate(P102AfastamentoJpaEntity e, AfastamentoAnnotatedUpdateDTO dto) {
                    if (dto.substitutoServidorId() != null) {
                        e.substitutoServidorId = dto.substitutoServidorId();
                    }
                    if (dto.cidCodigo() != null) {
                        e.cidCodigo = dto.cidCodigo();
                    }
                }

                @Override
                public Long extractId(P102AfastamentoJpaEntity e) {
                    return e.id;
                }
            };
        }

        @Override
        protected boolean isCallerCedente(P102AfastamentoJpaEntity entity) {
            return useDeclarativeCustody.get() ? super.isCallerCedente(entity) : callerIsCedente.get();
        }

        @Override
        protected boolean isCallerCessionario(P102AfastamentoJpaEntity entity) {
            return useDeclarativeCustody.get() ? super.isCallerCessionario(entity) : callerIsCessionario.get();
        }

        @Override
        protected List<CollectionExportField> defineRawExportFields() {
            return List.of(
                    new CollectionExportField("id", "ID", true, true, "number", "id"),
                    new CollectionExportField("lotacaoSetorId", "Setor Lotação", true, true, "number", "lotacaoSetorId"),
                    new CollectionExportField("statusAfastamento", "Status Afastamento", true, true, "text", "statusAfastamento"),
                    new CollectionExportField("substitutoServidorId", "Substituto", true, true, "number", "substitutoServidorId")
            );
        }

        @Override
        protected StatsFieldRegistry defineRawStatsFieldRegistry() {
            return StatsFieldRegistry.builder()
                    .categoricalGroupByBucket("statusAfastamento", "statusAfastamento")
                    .categoricalGroupByBucket("cidCodigo", "cidCodigo")
                    .build();
        }

        @Override
        public boolean supportsCursorPagination() {
            return true;
        }

        ResourceRepresentationResult<AfastamentoAnnotatedResponseDTO> designarSubstituto(
                Long id,
                DesignarSubstitutoCommandDTO cmd,
                ResourceVersionUpdatePrecondition<Long> precondition
        ) {
            return executeGovernedVersionedCommand(id, "designar-substituto", cmd, precondition, entity ->
                    entity.substitutoServidorId = cmd.substitutoServidorId()
            );
        }

        ResourceRepresentationResult<AfastamentoAnnotatedResponseDTO> homologarSemPayload(
                Long id,
                ResourceVersionUpdatePrecondition<Long> precondition
        ) {
            return executeGovernedVersionedCommand(id, "homologar-afastamento", null, precondition, entity ->
                    entity.statusAfastamento = "HOMOLOGADO"
            );
        }

        AfastamentoAnnotatedResponseDTO reverterParaDeferidoSemVersao(Long id) {
            return executeGovernedItemCommand(id, "homologar-afastamento", null, entity ->
                    entity.statusAfastamento = "DEFERIDO"
            );
        }

        AfastamentoAnnotatedResponseDTO homologarComJustificativa(
                Long id,
                HomologarComJustificativaCommandDTO cmd
        ) {
            return executeGovernedItemCommand(id, "homologar-afastamento", cmd, entity ->
                    entity.statusAfastamento = "HOMOLOGADO"
            );
        }

        AfastamentoAnnotatedResponseDTO executeFailingCommandAfterStep11(Long id) {
            return executeGovernedItemCommand(id, "homologar-afastamento", null, entity -> {
                throw new IllegalStateException("Domain failure after STEP_11 inside entityMutator");
            });
        }

        List<AuthzGovernedBulkDomainResourceAdapter.BulkCohortItemOutcome<Long>> homologarEmLote(
                java.util.Collection<Long> targetIds,
                org.praxisplatform.authz.contracts.binding.BatchAuthorizationMode batchMode
        ) {
            return executeGovernedBulkCommand(
                    targetIds,
                    "homologar-lote",
                    null,
                    batchMode,
                    entity -> entity.statusAfastamento = "HOMOLOGADO"
            );
        }

        List<AuthzGovernedBulkDomainResourceAdapter.BulkCohortItemOutcome<Long>> homologarEmLoteComFalhaValidacao(
                java.util.Collection<Long> targetIds,
                org.praxisplatform.authz.contracts.binding.BatchAuthorizationMode batchMode
        ) {
            return executeGovernedBulkCommand(
                    targetIds,
                    "homologar-lote",
                    null,
                    batchMode,
                    entity -> {
                        entity.statusAfastamento = "STATUS_CORROMPIDO_NAO_AUDITADO";
                        throw new IllegalStateException("Simulated domain validation failure after dirtying JPA entity");
                    }
            );
        }

        @Override
        protected java.util.Collection<ReactiveDeterminationDefinition> defineReactiveDeterminations() {
            return List.of(
                    ReactiveDeterminationDefinition
                            .forCrudResource(
                                    "det-substituto-preview-spec",
                                    "createAfastamento",
                                    "updateAfastamento",
                                    "previewSubstitutoAfastamento"
                            )
                            .source("/substitutoServidorId")
                            .input("/substitutoServidorId", "/substitutoServidorId")
                            .output("/statusAfastamento", "/statusAfastamento")
                            .output("/cidCodigo", "/cidCodigo")
                            .provenance(new ReactiveDeterminationProvenance(
                                    ReactiveDeterminationProvenanceKind.HOST,
                                    "previewSubstitutoAfastamento",
                                    "v1"
                            ))
                            .build()
            );
        }

        AfastamentoAnnotatedCreateDTO duplicateDraft(Long sourceId) {
            return executeGovernedDuplicateDraft(sourceId, source -> new AfastamentoAnnotatedCreateDTO(
                    null,
                    source.tenantId,
                    source.cedenteOrgaoId,
                    source.cessionarioOrgaoId,
                    source.lotacaoSetorId,
                    "RASCUNHO",
                    source.substitutoServidorId,
                    source.cidCodigo
            ));
        }
    }
}
