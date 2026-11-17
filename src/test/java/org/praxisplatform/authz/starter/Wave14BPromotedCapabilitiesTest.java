package org.praxisplatform.authz.starter;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EntityManager;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.Version;
import java.math.BigDecimal;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Properties;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.sql.DataSource;
import org.hibernate.jpa.HibernatePersistenceProvider;
import org.junit.jupiter.api.Test;
import org.praxisplatform.authz.agent.AuthzAgentAuthorizationBridge;
import org.praxisplatform.authz.autoconfigure.PraxisAuthzAgentBridgeAutoConfiguration;
import org.praxisplatform.authz.autoconfigure.PraxisAuthzAutoConfiguration;
import org.praxisplatform.authz.autoconfigure.PraxisAuthzHostBridgeAutoConfiguration;
import org.praxisplatform.authz.contracts.annotation.AuthzActionRule;
import org.praxisplatform.authz.contracts.annotation.AuthzCustodyPartition;
import org.praxisplatform.authz.contracts.annotation.AuthzCustodyRole;
import org.praxisplatform.authz.contracts.annotation.AuthzDelegationSplitMode;
import org.praxisplatform.authz.contracts.annotation.AuthzMask;
import org.praxisplatform.authz.contracts.annotation.AuthzMaskStrategy;
import org.praxisplatform.authz.contracts.annotation.AuthzScopeAnchor;
import org.praxisplatform.authz.contracts.annotation.AuthzTenantScope;
import org.praxisplatform.authz.contracts.annotation.AuthzTenantScopeMode;
import org.praxisplatform.authz.contracts.decisionpoint.EnforcementCapability;
import org.praxisplatform.authz.contracts.decisionpoint.FieldUseCategory;
import org.praxisplatform.authz.contracts.envelope.RuleEffect;
import org.praxisplatform.authz.contracts.policy.MaskContributionSpec;
import org.praxisplatform.authz.host.metadata.AbstractAuthzGovernedResourceService;
import org.praxisplatform.authz.host.metadata.AuthzCallerContext;
import org.praxisplatform.authz.host.metadata.AuthzGovernedResourceServiceSupport;
import org.praxisplatform.authz.host.metadata.AuthzHostPolicyBootstrapBuilder;
import org.praxisplatform.authz.host.metadata.AuthzHostReadinessReviewer;
import org.praxisplatform.authz.host.metadata.AuthzHostReadinessReviewer.ReadinessReport;
import org.praxisplatform.authz.host.metadata.AuthzResourceGovernanceSpec;
import org.praxisplatform.authz.host.metadata.AuthzResourceOperationAvailabilityProvider;
import org.praxisplatform.authz.host.metadata.AuthzResourceOperationAvailabilityRule;
import org.praxisplatform.authz.host.metadata.HardScopeResolver;
import org.praxisplatform.authz.host.metadata.HardScopeResolver.HardScopeMode;
import org.praxisplatform.authz.host.metadata.HardScopeResolver.HardScopeSelection;
import org.praxisplatform.authz.host.metadata.MetadataDtoGovernanceIntrospector;
import org.praxisplatform.authz.host.metadata.MetadataDtoGovernanceIntrospector.IntrospectedDtoGovernanceContract;
import org.praxisplatform.authz.host.metadata.MultiOrganizationHardScopeResolver;
import org.praxisplatform.authz.host.metadata.ThreadLocalAuthzCallerContextProvider;
import org.praxisplatform.authz.opa.compiler.CompiledRegoUnit;
import org.praxisplatform.authz.outbox.JdbcTransactionalAuditOutbox;
import org.praxisplatform.authz.seams.RuntimeDecisionPointRegistry;
import org.praxisplatform.config.ai.agent.spi.AgentExecutionContext;
import org.praxisplatform.uischema.action.ActionScope;
import org.praxisplatform.uischema.annotation.AiUsagePolicy;
import org.praxisplatform.uischema.annotation.AiVisibilityMode;
import org.praxisplatform.uischema.annotation.ApiResource;
import org.praxisplatform.uischema.annotation.DomainClassification;
import org.praxisplatform.uischema.annotation.DomainDataCategory;
import org.praxisplatform.uischema.annotation.DomainGovernance;
import org.praxisplatform.uischema.annotation.DomainLineage;
import org.praxisplatform.uischema.annotation.UiSurface;
import org.praxisplatform.uischema.annotation.WorkflowAction;
import org.praxisplatform.uischema.capability.AvailabilityDecision;
import org.praxisplatform.uischema.capability.CompositeResourceOperationAvailabilityEvaluator;
import org.praxisplatform.uischema.capability.ResourceOperationAvailabilityContext;
import org.praxisplatform.uischema.capability.ResourceOperationAvailabilityProvider;
import org.praxisplatform.uischema.capability.ResourceOperationAvailabilityRule;
import org.praxisplatform.uischema.exporting.CollectionExportExecutor;
import org.praxisplatform.uischema.exporting.CollectionExportField;
import org.praxisplatform.uischema.exporting.CsvCollectionExportEngine;
import org.praxisplatform.uischema.exporting.DefaultCollectionExportExecutor;
import org.praxisplatform.uischema.filter.annotation.Filterable;
import org.praxisplatform.uischema.filter.dto.GenericFilterDTO;
import org.praxisplatform.uischema.filter.specification.GenericSpecificationsBuilder;
import org.praxisplatform.uischema.governance.AccessMode;
import org.praxisplatform.uischema.governance.MutationContext;
import org.praxisplatform.uischema.governance.MutationKind;
import org.praxisplatform.uischema.mapper.base.ResourceMapper;
import org.praxisplatform.uischema.repository.base.BaseCrudRepository;
import org.praxisplatform.uischema.service.base.AbstractBaseQueryResourceService;
import org.praxisplatform.uischema.service.base.AbstractBaseResourceService;
import org.praxisplatform.uischema.service.base.ResourceFilterAccessScope;
import org.praxisplatform.uischema.stats.StatsFieldDescriptor;
import org.praxisplatform.uischema.stats.StatsFieldRegistry;
import org.praxisplatform.uischema.stats.StatsMetric;
import org.praxisplatform.uischema.surface.SurfaceKind;
import org.praxisplatform.uischema.surface.SurfaceScope;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.repository.support.JpaRepositoryFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.orm.jpa.SharedEntityManagerCreator;
import org.springframework.orm.jpa.vendor.HibernateJpaVendorAdapter;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

/**
 * Conformance and end-to-end integration tests for Wave 1.4B promoted platform capabilities:
 * <ol>
 *   <li>Declarative {@code @Authz*} annotations ({@link AuthzTenantScope}, {@link AuthzScopeAnchor},
 *       {@link AuthzCustodyPartition}, {@link AuthzMask}, {@link AuthzActionRule});</li>
 *   <li>Automatic {@link DomainGovernance} field mask derivation and {@code @AuthzMask} override precedence;</li>
 *   <li>Zero-config {@link AuthzHostPolicyBootstrapBuilder#addAnnotatedResource} synthesis with disjunctive
 *       role Rego compilation and {@code AUTHZ-HOST-010} resolution;</li>
 *   <li>{@link MultiOrganizationHardScopeResolver} ({@code SINGLE_VALUE}, {@code MULTI_ORGANIZATION},
 *       {@code SHARED_UNRESTRICTED}, {@code DENIED}, consolidation read-only, immutable scope anchors);</li>
 *   <li>{@link AuthzResourceGovernanceInterceptor} governing plain {@link AbstractBaseResourceService} and
 *       {@link AbstractBaseQueryResourceService} beans while bypassing {@link AbstractAuthzGovernedResourceService};</li>
 *   <li>{@link AuthzResourceOperationAvailabilityRule} + {@code @Primary CompositeResourceOperationAvailabilityEvaluator}
 *       deny-wins composition and {@link PraxisAuthzAgentBridgeAutoConfiguration} compatibility.</li>
 * </ol>
 */
class Wave14BPromotedCapabilitiesTest {

    @Entity(name = "Wave14BAssignmentEntity")
    @Table(name = "wave14b_assignments")
    static class AssignmentEntity {
        @Id
        Long id;

        @Column(name = "tenant_id", nullable = false)
        String tenantId;

        @AuthzScopeAnchor(
                attributeId = "workforce.assignments.organization_unit_id",
                requiredOnCreate = true,
                forbidClearOnUpdate = true,
                immutableAfterCreate = true,
                reason = "Organization assignment anchor cannot change after creation"
        )
        @AuthzCustodyPartition(
                role = AuthzCustodyRole.ORIGIN,
                custodyAnchor = true,
                mode = AuthzDelegationSplitMode.ORIGIN_DESTINATION_SPLIT,
                attributeId = "workforce.assignments.organization_unit_id"
        )
        @Column(name = "organization_unit_id", nullable = false)
        Long organizationUnitId;

        @AuthzCustodyPartition(
                role = AuthzCustodyRole.DESTINATION,
                custodyAnchor = true,
                mode = AuthzDelegationSplitMode.ORIGIN_DESTINATION_SPLIT,
                attributeId = "workforce.assignments.destination_unit_id"
        )
        @Column(name = "destination_unit_id")
        Long destinationUnitId;

        @Column(name = "employee_name", nullable = false)
        String employeeName;

        @Column(name = "status", nullable = false)
        String status;

        @Column(name = "tax_id")
        String taxId;

        @Column(name = "document_code")
        String documentCode;

        @Column(name = "salary_amount", precision = 12, scale = 2)
        BigDecimal salaryAmount;

        @Column(name = "risk_score", nullable = false)
        int riskScore;

        @Column(name = "pin_code")
        String pinCode;

        @Version
        Long version;

        public Long getId() { return id; }
        public String getTenantId() { return tenantId; }
        public Long getOrganizationUnitId() { return organizationUnitId; }
        public Long getDestinationUnitId() { return destinationUnitId; }
        public String getEmployeeName() { return employeeName; }
        public String getStatus() { return status; }
        public String getTaxId() { return taxId; }
        public String getDocumentCode() { return documentCode; }
        public BigDecimal getSalaryAmount() { return salaryAmount; }
        public int getRiskScore() { return riskScore; }
        public String getPinCode() { return pinCode; }
        public Long getVersion() { return version; }
    }

    @Entity(name = "Wave14BCatalogEntity")
    @Table(name = "wave14b_catalog_items")
    static class CatalogEntity {
        @Id
        Long id;

        @Column(name = "tenant_id", nullable = false)
        String tenantId;

        @Column(name = "code", nullable = false)
        String code;

        @Column(name = "title", nullable = false)
        String title;

        public Long getId() { return id; }
        public String getTenantId() { return tenantId; }
        public String getCode() { return code; }
        public String getTitle() { return title; }
    }

    static final class AssignmentResponseDTO {
        @Schema(description = "Assignment identifier")
        @DomainLineage(attributeId = "workforce.assignments.id")
        @DomainGovernance(
                classification = DomainClassification.INTERNAL,
                dataCategory = DomainDataCategory.OPERATIONAL,
                exportable = true,
                aiUsage = @AiUsagePolicy(visibility = AiVisibilityMode.ALLOW)
        )
        public Long id;

        @Schema(description = "Tenant identifier")
        @DomainLineage(attributeId = "workforce.assignments.tenant_id")
        @DomainGovernance(
                classification = DomainClassification.INTERNAL,
                dataCategory = DomainDataCategory.OPERATIONAL,
                exportable = true,
                aiUsage = @AiUsagePolicy(visibility = AiVisibilityMode.ALLOW)
        )
        public String tenantId;

        @Schema(description = "Owning organization unit identifier")
        @DomainLineage(attributeId = "workforce.assignments.organization_unit_id")
        @DomainGovernance(
                classification = DomainClassification.INTERNAL,
                dataCategory = DomainDataCategory.OPERATIONAL,
                exportable = true,
                aiUsage = @AiUsagePolicy(visibility = AiVisibilityMode.ALLOW)
        )
        public Long organizationUnitId;

        @Schema(description = "Destination organization unit identifier")
        @DomainLineage(attributeId = "workforce.assignments.destination_unit_id")
        @DomainGovernance(
                classification = DomainClassification.INTERNAL,
                dataCategory = DomainDataCategory.OPERATIONAL,
                exportable = true,
                aiUsage = @AiUsagePolicy(visibility = AiVisibilityMode.ALLOW)
        )
        public Long destinationUnitId;

        @Schema(description = "Employee full name")
        @DomainLineage(attributeId = "workforce.assignments.employee_name")
        @DomainGovernance(
                classification = DomainClassification.INTERNAL,
                dataCategory = DomainDataCategory.OPERATIONAL,
                exportable = true,
                aiUsage = @AiUsagePolicy(visibility = AiVisibilityMode.ALLOW)
        )
        public String employeeName;

        @Schema(description = "Assignment workflow status")
        @DomainLineage(attributeId = "workforce.assignments.status")
        @DomainGovernance(
                classification = DomainClassification.INTERNAL,
                dataCategory = DomainDataCategory.OPERATIONAL,
                exportable = true,
                aiUsage = @AiUsagePolicy(visibility = AiVisibilityMode.ALLOW)
        )
        public String status;

        @Schema(description = "Sensitive national tax ID (auto-derived mask)")
        @DomainLineage(attributeId = "workforce.assignments.tax_id")
        @DomainGovernance(
                classification = DomainClassification.RESTRICTED,
                dataCategory = DomainDataCategory.SENSITIVE_PERSONAL,
                exportable = false,
                aiUsage = @AiUsagePolicy(visibility = AiVisibilityMode.MASK)
        )
        public String taxId;

        @Schema(description = "Explicitly masked document code overriding derived strategy")
        @DomainLineage(attributeId = "workforce.assignments.document_code")
        @DomainGovernance(
                classification = DomainClassification.RESTRICTED,
                dataCategory = DomainDataCategory.SENSITIVE_PERSONAL,
                exportable = false,
                aiUsage = @AiUsagePolicy(visibility = AiVisibilityMode.MASK)
        )
        @AuthzMask(strategy = AuthzMaskStrategy.CPF_CNPJ_PARTIAL, reason = "Preserve tail digits for support desk")
        public String documentCode;

        @Schema(description = "Confidential base salary (nullable non-String object auto-derived NULLIFY)", nullable = true)
        @DomainLineage(attributeId = "workforce.assignments.salary_amount")
        @DomainGovernance(
                classification = DomainClassification.CONFIDENTIAL,
                dataCategory = DomainDataCategory.FINANCIAL,
                exportable = false,
                aiUsage = @AiUsagePolicy(visibility = AiVisibilityMode.MASK)
        )
        public BigDecimal salaryAmount;

        @Schema(description = "Restricted numeric risk score (primitive int auto-derived OMIT)")
        @DomainLineage(attributeId = "workforce.assignments.risk_score")
        @DomainGovernance(
                classification = DomainClassification.RESTRICTED,
                dataCategory = DomainDataCategory.OPERATIONAL,
                exportable = false,
                aiUsage = @AiUsagePolicy(visibility = AiVisibilityMode.MASK)
        )
        public int riskScore;

        @Schema(description = "Internal PIN credential (VALUE+DENY)")
        @DomainLineage(attributeId = "workforce.assignments.pin_code")
        @DomainGovernance(
                classification = DomainClassification.RESTRICTED,
                dataCategory = DomainDataCategory.CREDENTIAL,
                exportable = false,
                aiUsage = @AiUsagePolicy(visibility = AiVisibilityMode.DENY)
        )
        public String pinCode;

        public AssignmentResponseDTO() {}

        AssignmentResponseDTO(
                Long id,
                String tenantId,
                Long organizationUnitId,
                Long destinationUnitId,
                String employeeName,
                String status,
                String taxId,
                String documentCode,
                BigDecimal salaryAmount,
                int riskScore,
                String pinCode
        ) {
            this.id = id;
            this.tenantId = tenantId;
            this.organizationUnitId = organizationUnitId;
            this.destinationUnitId = destinationUnitId;
            this.employeeName = employeeName;
            this.status = status;
            this.taxId = taxId;
            this.documentCode = documentCode;
            this.salaryAmount = salaryAmount;
            this.riskScore = riskScore;
            this.pinCode = pinCode;
        }
    }

    static final class AssignmentCreateDTO {
        public Long id;
        @DomainLineage(attributeId = "workforce.assignments.tenant_id")
        public String tenantId;
        @AuthzScopeAnchor(
                attributeId = "workforce.assignments.organization_unit_id",
                requiredOnCreate = true,
                forbidClearOnUpdate = true,
                immutableAfterCreate = true
        )
        @DomainLineage(attributeId = "workforce.assignments.organization_unit_id")
        public Long organizationUnitId;
        @DomainLineage(attributeId = "workforce.assignments.destination_unit_id")
        public Long destinationUnitId;
        @DomainLineage(attributeId = "workforce.assignments.employee_name")
        public String employeeName;
        @DomainLineage(attributeId = "workforce.assignments.status")
        public String status;
        @DomainLineage(attributeId = "workforce.assignments.tax_id")
        public String taxId;
        @DomainLineage(attributeId = "workforce.assignments.document_code")
        public String documentCode;
        @DomainLineage(attributeId = "workforce.assignments.salary_amount")
        public BigDecimal salaryAmount;
        @DomainLineage(attributeId = "workforce.assignments.risk_score")
        public int riskScore;

        public AssignmentCreateDTO() {}

        AssignmentCreateDTO(
                Long id, String tenantId, Long organizationUnitId, Long destinationUnitId,
                String employeeName, String status, String taxId, String documentCode,
                BigDecimal salaryAmount, int riskScore
        ) {
            this.id = id;
            this.tenantId = tenantId;
            this.organizationUnitId = organizationUnitId;
            this.destinationUnitId = destinationUnitId;
            this.employeeName = employeeName;
            this.status = status;
            this.taxId = taxId;
            this.documentCode = documentCode;
            this.salaryAmount = salaryAmount;
            this.riskScore = riskScore;
        }
    }

    static final class AssignmentUpdateDTO {
        @DomainLineage(attributeId = "workforce.assignments.organization_unit_id")
        public Long organizationUnitId;
        @DomainLineage(attributeId = "workforce.assignments.employee_name")
        public String employeeName;
        @DomainLineage(attributeId = "workforce.assignments.status")
        public String status;

        public AssignmentUpdateDTO() {}

        AssignmentUpdateDTO(Long organizationUnitId, String employeeName, String status) {
            this.organizationUnitId = organizationUnitId;
            this.employeeName = employeeName;
            this.status = status;
        }
    }

    static final class AssignmentFilterDTO implements GenericFilterDTO {
        @Filterable(operation = Filterable.FilterOperation.EQUAL)
        public String status;
        @Filterable(operation = Filterable.FilterOperation.EQUAL)
        public String taxId;
    }

    static final class ApproveCommandDTO {
        @DomainLineage(attributeId = "workforce.assignments.status")
        public String status;
    }

    static final class CatalogResponseDTO {
        @DomainLineage(attributeId = "workforce.catalogs.id")
        @DomainGovernance(
                classification = DomainClassification.INTERNAL,
                dataCategory = DomainDataCategory.OPERATIONAL,
                exportable = true,
                aiUsage = @AiUsagePolicy(visibility = AiVisibilityMode.ALLOW)
        )
        public Long id;
        @DomainLineage(attributeId = "workforce.catalogs.tenant_id")
        @DomainGovernance(
                classification = DomainClassification.INTERNAL,
                dataCategory = DomainDataCategory.OPERATIONAL,
                exportable = true,
                aiUsage = @AiUsagePolicy(visibility = AiVisibilityMode.ALLOW)
        )
        public String tenantId;
        @DomainLineage(attributeId = "workforce.catalogs.code")
        @DomainGovernance(
                classification = DomainClassification.INTERNAL,
                dataCategory = DomainDataCategory.OPERATIONAL,
                exportable = true,
                aiUsage = @AiUsagePolicy(visibility = AiVisibilityMode.ALLOW)
        )
        public String code;
        @DomainLineage(attributeId = "workforce.catalogs.title")
        @DomainGovernance(
                classification = DomainClassification.INTERNAL,
                dataCategory = DomainDataCategory.OPERATIONAL,
                exportable = true,
                aiUsage = @AiUsagePolicy(visibility = AiVisibilityMode.ALLOW)
        )
        public String title;

        public CatalogResponseDTO() {}

        CatalogResponseDTO(Long id, String tenantId, String code, String title) {
            this.id = id;
            this.tenantId = tenantId;
            this.code = code;
            this.title = title;
        }
    }

    static final class CatalogFilterDTO implements GenericFilterDTO {
        @Filterable(operation = Filterable.FilterOperation.EQUAL)
        public String code;
    }

    @ApiResource(value = "/api/workforce/assignments", resourceKey = "workforce.assignments")
    @AuthzTenantScope(
            mode = AuthzTenantScopeMode.ORGANIZATIONAL_UNIT,
            tenantField = "organizationUnitId",
            subjectFactPath = AuthzCallerContext.FACT_AUTHORIZED_ORGANIZATION_IDS
    )
    @AuthzCustodyPartition(
            originExclusiveWriteAttributes = {
                    "workforce.assignments.id",
                    "workforce.assignments.tenant_id",
                    "workforce.assignments.destination_unit_id",
                    "workforce.assignments.employee_name",
                    "workforce.assignments.tax_id",
                    "workforce.assignments.document_code",
                    "workforce.assignments.salary_amount",
                    "workforce.assignments.risk_score"
            },
            destinationAllowedWriteAttributes = {"workforce.assignments.status"}
    )
    static class AnnotatedAssignmentController {
        @WorkflowAction(id = "approve", title = "Approve", scope = ActionScope.ITEM)
        @AuthzActionRule(
                requiredRoles = {"HR_MANAGER", "PAYROLL_DIRECTOR"},
                conditionFactPath = "resource.status",
                conditionAllowedValues = {"PENDING"},
                allowedWriteAttributes = {"workforce.assignments.status"},
                reasonCode = "ALLOW_APPROVE_PENDING_ASSIGNMENT"
        )
        @PostMapping("/{id}/actions/approve")
        public void approve(@PathVariable Long id, @RequestBody ApproveCommandDTO cmd) {}

        @WorkflowAction(id = "acknowledge", title = "Acknowledge", scope = ActionScope.ITEM)
        @AuthzActionRule(
                requiredRoles = {"EMPLOYEE"},
                allowedWriteAttributes = {},
                auditRequired = false,
                reasonCode = "ALLOW_EMPLOYEE_ACK"
        )
        @PostMapping("/{id}/actions/acknowledge")
        public void acknowledge(@PathVariable Long id) {}

        @UiSurface(id = "salary-summary", title = "Salary Summary", kind = SurfaceKind.VIEW, scope = SurfaceScope.ITEM)
        @AuthzActionRule(
                requiredRoles = {"HR_MANAGER", "PAYROLL_DIRECTOR"},
                reasonCode = "ALLOW_SALARY_SUMMARY"
        )
        public void salarySummarySurface() {}
    }

    @ApiResource(value = "/api/workforce/catalogs", resourceKey = "workforce.catalogs")
    @AuthzTenantScope(mode = AuthzTenantScopeMode.TENANT_ONLY)
    static class AnnotatedCatalogController {}

    interface AssignmentRepository extends BaseCrudRepository<AssignmentEntity, Long> {}
    interface CatalogRepository extends BaseCrudRepository<CatalogEntity, Long> {}

    static final class PlainAssignmentMapper
            implements ResourceMapper<AssignmentEntity, AssignmentResponseDTO, AssignmentCreateDTO, AssignmentUpdateDTO, Long> {
        @Override
        public AssignmentResponseDTO toResponse(AssignmentEntity e) {
            return new AssignmentResponseDTO(
                    e.id, e.tenantId, e.organizationUnitId, e.destinationUnitId,
                    e.employeeName, e.status, e.taxId, e.documentCode,
                    e.salaryAmount, e.riskScore, e.pinCode
            );
        }

        @Override
        public AssignmentEntity newEntity(AssignmentCreateDTO dto) {
            AssignmentEntity e = new AssignmentEntity();
            e.id = dto.id;
            e.tenantId = dto.tenantId;
            e.organizationUnitId = dto.organizationUnitId;
            e.destinationUnitId = dto.destinationUnitId;
            e.employeeName = dto.employeeName;
            e.status = dto.status != null ? dto.status : "PENDING";
            e.taxId = dto.taxId;
            e.documentCode = dto.documentCode;
            e.salaryAmount = dto.salaryAmount;
            e.riskScore = dto.riskScore;
            e.pinCode = "SECRET-PIN";
            return e;
        }

        @Override
        public void applyUpdate(AssignmentEntity e, AssignmentUpdateDTO dto) {
            if (dto.organizationUnitId != null) {
                e.organizationUnitId = dto.organizationUnitId;
            }
            if (dto.employeeName != null) {
                e.employeeName = dto.employeeName;
            }
            if (dto.status != null) {
                e.status = dto.status;
            }
        }

        @Override
        public Long extractId(AssignmentEntity e) {
            return e.id;
        }
    }

    static final class PlainCatalogMapper
            implements ResourceMapper<CatalogEntity, CatalogResponseDTO, Object, Object, Long> {
        @Override
        public CatalogResponseDTO toResponse(CatalogEntity e) {
            return new CatalogResponseDTO(e.id, e.tenantId, e.code, e.title);
        }

        @Override
        public CatalogEntity newEntity(Object dto) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void applyUpdate(CatalogEntity entity, Object dto) {
            throw new UnsupportedOperationException();
        }

        @Override
        public Long extractId(CatalogEntity e) {
            return e.id;
        }
    }

    static class PlainAssignmentService
            extends AbstractBaseResourceService<AssignmentEntity, AssignmentResponseDTO, Long, AssignmentFilterDTO, AssignmentCreateDTO, AssignmentUpdateDTO> {
        private final PlainAssignmentMapper mapper = new PlainAssignmentMapper();

        PlainAssignmentService(
                AssignmentRepository repository,
                GenericSpecificationsBuilder<AssignmentEntity> specificationsBuilder
        ) {
            super(repository, specificationsBuilder, AssignmentEntity.class);
        }

        @Override
        public String getResourceKey() {
            return "workforce.assignments";
        }

        @Override
        protected ResourceMapper<AssignmentEntity, AssignmentResponseDTO, AssignmentCreateDTO, AssignmentUpdateDTO, Long> getResourceMapper() {
            return mapper;
        }

        @Override
        protected List<CollectionExportField> exportFields() {
            return List.of(
                    new CollectionExportField("employeeName", "Employee", true, true, "STRING", "employeeName"),
                    new CollectionExportField("taxId", "Tax ID", true, true, "STRING", "taxId"),
                    new CollectionExportField("pinCode", "PIN", true, true, "STRING", "pinCode")
            );
        }

        @Override
        public StatsFieldRegistry getStatsFieldRegistry() {
            return StatsFieldRegistry.of(List.of(
                    StatsFieldDescriptor.groupByBucket("status", "status", Set.of(StatsMetric.COUNT))
            ));
        }
    }

    static class PlainCatalogReadOnlyService
            extends AbstractBaseQueryResourceService<CatalogEntity, CatalogResponseDTO, Long, CatalogFilterDTO> {
        private final PlainCatalogMapper mapper = new PlainCatalogMapper();

        PlainCatalogReadOnlyService(
                CatalogRepository repository,
                GenericSpecificationsBuilder<CatalogEntity> specificationsBuilder
        ) {
            super(repository, specificationsBuilder, CatalogEntity.class);
        }

        @Override
        public String getResourceKey() {
            return "workforce.catalogs";
        }

        @Override
        protected ResourceMapper<CatalogEntity, CatalogResponseDTO, ?, ?, Long> getResourceMapper() {
            return mapper;
        }
    }

    static class ExplicitGovernedDummyService
            extends AbstractAuthzGovernedResourceService<AssignmentEntity, AssignmentResponseDTO, Long, AssignmentFilterDTO, AssignmentCreateDTO, AssignmentUpdateDTO> {
        ExplicitGovernedDummyService(
                AssignmentRepository repository,
                AuthzGovernedResourceServiceSupport serviceSupport,
                ThreadLocalAuthzCallerContextProvider callerContextProvider,
                AuthzResourceGovernanceSpec<AssignmentEntity> spec
        ) {
            super(repository, new GenericSpecificationsBuilder<>(), AssignmentEntity.class,
                    AssignmentResponseDTO.class, serviceSupport, spec, callerContextProvider);
        }

        @Override
        protected ResourceMapper<AssignmentEntity, AssignmentResponseDTO, AssignmentCreateDTO, AssignmentUpdateDTO, Long> getRawResourceMapper() {
            return new PlainAssignmentMapper();
        }
    }

    @Test
    void testAnnotationDiscoveryMaskDerivationZeroConfigBootstrapAndAuthzHost010() {
        MetadataDtoGovernanceIntrospector introspector = new MetadataDtoGovernanceIntrospector();
        IntrospectedDtoGovernanceContract dtoContract = introspector.introspect(
                AssignmentResponseDTO.class, "workforce.assignments"
        );

        // Derived masks cover SENSITIVE_PERSONAL / CONFIDENTIAL / RESTRICTED, skipping CREDENTIAL (VALUE+DENY)
        // and non-nullable primitives (also enforced via VALUE+DENY / OMIT_BY_FIELD_USE_DENY);
        // explicit @AuthzMask on documentCode overrides derived REDACT_CONSTANT!
        List<MaskContributionSpec> effectiveMasks = dtoContract.effectiveMaskDirectives();
        assertEquals(3, effectiveMasks.size(), "Expected taxId, documentCode (override), salaryAmount");
        assertTrue(effectiveMasks.stream().anyMatch(m ->
                m.fieldSelector().attributeIds().contains("workforce.assignments.tax_id")
                        && "REDACT_CONSTANT".equals(m.strategyId())));
        assertTrue(effectiveMasks.stream().anyMatch(m ->
                m.fieldSelector().attributeIds().contains("workforce.assignments.document_code")
                        && "CPF_CNPJ_PARTIAL".equals(m.strategyId())));
        assertTrue(effectiveMasks.stream().anyMatch(m ->
                m.fieldSelector().attributeIds().contains("workforce.assignments.salary_amount")
                        && "NULLIFY".equals(m.strategyId())));
        assertTrue(dtoContract.aiContextDeniedAttributeIds().contains("workforce.assignments.pin_code"));
        assertTrue(dtoContract.baselineFieldUseDirectives().stream().anyMatch(d ->
                d.attributeId().equals("workforce.assignments.pin_code")
                        && d.category() == FieldUseCategory.VALUE
                        && d.effect() == RuleEffect.DENY));
        assertTrue(dtoContract.baselineFieldUseDirectives().stream().anyMatch(d ->
                d.attributeId().equals("workforce.assignments.risk_score")
                        && d.category() == FieldUseCategory.VALUE
                        && d.effect() == RuleEffect.DENY));

        AuthzResourceGovernanceSpec<AssignmentEntity> spec = AuthzResourceGovernanceSpec.fromAnnotatedResource(
                "workforce-hr",
                "workforce.assignments",
                null,
                AssignmentEntity.class,
                AssignmentResponseDTO.class,
                AssignmentFilterDTO.class,
                AssignmentCreateDTO.class,
                AssignmentUpdateDTO.class,
                AnnotatedAssignmentController.class,
                null
        );
        assertEquals(AuthzTenantScopeMode.ORGANIZATIONAL_UNIT, spec.tenantScopeMode());
        assertEquals("organizationUnitId", spec.tenantFieldName());
        assertEquals(AuthzCallerContext.FACT_AUTHORIZED_ORGANIZATION_IDS, spec.tenantScopeSpec().subjectFactPath());
        assertTrue(spec.hasImmutableTenantAnchor());
        assertNotNull(spec.dualScopeDelegationSpec());
        assertTrue(spec.actionDecisionPoints().containsKey("approve"));
        assertTrue(spec.actionDecisionPoints().containsKey("acknowledge"));
        assertFalse(spec.actionDecisionPoints().get("acknowledge").supportedCapabilities()
                .contains(EnforcementCapability.FIELD_WRITE),
                "Transition-only @AuthzActionRule(allowedWriteAttributes={}) must omit FIELD_WRITE");
        assertTrue(spec.surfaceDecisionPoints().containsKey("salary-summary"));
        assertTrue(spec.factContract().descriptorsByPath().containsKey("subject.roles"));
        assertTrue(spec.factContract().descriptorsByPath().containsKey("resource.status"));

        // Verify TENANT_ONLY normalizes default subjectFactPath -> subject.tenantId
        AuthzResourceGovernanceSpec<CatalogEntity> catalogSpec = AuthzResourceGovernanceSpec.fromAnnotatedResource(
                "workforce-hr",
                CatalogEntity.class,
                CatalogResponseDTO.class,
                CatalogFilterDTO.class,
                AnnotatedCatalogController.class
        );
        assertEquals(AuthzTenantScopeMode.TENANT_ONLY, catalogSpec.tenantScopeMode());
        assertEquals("subject.tenantId", catalogSpec.tenantScopeSpec().subjectFactPath());
        assertTrue(catalogSpec.factContract().descriptorsByPath().containsKey("subject.tenantId"));

        // Zero-config policy synthesis builds OPA bundle with real Rego disjunctive role branches
        AuthzHostPolicyBootstrapBuilder.AuthzHostPolicyBootstrapBundle bundle =
                AuthzHostPolicyBootstrapBuilder.forService("workforce-hr")
                        .addAnnotatedResource(
                                spec,
                                AssignmentResponseDTO.class,
                                AssignmentCreateDTO.class,
                                AssignmentUpdateDTO.class
                        )
                        .addAnnotatedResource(catalogSpec, CatalogResponseDTO.class, null, null)
                        .build();

        CompiledRegoUnit approveUnit = bundle.bundleArtifact().compiledUnits().stream()
                .filter(u -> u.sourcePolicy().policyId().contains("-act-approve"))
                .findFirst()
                .orElseThrow();
        assertTrue(approveUnit.regoSource().contains("HR_MANAGER"), "Compiled Rego must include HR_MANAGER branch");
        assertTrue(approveUnit.regoSource().contains("PAYROLL_DIRECTOR"), "Compiled Rego must include PAYROLL_DIRECTOR branch");
        assertFalse(approveUnit.regoSource().contains("UNSUPPORTED_DISJUNCTION"),
                "Disjunctive roles must compile to real Rego branches without compiler comments");

        // AUTHZ-HOST-010 passes cleanly with zero issues
        RuntimeDecisionPointRegistry registry = new RuntimeDecisionPointRegistry(
                bundle.admissionRecords(), bundle.coordinates());
        AuthzHostReadinessReviewer reviewer = new AuthzHostReadinessReviewer(
                introspector, registry, bundle.coordinates());
        ReadinessReport report = reviewer.reviewGovernanceSpec(
                spec,
                AssignmentEntity.class,
                AssignmentResponseDTO.class,
                AssignmentFilterDTO.class,
                AssignmentCreateDTO.class,
                AssignmentUpdateDTO.class
        );
        report.assertZeroIssues();
    }

    @Test
    void testMultiOrganizationHardScopeResolverSemanticsAndWriteInvariants() {
        MultiOrganizationHardScopeResolver resolver = new MultiOrganizationHardScopeResolver();
        AuthzResourceGovernanceSpec<AssignmentEntity> spec = AuthzResourceGovernanceSpec.fromAnnotatedResource(
                "workforce-hr",
                "workforce.assignments",
                null,
                AssignmentEntity.class,
                AssignmentResponseDTO.class,
                AssignmentFilterDTO.class,
                AssignmentCreateDTO.class,
                AssignmentUpdateDTO.class,
                AnnotatedAssignmentController.class,
                null
        );

        // 1. Single value
        AuthzCallerContext singleCtx = AuthzCallerContext.of("tenant-a", Map.of(
                "subject.principalId", "alice",
                AuthzCallerContext.FACT_AUTHORIZED_ORGANIZATION_IDS, List.of(10L)
        ));
        HardScopeSelection singleSel = resolver.resolveSelection(spec, singleCtx);
        assertEquals(HardScopeMode.SINGLE_VALUE, singleSel.mode());
        assertEquals("e.organizationUnitId = :__praxis_hard_tenant_id", resolver.buildJpqlPredicate(spec, singleCtx));
        assertEquals(Map.of("__praxis_hard_tenant_id", 10L), resolver.buildJpqlParams(spec, singleCtx));

        // 2. Multi-organization (IN)
        AuthzCallerContext multiCtx = AuthzCallerContext.of("tenant-a", Map.of(
                "subject.principalId", "alice",
                AuthzCallerContext.FACT_AUTHORIZED_ORGANIZATION_IDS, List.of(10L, 20L)
        ));
        HardScopeSelection multiSel = resolver.resolveSelection(spec, multiCtx);
        assertEquals(HardScopeMode.MULTI_ORGANIZATION, multiSel.mode());
        assertEquals("e.organizationUnitId IN :__praxis_hard_tenant_ids", resolver.buildJpqlPredicate(spec, multiCtx));
        @SuppressWarnings("unchecked")
        java.util.Collection<Object> multiParamVals =
                (java.util.Collection<Object>) resolver.buildJpqlParams(spec, multiCtx).get("__praxis_hard_tenant_ids");
        assertEquals(Set.of(10L, 20L), Set.copyOf(multiParamVals));

        AssignmentEntity inOrg20 = new AssignmentEntity();
        inOrg20.organizationUnitId = 20L;
        resolver.verifyEntityAccess(spec, inOrg20, multiCtx);

        AssignmentEntity inOrg99 = new AssignmentEntity();
        inOrg99.organizationUnitId = 99L;
        assertThrows(SecurityException.class, () ->
                resolver.verifyEntityAccess(spec, inOrg99, multiCtx));

        // 3. Explicitly empty organization set fails closed -> DENIED (1 = 0)
        AuthzCallerContext emptyOrgCtx = AuthzCallerContext.of("tenant-a", Map.of(
                "subject.principalId", "alice",
                AuthzCallerContext.FACT_AUTHORIZED_ORGANIZATION_IDS, List.of()
        ));
        assertEquals(HardScopeMode.DENIED, resolver.resolveSelection(spec, emptyOrgCtx).mode());
        assertEquals("1 = 0", resolver.buildJpqlPredicate(spec, emptyOrgCtx));
        assertEquals(ResourceFilterAccessScope.Mode.DENIED, resolver.buildCriteriaScope(spec, emptyOrgCtx).mode());
        assertThrows(SecurityException.class, () ->
                resolver.verifyEntityAccess(spec, inOrg20, emptyOrgCtx));

        // 4. Consolidation read-only guard allows read, denies write
        AuthzCallerContext consolidationCtx = AuthzCallerContext.of("tenant-a", Map.of(
                "subject.principalId", "auditor",
                AuthzCallerContext.FACT_AUTHORIZED_ORGANIZATION_IDS, List.of(10L, 20L),
                AuthzCallerContext.FACT_READ_ONLY_CONSOLIDATION_SCOPE, true
        ));
        resolver.verifyEntityAccess(spec, inOrg20, consolidationCtx);
        SecurityException consWriteEx = assertThrows(SecurityException.class, () ->
                resolver.verifyWritableTarget(spec, inOrg20, null, consolidationCtx));
        assertTrue(consWriteEx.getMessage().contains("AUTHZ_CONSOLIDATION_READ_ONLY_SCOPE"));

        // 5. Immutable scope anchor check forbids changing organizationUnitId even within caller's multi-org set
        AssignmentEntity prevOrg10 = new AssignmentEntity();
        prevOrg10.organizationUnitId = 10L;
        SecurityException anchorImmutableEx = assertThrows(SecurityException.class, () ->
                resolver.verifyWritableTarget(spec, inOrg20, prevOrg10, multiCtx));
        assertTrue(anchorImmutableEx.getMessage().contains("AUTHZ_SCOPE_ANCHOR_IMMUTABLE"));

        // 6. SHARED_UNRESTRICTED for AUTHENTICATED_SHARED
        AuthzResourceGovernanceSpec<CatalogEntity> sharedSpec = AuthzResourceGovernanceSpec
                .<CatalogEntity>builder("workforce.catalogs")
                .tenantScope(new AuthzResourceGovernanceSpec.TenantScopeSpec(
                        AuthzTenantScopeMode.AUTHENTICATED_SHARED, "tenantId", null, null, null, null, false, null))
                .queryAdapter(spec.queryProjection(), spec.fieldBindings())
                .decisionPoint(spec.decisionPoint())
                .factContractDigest(spec.factContractDigest())
                .build();
        assertEquals(HardScopeMode.SHARED_UNRESTRICTED, resolver.resolveSelection(sharedSpec, multiCtx).mode());
        assertEquals("1 = 1", resolver.buildJpqlPredicate(sharedSpec, multiCtx));
        assertTrue(resolver.buildJpqlParams(sharedSpec, multiCtx).isEmpty());
    }

    @Test
    void testEndToEndInterceptorAvailabilityRuleHardScopeOutboxMaskingAndAgentBridge() {
        String dbName = "wave14b_" + UUID.randomUUID().toString().replace("-", "");
        DriverManagerDataSource dataSource = new DriverManagerDataSource(
                "jdbc:h2:mem:" + dbName + ";DB_CLOSE_DELAY=-1;MODE=PostgreSQL", "sa", "");
        LocalContainerEntityManagerFactoryBean emfBean = new LocalContainerEntityManagerFactoryBean();
        emfBean.setDataSource(dataSource);
        emfBean.setPackagesToScan(Wave14BPromotedCapabilitiesTest.class.getPackageName());
        emfBean.setPersistenceProviderClass(HibernatePersistenceProvider.class);
        emfBean.setJpaVendorAdapter(new HibernateJpaVendorAdapter());
        Properties jpaProps = new Properties();
        jpaProps.setProperty("hibernate.hbm2ddl.auto", "create-drop");
        jpaProps.setProperty("hibernate.dialect", "org.hibernate.dialect.H2Dialect");
        emfBean.setJpaProperties(jpaProps);
        emfBean.afterPropertiesSet();

        var emf = Objects.requireNonNull(emfBean.getObject());
        JpaTransactionManager txManager = new JpaTransactionManager(emf);
        TransactionTemplate txTemplate = new TransactionTemplate(txManager);
        EntityManager sharedEm = SharedEntityManagerCreator.createSharedEntityManager(emf);
        JdbcTemplate jdbcTemplate = new JdbcTemplate(dataSource);
        JpaRepositoryFactory repoFactory = new JpaRepositoryFactory(sharedEm);
        AssignmentRepository assignmentRepo = repoFactory.getRepository(AssignmentRepository.class);
        CatalogRepository catalogRepo = repoFactory.getRepository(CatalogRepository.class);

        AuthzResourceGovernanceSpec<AssignmentEntity> assignmentSpec = AuthzResourceGovernanceSpec.fromAnnotatedResource(
                "workforce-hr",
                "workforce.assignments",
                null,
                AssignmentEntity.class,
                AssignmentResponseDTO.class,
                AssignmentFilterDTO.class,
                AssignmentCreateDTO.class,
                AssignmentUpdateDTO.class,
                AnnotatedAssignmentController.class,
                null
        );
        AuthzResourceGovernanceSpec<CatalogEntity> catalogSpec = AuthzResourceGovernanceSpec.fromAnnotatedResource(
                "workforce-hr",
                "workforce.catalogs",
                null,
                CatalogEntity.class,
                CatalogResponseDTO.class,
                CatalogFilterDTO.class,
                null,
                null,
                AnnotatedCatalogController.class,
                null
        );

        AuthzHostPolicyBootstrapBuilder.AuthzHostPolicyBootstrapBundle bundle =
                AuthzHostPolicyBootstrapBuilder.forService("workforce-hr")
                        .addAnnotatedResource(
                                assignmentSpec,
                                AssignmentResponseDTO.class,
                                AssignmentCreateDTO.class,
                                AssignmentUpdateDTO.class
                        )
                        .addAnnotatedResource(catalogSpec, CatalogResponseDTO.class, null, null)
                        .build();

        // Seed H2 rows across orgs 10L, 20L, and 99L, plus tenant-a vs tenant-b catalogs
        txTemplate.executeWithoutResult(st -> {
            AssignmentEntity a1 = new AssignmentEntity();
            a1.id = 1L;
            a1.tenantId = "tenant-a";
            a1.organizationUnitId = 10L;
            a1.destinationUnitId = 30L;
            a1.employeeName = "Alice";
            a1.status = "PENDING";
            a1.taxId = "12345678901";
            a1.documentCode = "52998224725";
            a1.salaryAmount = new BigDecimal("8500.00");
            a1.riskScore = 42;
            a1.pinCode = "9999";
            assignmentRepo.save(a1);

            AssignmentEntity a2 = new AssignmentEntity();
            a2.id = 2L;
            a2.tenantId = "tenant-a";
            a2.organizationUnitId = 20L;
            a2.destinationUnitId = 30L;
            a2.employeeName = "Bob";
            a2.status = "APPROVED";
            a2.taxId = "98765432100";
            a2.documentCode = "11122233344";
            a2.salaryAmount = new BigDecimal("9500.00");
            a2.riskScore = 15;
            a2.pinCode = "8888";
            assignmentRepo.save(a2);

            AssignmentEntity a99 = new AssignmentEntity();
            a99.id = 3L;
            a99.tenantId = "tenant-a";
            a99.organizationUnitId = 99L;
            a99.destinationUnitId = 30L;
            a99.employeeName = "Carol";
            a99.status = "PENDING";
            a99.taxId = "55555555555";
            a99.documentCode = "22233344455";
            a99.salaryAmount = new BigDecimal("11000.00");
            a99.riskScore = 7;
            a99.pinCode = "7777";
            assignmentRepo.save(a99);

            CatalogEntity c1 = new CatalogEntity();
            c1.id = 10L;
            c1.tenantId = "tenant-a";
            c1.code = "C-A";
            c1.title = "Tenant A Catalog";
            catalogRepo.save(c1);

            CatalogEntity c2 = new CatalogEntity();
            c2.id = 20L;
            c2.tenantId = "tenant-b";
            c2.code = "C-B";
            c2.title = "Tenant B Catalog";
            catalogRepo.save(c2);
        });

        AtomicBoolean maintenanceFreezeActive = new AtomicBoolean(false);
        ResourceOperationAvailabilityRule maintenanceHostRule = context -> {
            if (maintenanceFreezeActive.get() && "approve".equals(context.operationId())) {
                return AvailabilityDecision.deny("MAINTENANCE_FREEZE", Map.of("freeze", true));
            }
            return AvailabilityDecision.allowAll();
        };

        try {
            new ApplicationContextRunner()
                    .withConfiguration(AutoConfigurations.of(
                            PraxisAuthzAutoConfiguration.class,
                            PraxisAuthzHostBridgeAutoConfiguration.class,
                            PraxisAuthzAgentBridgeAutoConfiguration.class
                    ))
                    .withBean(DataSource.class, () -> dataSource)
                    .withBean(JdbcTemplate.class, () -> jdbcTemplate)
                    .withBean(jakarta.persistence.EntityManagerFactory.class, () -> emf)
                    .withBean(PlatformTransactionManager.class, () -> txManager)
                    .withBean(CollectionExportExecutor.class, () -> new DefaultCollectionExportExecutor(List.of(new CsvCollectionExportEngine())))
                    .withBean(AuthzHostPolicyBootstrapBuilder.AuthzHostPolicyBootstrapBundle.class, () -> bundle)
                    .withBean(AuthzResourceGovernanceSpec.class, () -> assignmentSpec)
                    .withBean("catalogGovernanceSpec", AuthzResourceGovernanceSpec.class, () -> catalogSpec)
                    .withBean("hostMaintenanceAvailabilityRule", ResourceOperationAvailabilityRule.class, () -> maintenanceHostRule)
                    .withBean(AnnotatedAssignmentController.class, AnnotatedAssignmentController::new)
                    .withBean(AnnotatedCatalogController.class, AnnotatedCatalogController::new)
                    .withBean(PlainAssignmentService.class, () ->
                            new PlainAssignmentService(assignmentRepo, new GenericSpecificationsBuilder<>()))
                    .withBean(PlainCatalogReadOnlyService.class, () ->
                            new PlainCatalogReadOnlyService(catalogRepo, new GenericSpecificationsBuilder<>()))
                    .run(ctx -> {
                        assertNull(ctx.getStartupFailure(), "Auto-configuration should start cleanly");
                        assertInstanceOf(MultiOrganizationHardScopeResolver.class, ctx.getBean(HardScopeResolver.class));
                        assertNotNull(ctx.getBean(AuthzResourceOperationAvailabilityRule.class));

                        // Primary ResourceOperationAvailabilityProvider is CompositeResourceOperationAvailabilityEvaluator
                        ResourceOperationAvailabilityProvider primaryAvail = ctx.getBean(ResourceOperationAvailabilityProvider.class);
                        assertInstanceOf(CompositeResourceOperationAvailabilityEvaluator.class, primaryAvail);
                        assertNotNull(ctx.getBean(AuthzResourceOperationAvailabilityProvider.class));
                        assertNotNull(ctx.getBean(AuthzAgentAuthorizationBridge.class));

                        var interceptor = ctx.getBean(org.praxisplatform.authz.host.metadata.AuthzResourceGovernanceInterceptor.class);
                        var callerProvider = ctx.getBean(ThreadLocalAuthzCallerContextProvider.class);
                        var plainService = ctx.getBean(PlainAssignmentService.class);
                        var plainCatalogService = ctx.getBean(PlainCatalogReadOnlyService.class);
                        var jdbcOutbox = ctx.getBean(JdbcTransactionalAuditOutbox.class);
                        var readinessReviewer = ctx.getBean(AuthzHostReadinessReviewer.class);

                        // Readiness reviewer checks interceptor-governed plain services -> AUTHZ-HOST-010 clean!
                        ReadinessReport interceptorReport = readinessReviewer.reviewInterceptorBoundServices(
                                List.of(plainService, plainCatalogService),
                                Map.of("workforce.assignments", assignmentSpec, "workforce.catalogs", catalogSpec)
                        );
                        interceptorReport.assertZeroIssues();

                        AuthzCallerContext multiOrgManager = AuthzCallerContext.of("tenant-a", Map.of(
                                "subject.principalId", "mgr-alice",
                                "subject.tenantId", "tenant-a",
                                "subject.roles", List.of("HR_MANAGER"),
                                AuthzCallerContext.FACT_AUTHORIZED_ORGANIZATION_IDS, List.of(10L, 20L),
                                "subject.organizationUnitIds", List.of(10L, 20L)
                        ));

                        callerProvider.runWithContext(multiOrgManager, () -> {
                            // 1. Filtered read across multiple organizations (10L, 20L) excludes 99L and masks sensitive fields
                            Page<AssignmentResponseDTO> page = txTemplate.execute(s ->
                                    plainService.filter(new AssignmentFilterDTO(), PageRequest.of(0, 10, Sort.by("id")), List.of()));
                            assertNotNull(page);
                            assertEquals(2, page.getTotalElements(), "Multi-org scope [10, 20] must exclude org 99L");
                            AssignmentResponseDTO r1 = page.getContent().get(0);
                            assertEquals("***", r1.taxId, "Derived @DomainGovernance String mask -> ***");
                            assertTrue(r1.documentCode != null && r1.documentCode.endsWith("25") && r1.documentCode.contains("*"),
                                    "Explicit @AuthzMask CPF_CNPJ_PARTIAL overrides derived mask");
                            assertNull(r1.salaryAmount, "Derived @DomainGovernance non-String mask -> NULLIFY");
                            assertEquals(0, r1.riskScore, "Derived @DomainGovernance primitive int -> VALUE+DENY / OMIT_BY_FIELD_USE_DENY (default 0)");
                            assertNull(r1.pinCode, "CREDENTIAL field must stay VALUE+DENY (null)");

                            // 2. Out-of-scope ID #3 (org 99L) rejected fail-closed
                            assertThrows(SecurityException.class, () ->
                                    txTemplate.execute(s -> plainService.findById(3L)));

                            // 3. TENANT_ONLY read-only plain service isolates tenant-a vs tenant-b
                            Page<CatalogResponseDTO> catalogs = txTemplate.execute(s ->
                                    plainCatalogService.filter(new CatalogFilterDTO(), PageRequest.of(0, 10), List.of()));
                            assertEquals(1, catalogs.getTotalElements());
                            assertEquals("C-A", catalogs.getContent().getFirst().code);

                            // 4. Stats & export filtering on plain service strip restricted/VALUE+DENY fields
                            StatsFieldRegistry filteredStats = interceptor.filterStatsRegistry(
                                    plainService,
                                    StatsFieldRegistry.of(List.of(
                                            StatsFieldDescriptor.groupByBucket("status", "status", Set.of(StatsMetric.COUNT)),
                                            StatsFieldDescriptor.groupByBucket("pinCode", "pinCode", Set.of(StatsMetric.COUNT)),
                                            StatsFieldDescriptor.groupByBucket("taxId", "taxId", Set.of(StatsMetric.COUNT))
                                    ))
                            );
                            assertTrue(filteredStats.descriptors().stream().anyMatch(d -> "status".equals(d.field())));
                            assertFalse(filteredStats.descriptors().stream().anyMatch(d -> "pinCode".equals(d.field())));

                            List<CollectionExportField> filteredExport = interceptor.filterExportFields(
                                    plainService, plainService.exportFields());
                            assertTrue(filteredExport.stream().anyMatch(f -> "employeeName".equals(f.key())));
                            assertFalse(filteredExport.stream().anyMatch(f -> "taxId".equals(f.key())));
                            assertFalse(filteredExport.stream().anyMatch(f -> "pinCode".equals(f.key())));

                            // 5. Create via plain service succeeds for authorized org 10L, persists outbox, returns masked DTO
                            int outboxBefore = jdbcOutbox.listCommittedEntries().size();
                            var created = txTemplate.execute(s -> plainService.create(new AssignmentCreateDTO(
                                    4L, "tenant-a", 10L, 30L, "Dave", null,
                                    "44455566677", "99988877766", new BigDecimal("7000.00"), 12
                            )));
                            assertNotNull(created);
                            assertEquals(4L, created.id());
                            assertEquals("***", created.body().taxId);
                            assertTrue(jdbcOutbox.listCommittedEntries().size() > outboxBefore,
                                    "Interceptor must fulfill BEFORE_COMMIT_OUTBOX on create");

                            // 6. Create targeting unauthorized org 99L fails closed before persistence
                            assertThrows(SecurityException.class, () -> txTemplate.execute(s -> plainService.create(
                                    new AssignmentCreateDTO(5L, "tenant-a", 99L, 30L, "Eve", null,
                                            "11111111111", "22222222222", new BigDecimal("6000.00"), 5))));

                            // 7. Update mutating or clearing immutable @AuthzScopeAnchor organizationUnitId fails closed!
                            assertThrows(SecurityException.class, () -> txTemplate.execute(s -> plainService.update(
                                    4L, new AssignmentUpdateDTO(20L, "Dave Updated", "PENDING"))));
                            assertThrows(SecurityException.class, () -> txTemplate.execute(s -> plainService.update(
                                    4L, new AssignmentUpdateDTO(null, "Dave Updated", "PENDING"))));

                            // 8. Non-anchor update with unchanged anchor & unchanged destination status omits deltas, writes outbox, masks response
                            AssignmentResponseDTO updated = txTemplate.execute(s -> plainService.update(
                                    4L, new AssignmentUpdateDTO(10L, "Dave Promoted", "PENDING")));
                            assertEquals("Dave Promoted", updated.employeeName);
                            assertEquals("***", updated.taxId);

                            // 9. Delete fulfills outbox and removes row #4
                            int outboxBeforeDel = jdbcOutbox.listCommittedEntries().size();
                            txTemplate.executeWithoutResult(s -> plainService.deleteById(4L));
                            assertTrue(jdbcOutbox.listCommittedEntries().size() > outboxBeforeDel);

                            // 10. Composite availability evaluator + AuthzResourceOperationAvailabilityRule + host rule
                            // Origin-only caller lacks destination custody required by approve's allowedWriteAttributes (status)
                            AvailabilityDecision denyOriginOnlyApprove = primaryAvail.evaluate(
                                    ResourceOperationAvailabilityContext.item(
                                            "workforce.assignments", "/api/workforce/assignments", "approve", 1L));
                            assertFalse(denyOriginOnlyApprove.allowed(),
                                    "Origin-only HR_MANAGER without destination custody must be denied destination-partitioned approve");

                            // Caller holding BOTH origin scope (for entity read) and destination custody (30L)
                            AuthzCallerContext destinationApprover = AuthzCallerContext.of("tenant-a", Map.of(
                                    "subject.principalId", "dest-hr-alice",
                                    "subject.tenantId", "tenant-a",
                                    "subject.roles", List.of("HR_MANAGER"),
                                    AuthzCallerContext.FACT_AUTHORIZED_ORGANIZATION_IDS, List.of(10L, 20L),
                                    "subject.organizationUnitIds", List.of(10L, 20L),
                                    "subject.destinationUnitIds", List.of(30L)
                            ));
                            callerProvider.runWithContext(destinationApprover, () -> {
                                AvailabilityDecision allowApprove = primaryAvail.evaluate(
                                        ResourceOperationAvailabilityContext.item(
                                                "workforce.assignments", "/api/workforce/assignments", "approve", 1L));
                                assertTrue(allowApprove.allowed(), "Destination HR_MANAGER should be allowed to approve PENDING #1");

                                AvailabilityDecision denyApprovedRow = primaryAvail.evaluate(
                                        ResourceOperationAvailabilityContext.item(
                                                "workforce.assignments", "/api/workforce/assignments", "approve", 2L));
                                assertFalse(denyApprovedRow.allowed(), "APPROVED row #2 cannot trigger PENDING-only approve");

                                maintenanceFreezeActive.set(true);
                                AvailabilityDecision denyByHostRule = primaryAvail.evaluate(
                                        ResourceOperationAvailabilityContext.item(
                                                "workforce.assignments", "/api/workforce/assignments", "approve", 1L));
                                assertFalse(denyByHostRule.allowed(), "Host rule maintenance freeze must deny-win over Authz permit");
                                assertEquals("MAINTENANCE_FREEZE", denyByHostRule.reason());
                                maintenanceFreezeActive.set(false);
                            });

                            // 11. PraxisAuthzAgentBridgeAutoConfiguration compatibility check
                            AuthzAgentAuthorizationBridge agentBridge = ctx.getBean(AuthzAgentAuthorizationBridge.class);
                            assertTrue(agentBridge.canReadResource(
                                    new AgentExecutionContext(
                                            UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID(),
                                            "tenant-a", "mgr-alice", "prod", "mgr-alice",
                                            Set.of("HR_MANAGER"), null, null, Map.of(), Map.of()),
                                    "/api/workforce/assignments"
                            ));
                        });

                        // 12. Verify AuthzResourceGovernanceInterceptor strictly bypasses AbstractAuthzGovernedResourceService
                        ExplicitGovernedDummyService explicitDummy = new ExplicitGovernedDummyService(
                                assignmentRepo,
                                ctx.getBean(AuthzGovernedResourceServiceSupport.class),
                                callerProvider,
                                assignmentSpec
                        );
                        ResourceFilterAccessScope<AssignmentEntity> dummyBase = ResourceFilterAccessScope.unrestricted();
                        assertEquals(dummyBase, interceptor.customizeFilterAccessScope(explicitDummy, dummyBase));
                        AssignmentEntity unauthDummy = new AssignmentEntity();
                        unauthDummy.organizationUnitId = 999L;
                        interceptor.verifyEntityAccess(explicitDummy, unauthDummy, AccessMode.READ);
                        interceptor.beforeMutation(explicitDummy,
                                new MutationContext(MutationKind.CREATE, false, List.of(), null, null),
                                unauthDummy, null);
                    });
        } finally {
            emf.close();
        }
    }
}
