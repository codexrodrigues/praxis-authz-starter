package org.praxisplatform.authz.starter;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.Entity;
import jakarta.persistence.EntityManager;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.lang.reflect.Proxy;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Properties;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import org.aopalliance.intercept.MethodInterceptor;
import org.hibernate.jpa.HibernatePersistenceProvider;
import org.hibernate.proxy.HibernateProxy;
import org.hibernate.proxy.LazyInitializer;
import org.junit.jupiter.api.Test;
import org.praxisplatform.authz.autoconfigure.PraxisAuthzHostBridgeAutoConfiguration;
import org.praxisplatform.authz.contracts.annotation.AuthzTenantScope;
import org.praxisplatform.authz.contracts.annotation.AuthzTenantScopeMode;
import org.praxisplatform.authz.contracts.context.FactCardinality;
import org.praxisplatform.authz.contracts.context.FactPresenceModel;
import org.praxisplatform.authz.contracts.context.FactResolutionStatus;
import org.praxisplatform.authz.contracts.context.FactValueType;
import org.praxisplatform.authz.contracts.datascope.DataScopeOutcome;
import org.praxisplatform.authz.contracts.datascope.SearchPredicateOperator;
import org.praxisplatform.authz.contracts.decisionpoint.EvaluationMode;
import org.praxisplatform.authz.contracts.envelope.ContributionAuthority;
import org.praxisplatform.authz.contracts.envelope.ObligationDirective;
import org.praxisplatform.authz.contracts.envelope.RuleEffect;
import org.praxisplatform.authz.contracts.obligation.DefaultObligationHandlerRegistry;
import org.praxisplatform.authz.contracts.policy.AccessContributionSpec;
import org.praxisplatform.authz.contracts.policy.AuthorizationPolicyRule;
import org.praxisplatform.authz.contracts.policy.AuthorizationRuleContributions;
import org.praxisplatform.authz.contracts.policy.AuthorizationSourceCondition;
import org.praxisplatform.authz.contracts.policy.ConditionProfileKind;
import org.praxisplatform.authz.contracts.policy.MaskContributionSpec;
import org.praxisplatform.authz.contracts.policy.PolicyFieldSelector;
import org.praxisplatform.authz.enforcement.context.UntrustedHeaderSpoofingException;
import org.praxisplatform.authz.enforcement.context.UntrustedRequestHeaderGuard;
import org.praxisplatform.authz.enforcement.fielduse.FieldUseQueryGuard;
import org.praxisplatform.authz.enforcement.jpa.JpaDataScopeAdapter;
import org.praxisplatform.authz.enforcement.masking.DetachedDtoMaskingProcessor;
import org.praxisplatform.authz.enforcement.obligation.ObligationBarrierCoordinator;
import org.praxisplatform.authz.enforcement.writeintent.DtoWriteIntentExtractor;
import org.praxisplatform.authz.enforcement.writeintent.FieldWriteAuthorizer;
import org.praxisplatform.authz.host.metadata.AuthzAccessDeniedException;
import org.praxisplatform.authz.host.metadata.AuthzCallerContext;
import org.praxisplatform.authz.host.metadata.AuthzCallerContextFilter;
import org.praxisplatform.authz.host.metadata.AuthzCallerContextHttpResolver;
import org.praxisplatform.authz.host.metadata.AuthzGovernedResourceServiceSupport;
import org.praxisplatform.authz.host.metadata.AuthzHostPolicyBootstrapBuilder;
import org.praxisplatform.authz.host.metadata.AuthzResourceGovernanceInterceptor;
import org.praxisplatform.authz.host.metadata.AuthzResourceGovernanceSpec;
import org.praxisplatform.authz.host.metadata.AuthzResourceOperationAvailabilityProvider;
import org.praxisplatform.authz.host.metadata.PraxisAuthzExceptionHandler;
import org.praxisplatform.authz.host.metadata.ThreadLocalAuthzCallerContextProvider;
import org.praxisplatform.authz.opa.client.OpaAuthorizationProviderAdapter;
import org.praxisplatform.authz.opa.revision.SameInstanceSearchRevisionGuard;
import org.praxisplatform.authz.outbox.JdbcTransactionalAuditOutbox;
import org.praxisplatform.authz.seams.MetadataResourceAuthorizationSeam;
import org.praxisplatform.authz.telemetry.SanitizedAuthorizationTelemetryPublisher;
import org.praxisplatform.uischema.action.ActionAvailabilityContext;
import org.praxisplatform.uischema.action.ActionDefinition;
import org.praxisplatform.uischema.action.ActionExecutionContract;
import org.praxisplatform.uischema.action.ActionScope;
import org.praxisplatform.uischema.capability.AvailabilityDecision;
import org.praxisplatform.uischema.capability.ResourceOperationAvailabilityContext;
import org.praxisplatform.uischema.capability.ResourceStateSnapshot;
import org.praxisplatform.uischema.capability.ResourceStateSnapshotScope;
import org.praxisplatform.uischema.filter.dto.GenericFilterDTO;
import org.praxisplatform.uischema.filter.specification.GenericSpecificationsBuilder;
import org.praxisplatform.uischema.governance.AccessMode;
import org.praxisplatform.uischema.mapper.base.ResourceMapper;
import org.praxisplatform.uischema.repository.base.BaseCrudRepository;
import org.praxisplatform.uischema.service.base.AbstractBaseResourceService;
import org.praxisplatform.uischema.service.base.BaseResourceQueryService;
import org.praxisplatform.uischema.surface.SurfaceAvailabilityContext;
import org.praxisplatform.uischema.surface.SurfaceDefinition;
import org.praxisplatform.uischema.surface.SurfaceKind;
import org.praxisplatform.uischema.surface.SurfaceResponseCardinality;
import org.praxisplatform.uischema.surface.SurfaceScope;
import org.springframework.aop.framework.ProxyFactory;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.data.jpa.repository.support.JpaRepositoryFactory;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.orm.jpa.SharedEntityManagerCreator;
import org.springframework.orm.jpa.vendor.HibernateJpaVendorAdapter;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.transaction.annotation.AnnotationTransactionAttributeSource;
import org.springframework.transaction.interceptor.TransactionInterceptor;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Regression tests for {@code praxis-authz-starter:0.1.0-beta.3} hotfixes:
 * <ul>
 *   <li>Actual HTTP header values in {@link AuthzCallerContext} avoiding false-positive spoofing denials;</li>
 *   <li>Automatic bundle {@code resourceSpecs()} consumption in {@link AuthzResourceGovernanceInterceptor};</li>
 *   <li>Opt-in {@code action.verb} and subject facts on {@code TARGET} evaluation plus bootstrap builder overloads.</li>
 * </ul>
 */
class Wave3StarterHotfixRegressionTest {

    @SuppressWarnings("unused")
    private static class SampleOrgEntity {
        public Long id;
        public Long organizationId;
        public String name;
        public String secretCode;
    }

    @SuppressWarnings("unused")
    private static final class ComputedGetterResponseDTO {
        @JsonProperty(access = JsonProperty.Access.READ_ONLY)
        public Long id;

        @JsonProperty(access = JsonProperty.Access.READ_ONLY)
        public Boolean ativo = true;

        public String name;
        public String secretCode;

        public Long getComputedOccupiedCount() {
            return 4L;
        }
    }

    private static MetadataResourceAuthorizationSeam createSeam(
            AuthzHostPolicyBootstrapBuilder.AuthzHostPolicyBootstrapBundle bundle,
            TransactionTemplate txTemplate,
            JdbcTemplate jdbcTemplate
    ) {
        JdbcTransactionalAuditOutbox jdbcOutbox = new JdbcTransactionalAuditOutbox(
                jdbcTemplate, "praxis_authz_obligation_outbox", true, true
        );
        OpaAuthorizationProviderAdapter opaAdapter = new OpaAuthorizationProviderAdapter(
                bundle.localOpaTransport(),
                new SameInstanceSearchRevisionGuard(1)
        );
        return new MetadataResourceAuthorizationSeam(
                opaAdapter,
                new FieldUseQueryGuard(),
                new DtoWriteIntentExtractor(),
                new FieldWriteAuthorizer(),
                new DetachedDtoMaskingProcessor(),
                new ObligationBarrierCoordinator(new DefaultObligationHandlerRegistry(), jdbcOutbox),
                new SanitizedAuthorizationTelemetryPublisher(List.of(), 100)
        );
    }

    @Test
    void callerContextFilterCapturesIncomingHeadersSoValidTenantHeadersPassAndSpoofingStillFails()
            throws Exception {
        AuthzResourceGovernanceSpec<SampleOrgEntity> orgSpec = AuthzResourceGovernanceSpec
                .<SampleOrgEntity>builder("workforce.orgs")
                .serviceKey("workforce-svc")
                .scalarFieldBinding("resource.organizationId", "organizationId", "e.organizationId")
                .build();

        AuthzHostPolicyBootstrapBuilder.AuthzHostPolicyBootstrapBundle bundle =
                AuthzHostPolicyBootstrapBuilder.forService("workforce-svc")
                        .addResourceSpec(orgSpec, SampleOrgEntity.class, SampleOrgEntity.class, SampleOrgEntity.class)
                        .addOrganizationalScopePolicy(
                                orgSpec,
                                "rule-workforce-orgs-scope",
                                "resource.organizationId",
                                "subject.organizationUnitIds",
                                Map.of()
                        )
                        .build();

        DriverManagerDataSource ds = new DriverManagerDataSource(
                "jdbc:h2:mem:wave3_headers_test;MODE=PostgreSQL;DB_CLOSE_DELAY=-1", "sa", "");
        JdbcTemplate jdbcTemplate = new JdbcTemplate(ds);
        TransactionTemplate txTemplate = new TransactionTemplate(new DataSourceTransactionManager(ds));
        MetadataResourceAuthorizationSeam seam = createSeam(bundle, txTemplate, jdbcTemplate);
        JpaDataScopeAdapter jpaAdapter = new JpaDataScopeAdapter(orgSpec.queryProjection(), orgSpec.fieldBindings());

        ThreadLocalAuthzCallerContextProvider callerProvider = new ThreadLocalAuthzCallerContextProvider();
        AuthzCallerContextHttpResolver resolver = request -> Optional.of(new AuthzCallerContext(
                "1",
                Map.of(
                        "subject.principalId", "manager@org1",
                        "subject.organizationUnitIds", List.of(10L)
                ),
                Map.of(
                        "subject.principalId", FactResolutionStatus.PRESENT,
                        "subject.organizationUnitIds", FactResolutionStatus.PRESENT
                ),
                Set.of(),
                Map.of(),
                null,
                null
        ));
        AuthzCallerContextFilter filter = new AuthzCallerContextFilter(
                resolver,
                callerProvider,
                new PraxisAuthzExceptionHandler(),
                new ObjectMapper().registerModule(new com.fasterxml.jackson.datatype.jsr310.JavaTimeModule())
        );

        // 1. Legitimate HTTP headers matching authoritative tenant/principal must pass SEARCH + mutation checks
        MockHttpServletRequest validRequest = new MockHttpServletRequest("POST", "/api/workforce/orgs/filter");
        validRequest.addHeader("X-Tenant-ID", "1");
        validRequest.addHeader("X-User-ID", "manager@org1");
        validRequest.addHeader("Accept", "application/json");
        MockHttpServletResponse validResponse = new MockHttpServletResponse();
        AtomicReference<AuthzCallerContext> captured = new AtomicReference<>();

        filter.doFilter(validRequest, validResponse, (req, res) -> captured.set(callerProvider.currentCallerContext()));
        assertEquals(200, validResponse.getStatus());
        AuthzCallerContext ctx = captured.get();
        assertNotNull(ctx);
        assertEquals("1", ctx.incomingHeaders().get("X-Tenant-ID"));
        assertEquals("manager@org1", ctx.incomingHeaders().get("X-User-ID"));

        var queryCtx = seam.authorizeAndCompileJpaQueryScope(
                orgSpec.decisionPoint(),
                orgSpec.factContractDigest(),
                ctx.incomingHeaderNames(),
                ctx.incomingHeaders(),
                ctx.tenantId(),
                ctx.subjectAndEnvironmentFacts(),
                ctx.factStatuses(),
                Map.of(),
                List.of(),
                jpaAdapter,
                "1 = 1",
                Map.of(),
                row -> true
        );
        assertNotNull(queryCtx.dataScopePlan());

        // 2. Tampered tenant header must still be blocked by UntrustedRequestHeaderGuard (filter + probe helper)
        MockHttpServletRequest spoofedRequest = new MockHttpServletRequest("POST", "/api/workforce/orgs/filter");
        spoofedRequest.addHeader("X-Tenant-ID", "999");
        MockHttpServletResponse spoofedResponse = new MockHttpServletResponse();
        filter.doFilter(spoofedRequest, spoofedResponse, new MockFilterChain());
        assertEquals(403, spoofedResponse.getStatus());

        assertThrows(UntrustedHeaderSpoofingException.class, () ->
                UntrustedRequestHeaderGuard.assertNoAuthoritySpoofingHeaders(
                        AuthzCallerContext.buildHeaderProbeMap(
                                Set.of("X-Tenant-ID"),
                                Map.of("X-Tenant-ID", "999")
                        ),
                        MetadataResourceAuthorizationSeam.toAuthoritativeSubjectFactMap(
                                ctx.subjectAndEnvironmentFacts(),
                                ctx.factStatuses(),
                                ctx.tenantId()
                        )
                )
        );
        assertThrows(UntrustedHeaderSpoofingException.class, () ->
                UntrustedRequestHeaderGuard.assertNoAuthoritySpoofingHeaders(
                        AuthzCallerContext.buildHeaderProbeMap(Set.of("X-Praxis-Authz-Roles"), Map.of()),
                        Map.of()
                )
        );
    }

    @Test
    @SuppressWarnings("unchecked")
    void hostBridgeInterceptorAutomaticallyConsumesBundleResourceSpecs() {
        AuthzResourceGovernanceSpec<SampleOrgEntity> orgSpec = AuthzResourceGovernanceSpec
                .<SampleOrgEntity>builder("workforce.orgs")
                .serviceKey("workforce-svc")
                .scalarFieldBinding("resource.organizationId", "organizationId", "e.organizationId")
                .build();

        AuthzHostPolicyBootstrapBuilder.AuthzHostPolicyBootstrapBundle bundle =
                AuthzHostPolicyBootstrapBuilder.forService("workforce-svc")
                        .addResourceSpec(orgSpec, SampleOrgEntity.class, SampleOrgEntity.class, SampleOrgEntity.class)
                        .addOrganizationalScopePolicy(
                                orgSpec,
                                "rule-workforce-orgs-scope",
                                "resource.organizationId",
                                "subject.organizationUnitIds",
                                Map.of()
                        )
                        .build();

        assertEquals(1, bundle.resourceSpecs().size());
        assertSame(orgSpec, bundle.resourceSpecs().get(0));

        DriverManagerDataSource ds = new DriverManagerDataSource(
                "jdbc:h2:mem:wave3_interceptor_bundle;MODE=PostgreSQL;DB_CLOSE_DELAY=-1", "sa", "");
        JdbcTemplate jdbcTemplate = new JdbcTemplate(ds);
        MetadataResourceAuthorizationSeam seam = createSeam(
                bundle,
                new TransactionTemplate(new DataSourceTransactionManager(ds)),
                jdbcTemplate
        );

        new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(PraxisAuthzHostBridgeAutoConfiguration.class))
                .withBean(AuthzHostPolicyBootstrapBuilder.AuthzHostPolicyBootstrapBundle.class, () -> bundle)
                .withBean(ThreadLocalAuthzCallerContextProvider.class, ThreadLocalAuthzCallerContextProvider::new)
                .withBean(AuthzGovernedResourceServiceSupport.class, () ->
                        new AuthzGovernedResourceServiceSupport(seam, new DetachedDtoMaskingProcessor()))
                .run(context -> {
                    assertNull(context.getStartupFailure(), "HostBridge auto-configuration must boot cleanly");
                    AuthzResourceGovernanceInterceptor interceptor =
                            context.getBean(AuthzResourceGovernanceInterceptor.class);
                    Map<String, AuthzResourceGovernanceSpec<?>> registeredSpecs =
                            (Map<String, AuthzResourceGovernanceSpec<?>>) ReflectionTestUtils
                                    .getField(interceptor, "specsByResourceKey");
                    assertNotNull(registeredSpecs);
                    assertSame(orgSpec, registeredSpecs.get("workforce.orgs"));
                });
    }

    @Test
    void actionVerbFactAndBuilderOverloadsEnableCreateSpecificRuleAndAuthenticatedSharedPolicy() {
        AuthzResourceGovernanceSpec<SampleOrgEntity> orgSpec = AuthzResourceGovernanceSpec
                .<SampleOrgEntity>builder("workforce.orgs")
                .serviceKey("workforce-svc")
                .scalarFieldBinding("resource.organizationId", "organizationId", "e.organizationId")
                .resourceSensitiveFact("resource.secretCode", "secretCode", FactValueType.STRING, "LGPD_SENSITIVE", "STATUTORY_LEGAL_OBLIGATION")
                .withActionVerbFact()
                .withSubjectRolesFact()
                .subjectFact(
                        "subject.canProvisionRealmOrganization",
                        FactValueType.BOOLEAN,
                        FactCardinality.SCALAR,
                        FactPresenceModel.MAY_BE_ABSENT
                )
                .uiSurface("detail", "GET", "/api/workforce/orgs/{id}/surfaces/detail")
                .build();

        assertTrue(orgSpec.factContract().descriptorsByPath().containsKey("action.verb"));
        assertTrue(orgSpec.factContract().descriptorsByPath().containsKey("subject.roles"));
        assertTrue(orgSpec.factContract().descriptorsByPath().containsKey("subject.canProvisionRealmOrganization"));

        AuthzResourceGovernanceSpec<SampleOrgEntity> sharedSpec = AuthzResourceGovernanceSpec
                .<SampleOrgEntity>builder("workforce.catalog")
                .serviceKey("workforce-svc")
                .scalarFieldBinding("resource.id", "id", "e.id")
                .resourceSensitiveFact("resource.secretCode", "secretCode", FactValueType.STRING, "LGPD_SENSITIVE", "STATUTORY_LEGAL_OBLIGATION")
                .tenantScope(new AuthzResourceGovernanceSpec.TenantScopeSpec(
                        AuthzTenantScopeMode.AUTHENTICATED_SHARED,
                        "organizationId",
                        "",
                        "subject.principalId",
                        "",
                        "",
                        false,
                        ""
                ))
                .build();

        List<MaskContributionSpec> masks = List.of(new MaskContributionSpec(
                PolicyFieldSelector.exact(Set.of("secretCode")),
                "REDACT_CONSTANT",
                Map.of("replacement", "***SECRET-MASKED***")
        ));

        AuthorizationPolicyRule realmProvisionRule = new AuthorizationPolicyRule(
                "rule-orgs-realm-manager-create",
                "Allows realm provisioning POST creation across organizations",
                Set.of(EvaluationMode.TARGET),
                new AuthorizationSourceCondition(
                        AuthorizationSourceCondition.LANGUAGE_PRAXIS_JSON_LOGIC,
                        ConditionProfileKind.AUTHORIZATION_TARGET_V1,
                        Map.of("and", List.of(
                                Map.of("!=", List.of(Map.of("var", "subject.principalId"), "")),
                                Map.of("==", List.of(Map.of("var", "action.verb"), "POST")),
                                Map.of("==", List.of(Map.of("var", "subject.canProvisionRealmOrganization"), true))
                        ))
                ),
                new AuthorizationRuleContributions(
                        new AccessContributionSpec(ContributionAuthority.GRANT, RuleEffect.ALLOW),
                        null,
                        List.of(),
                        List.of(),
                        masks,
                        "ALLOW_REALM_ORG_PROVISIONING"
                ),
                List.of(new ObligationDirective(
                        "DURABLE_AUDIT_EVIDENCE",
                        "ON_PERMIT",
                        "BEFORE_COMMIT_OUTBOX",
                        Map.of("auditCategory", "GOVERNED_RESOURCE_ACCESS")
                ))
        );

        AuthzHostPolicyBootstrapBuilder.AuthzHostPolicyBootstrapBundle bundle =
                AuthzHostPolicyBootstrapBuilder.forService("workforce-svc")
                        .addResourceSpec(orgSpec, SampleOrgEntity.class, SampleOrgEntity.class, SampleOrgEntity.class)
                        .addOrganizationalScopePolicy(
                                orgSpec,
                                "rule-orgs-scope",
                                "resource.organizationId",
                                "subject.organizationUnitIds",
                                masks,
                                List.of(realmProvisionRule)
                        )
                        .addSurfacePolicy(
                                orgSpec,
                                "detail",
                                "rule-orgs-detail-surface",
                                Map.of("!=", List.of(Map.of("var", "subject.principalId"), "")),
                                masks
                        )
                        .addResourceSpec(sharedSpec, SampleOrgEntity.class, null, null)
                        .addAuthenticatedSharedPolicy(sharedSpec, "rule-catalog-shared", masks, List.of())
                        .build();

        DriverManagerDataSource ds = new DriverManagerDataSource(
                "jdbc:h2:mem:wave3_actionverb_test;MODE=PostgreSQL;DB_CLOSE_DELAY=-1", "sa", "");
        JdbcTemplate jdbcTemplate = new JdbcTemplate(ds);
        TransactionTemplate txTemplate = new TransactionTemplate(new DataSourceTransactionManager(ds));
        MetadataResourceAuthorizationSeam seam = createSeam(bundle, txTemplate, jdbcTemplate);

        txTemplate.executeWithoutResult(status -> {
            Map<String, Object> targetFacts = Map.of(
                    "subject.principalId", "realm-admin",
                    "subject.organizationUnitIds", List.of(1L),
                    "subject.canProvisionRealmOrganization", true,
                    "resource.organizationId", 5L
            );
            Map<String, FactResolutionStatus> statuses = Map.of(
                    "subject.principalId", FactResolutionStatus.PRESENT,
                    "subject.organizationUnitIds", FactResolutionStatus.PRESENT,
                    "subject.canProvisionRealmOrganization", FactResolutionStatus.PRESENT,
                    "resource.organizationId", FactResolutionStatus.PRESENT
            );

            // POST creation in ungranted org 5 succeeds via action.verb == "POST" + subject capability
            var createCtx = seam.authorizePreHydrationMutation(
                    orgSpec.decisionPoint(),
                    orgSpec.factContractDigest(),
                    "POST",
                    false,
                    "{\"name\":\"Org 5\"}",
                    Map.of("/name", "name"),
                    Set.of("/version"),
                    Set.of(),
                    null,
                    false,
                    false,
                    targetFacts,
                    statuses
            );
            assertNotNull(createCtx);
            assertTrue(createCtx.maskDirectives().stream()
                    .anyMatch(d -> "secretCode".equals(d.attributeId())));

            // GET and PATCH on ungranted org 5 remain denied
            assertThrows(AuthzAccessDeniedException.class, () ->
                    seam.evaluateTargetReadProjection(
                            orgSpec.decisionPoint(),
                            orgSpec.factContractDigest(),
                            targetFacts,
                            statuses
                    )
            );
            assertThrows(AuthzAccessDeniedException.class, () ->
                    seam.authorizePreHydrationMutation(
                            orgSpec.decisionPoint(),
                            orgSpec.factContractDigest(),
                            "PATCH",
                            true,
                            "{\"name\":\"Org 5 Renamed\"}",
                            Map.of("/name", "name"),
                            Set.of("/version"),
                            Set.of(),
                            null,
                            false,
                            false,
                            targetFacts,
                            statuses
                    )
            );
        });

        // Authenticated-shared policy masks restricted field without filtering by tenant/org ID
        var sharedEval = seam.evaluateTargetReadProjection(
                sharedSpec.decisionPoint(),
                sharedSpec.factContractDigest(),
                Map.of("subject.principalId", "user-1"),
                Map.of("subject.principalId", FactResolutionStatus.PRESENT)
        );
        assertFalse(sharedEval.maskDirectives().isEmpty());
        assertTrue(sharedEval.maskDirectives().stream()
                .anyMatch(d -> "secretCode".equals(d.attributeId())));
    }

    @Test
    void unmaskedAuthenticatedSharedAndBulkActionSynthesizeValidSearchRules() {
        AuthzResourceGovernanceSpec<SampleOrgEntity> unmaskedSharedSpec = AuthzResourceGovernanceSpec
                .<SampleOrgEntity>builder("workforce.reference-catalogs")
                .serviceKey("workforce-svc")
                .scalarFieldBinding(
                        "resource.id",
                        "id",
                        "e.id",
                        FactValueType.INT64,
                        Set.of(SearchPredicateOperator.EQ, SearchPredicateOperator.IN, SearchPredicateOperator.IS_NOT_NULL),
                        false
                )
                .scalarFieldBinding("resource.name", "name", "e.name", FactValueType.STRING, Set.of(SearchPredicateOperator.EQ), false)
                .tenantScope(new AuthzResourceGovernanceSpec.TenantScopeSpec(
                        AuthzTenantScopeMode.AUTHENTICATED_SHARED,
                        "organizationId",
                        "",
                        "subject.principalId",
                        "",
                        "",
                        false,
                        ""
                ))
                .bulkWorkflowAction("approve-batch", Set.of("name"))
                .build();

        AuthzResourceGovernanceSpec<SampleOrgEntity> annotatedSharedSpec = AuthzResourceGovernanceSpec
                .<SampleOrgEntity>builder("workforce.annotated-shared-catalogs")
                .serviceKey("workforce-svc")
                .scalarFieldBinding(
                        "resource.id",
                        "id",
                        "e.id",
                        FactValueType.INT64,
                        Set.of(SearchPredicateOperator.EQ, SearchPredicateOperator.IN, SearchPredicateOperator.IS_NOT_NULL),
                        false
                )
                .scalarFieldBinding("resource.name", "name", "e.name", FactValueType.STRING, Set.of(SearchPredicateOperator.EQ), false)
                .tenantScope(new AuthzResourceGovernanceSpec.TenantScopeSpec(
                        AuthzTenantScopeMode.AUTHENTICATED_SHARED,
                        "organizationId",
                        "",
                        "subject.principalId",
                        "",
                        "",
                        false,
                        ""
                ))
                .bulkWorkflowAction("publish-batch", Set.of("name"))
                .build();

        Map<String, Object> principalPresent = Map.of("!=", List.of(Map.of("var", "subject.principalId"), ""));

        AuthzHostPolicyBootstrapBuilder.AuthzHostPolicyBootstrapBundle bundle =
                AuthzHostPolicyBootstrapBuilder.forService("workforce-svc")
                        .addResourceSpec(unmaskedSharedSpec, SampleOrgEntity.class, null, null)
                        .addAuthenticatedSharedPolicy(
                                unmaskedSharedSpec,
                                "rule-ref-catalog-shared",
                                List.of(),
                                List.of()
                        )
                        .addSharedBulkActionPolicy(
                                unmaskedSharedSpec,
                                "approve-batch",
                                "rule-ref-catalog-bulk-approve",
                                principalPresent,
                                Set.of("name")
                        )
                        .addAnnotatedResource(annotatedSharedSpec, SampleOrgEntity.class, null, null)
                        .build();

        DriverManagerDataSource ds = new DriverManagerDataSource(
                "jdbc:h2:mem:wave3_unmasked_shared_test;MODE=PostgreSQL;DB_CLOSE_DELAY=-1", "sa", "");
        JdbcTemplate jdbcTemplate = new JdbcTemplate(ds);
        MetadataResourceAuthorizationSeam seam = createSeam(
                bundle,
                new TransactionTemplate(new DataSourceTransactionManager(ds)),
                jdbcTemplate
        );

        JpaDataScopeAdapter unmaskedJpa = new JpaDataScopeAdapter(
                unmaskedSharedSpec.queryProjection(),
                unmaskedSharedSpec.fieldBindings()
        );
        var unmaskedQueryCtx = seam.authorizeAndCompileJpaQueryScope(
                unmaskedSharedSpec.decisionPoint(),
                unmaskedSharedSpec.factContractDigest(),
                Set.of(),
                Map.of("subject.principalId", "user-1"),
                Map.of("subject.principalId", FactResolutionStatus.PRESENT),
                Map.of(),
                List.of(),
                unmaskedJpa,
                "1 = 1",
                Map.of(),
                row -> true
        );
        assertEquals(DataScopeOutcome.ALL, unmaskedQueryCtx.scopeOutcome());

        var unmaskedBulkCtx = seam.authorizeAndCompileJpaQueryScope(
                unmaskedSharedSpec.actionDecisionPoints().get("approve-batch"),
                unmaskedSharedSpec.factContractDigest(),
                Set.of(),
                Map.of("subject.principalId", "user-1"),
                Map.of("subject.principalId", FactResolutionStatus.PRESENT),
                Map.of(),
                List.of(),
                unmaskedJpa,
                "1 = 1",
                Map.of(),
                row -> true
        );
        assertEquals(DataScopeOutcome.FILTER, unmaskedBulkCtx.scopeOutcome());

        var unmaskedTarget = seam.evaluateTargetReadProjection(
                unmaskedSharedSpec.decisionPoint(),
                unmaskedSharedSpec.factContractDigest(),
                Map.of("subject.principalId", "user-1"),
                Map.of("subject.principalId", FactResolutionStatus.PRESENT)
        );
        assertTrue(unmaskedTarget.maskDirectives().isEmpty());

        assertThrows(AuthzAccessDeniedException.class, () ->
                seam.evaluateTargetReadProjection(
                        unmaskedSharedSpec.decisionPoint(),
                        unmaskedSharedSpec.factContractDigest(),
                        Map.of("subject.principalId", ""),
                        Map.of("subject.principalId", FactResolutionStatus.PRESENT)
                )
        );

        JpaDataScopeAdapter annotatedJpa = new JpaDataScopeAdapter(
                annotatedSharedSpec.queryProjection(),
                annotatedSharedSpec.fieldBindings()
        );
        var annotatedQueryCtx = seam.authorizeAndCompileJpaQueryScope(
                annotatedSharedSpec.decisionPoint(),
                annotatedSharedSpec.factContractDigest(),
                Set.of(),
                Map.of("subject.principalId", "user-1"),
                Map.of("subject.principalId", FactResolutionStatus.PRESENT),
                Map.of(),
                List.of(),
                annotatedJpa,
                "1 = 1",
                Map.of(),
                row -> true
        );
        assertEquals(DataScopeOutcome.ALL, annotatedQueryCtx.scopeOutcome());

        var annotatedBulkCtx = seam.authorizeAndCompileJpaQueryScope(
                annotatedSharedSpec.actionDecisionPoints().get("publish-batch"),
                annotatedSharedSpec.factContractDigest(),
                Set.of(),
                Map.of("subject.principalId", "user-1"),
                Map.of("subject.principalId", FactResolutionStatus.PRESENT),
                Map.of(),
                List.of(),
                annotatedJpa,
                "1 = 1",
                Map.of(),
                row -> true
        );
        assertEquals(DataScopeOutcome.FILTER, annotatedBulkCtx.scopeOutcome());
    }

    @Test
    void wrappedMapperIgnoresComputedReadOnlyDtoGettersDuringMasking() {
        AuthzResourceGovernanceSpec<SampleOrgEntity> spec = AuthzResourceGovernanceSpec
                .<SampleOrgEntity>builder("workforce.positions")
                .serviceKey("workforce-svc")
                .scalarFieldBinding("resource.organizationId", "workforce.positions.organization_id", "organizationId")
                .resourceSensitiveFact(
                        "resource.secretCode",
                        "workforce.positions.secret_code",
                        FactValueType.STRING,
                        "LGPD_SENSITIVE",
                        "STATUTORY_LEGAL_OBLIGATION"
                )
                .build();

        List<MaskContributionSpec> masks = List.of(new MaskContributionSpec(
                PolicyFieldSelector.exact(Set.of("workforce.positions.secret_code")),
                "REDACT_CONSTANT",
                Map.of("replacement", "***")
        ));

        AuthzHostPolicyBootstrapBuilder.AuthzHostPolicyBootstrapBundle bundle =
                AuthzHostPolicyBootstrapBuilder.forService("workforce-svc")
                        .addResourceSpec(spec, ComputedGetterResponseDTO.class, SampleOrgEntity.class, SampleOrgEntity.class)
                        .addOrganizationalScopePolicy(
                                spec,
                                "rule-workforce-positions-scope",
                                "resource.organizationId",
                                "subject.organizationUnitIds",
                                masks,
                                List.of()
                        )
                        .build();

        DriverManagerDataSource ds = new DriverManagerDataSource(
                "jdbc:h2:mem:wave3_computed_getter_test;MODE=PostgreSQL;DB_CLOSE_DELAY=-1", "sa", "");
        JdbcTemplate jdbcTemplate = new JdbcTemplate(ds);
        TransactionTemplate txTemplate = new TransactionTemplate(new DataSourceTransactionManager(ds));
        MetadataResourceAuthorizationSeam seam = createSeam(bundle, txTemplate, jdbcTemplate);
        AuthzGovernedResourceServiceSupport serviceSupport =
                new AuthzGovernedResourceServiceSupport(seam, new DetachedDtoMaskingProcessor());

        ResourceMapper<SampleOrgEntity, ComputedGetterResponseDTO, SampleOrgEntity, SampleOrgEntity, Long> rawMapper =
                new ResourceMapper<>() {
                    @Override
                    public ComputedGetterResponseDTO toResponse(SampleOrgEntity entity) {
                        ComputedGetterResponseDTO dto = new ComputedGetterResponseDTO();
                        dto.id = entity.id;
                        dto.ativo = Boolean.FALSE;
                        dto.name = entity.name;
                        dto.secretCode = entity.secretCode;
                        return dto;
                    }

                    @Override
                    public SampleOrgEntity newEntity(SampleOrgEntity dto) {
                        return dto;
                    }

                    @Override
                    public void applyUpdate(SampleOrgEntity entity, SampleOrgEntity dto) {
                        entity.name = dto.name;
                    }

                    @Override
                    public Long extractId(SampleOrgEntity entity) {
                        return entity.id;
                    }
                };

        ResourceMapper<SampleOrgEntity, ComputedGetterResponseDTO, SampleOrgEntity, SampleOrgEntity, Long> wrappedMapper =
                serviceSupport.wrapResourceMapper(rawMapper, ComputedGetterResponseDTO.class, spec.resourceKey());

        SampleOrgEntity entity = new SampleOrgEntity();
        entity.id = 77L;
        entity.organizationId = 10L;
        entity.name = "Analista";
        entity.secretCode = "SENSITIVE-XYZ";

        txTemplate.executeWithoutResult(status -> {
            serviceSupport.authorizeBeforeHydrationAndRules(
                    spec.decisionPoint(),
                    spec.factContractDigest(),
                    "POST",
                    false,
                    "{\"organizationId\":10,\"name\":\"Analista\"}",
                    Map.of(
                            "/organizationId", "workforce.positions.organization_id",
                            "/name", "workforce.positions.name"
                    ),
                    Set.of("/version"),
                    Set.of("workforce.positions.organization_id"),
                    null,
                    true,
                    false,
                    Map.of(
                            "subject.principalId", "mgr-1",
                            "subject.organizationUnitIds", List.of(10L),
                            "resource.organizationId", 10L
                    ),
                    Map.of(
                            "subject.principalId", FactResolutionStatus.PRESENT,
                            "subject.organizationUnitIds", FactResolutionStatus.PRESENT,
                            "resource.organizationId", FactResolutionStatus.PRESENT
                    )
            );
            serviceSupport.markPostMutationReadyForOutboxAndMasking();
            ComputedGetterResponseDTO mapped = wrappedMapper.toResponse(entity);
            assertEquals(77L, mapped.id);
            assertEquals(Boolean.FALSE, mapped.ativo);
            assertEquals("Analista", mapped.name);
            assertEquals("***", mapped.secretCode);
            assertEquals(4L, mapped.getComputedOccupiedCount());
        });

        ComputedGetterResponseDTO writeBean = new ComputedGetterResponseDTO();
        writeBean.id = 99L;
        writeBean.name = "Alterado";
        writeBean.secretCode = "KEEP-WRITABLE";
        @SuppressWarnings("unchecked")
        Map<String, Object> writeIntentMap =
                AuthzGovernedResourceServiceSupport.createWriteIntentBeanObjectMapper()
                        .convertValue(writeBean, Map.class);
        assertFalse(writeIntentMap.containsKey("id"));
        assertFalse(writeIntentMap.containsKey("ativo"));
        assertEquals("Alterado", writeIntentMap.get("name"));
        assertEquals("KEEP-WRITABLE", writeIntentMap.get("secretCode"));
    }

    @Test
    void allowGlobalNullScopeCompilesAndAdmitsBothOrgMatchedAndNullScopedRecords() {
        AuthzResourceGovernanceSpec<SampleOrgEntity> spec = AuthzResourceGovernanceSpec
                .<SampleOrgEntity>builder("workforce.global-rules")
                .serviceKey("workforce-svc")
                .tenantField("organizationId")
                .allowGlobalNullScope(true)
                .introspectFromResource(
                        SampleOrgEntity.class,
                        SampleOrgEntity.class,
                        null,
                        SampleOrgEntity.class,
                        SampleOrgEntity.class,
                        null,
                        null
                )
                .build();

        assertTrue(
                spec.mandatoryScopeAnchorAttributeIds().isEmpty(),
                "Nullable global-or-org scope fields must not become mandatory scope anchors"
        );
        assertEquals(
                FactPresenceModel.MAY_BE_ABSENT,
                spec.factContract().descriptorsByPath().get("resource.organizationId").presenceModel()
        );

        AuthzHostPolicyBootstrapBuilder.AuthzHostPolicyBootstrapBundle bundle =
                AuthzHostPolicyBootstrapBuilder.forService("workforce-svc")
                        .addResourceSpec(spec, SampleOrgEntity.class, SampleOrgEntity.class, SampleOrgEntity.class)
                        .addOrganizationalScopePolicy(
                                spec,
                                "rule-workforce-global-rules-scope",
                                "resource.organizationId",
                                "subject.organizationUnitIds",
                                List.of(),
                                List.of()
                        )
                        .build();

        DriverManagerDataSource ds = new DriverManagerDataSource(
                "jdbc:h2:mem:wave3_global_null_scope_test;MODE=PostgreSQL;DB_CLOSE_DELAY=-1", "sa", "");
        JdbcTemplate jdbcTemplate = new JdbcTemplate(ds);
        MetadataResourceAuthorizationSeam seam = createSeam(
                bundle,
                new TransactionTemplate(new DataSourceTransactionManager(ds)),
                jdbcTemplate
        );

        SampleOrgEntity orgMatched = new SampleOrgEntity();
        orgMatched.id = 1L;
        orgMatched.organizationId = 10L;
        orgMatched.name = "Org Rule";

        Map<String, Object> orgFacts = new LinkedHashMap<>(spec.extractEntityTargetFacts(orgMatched));
        orgFacts.put("subject.principalId", "user-1");
        orgFacts.put("subject.organizationUnitIds", List.of(10L));
        var orgEval = seam.evaluateTargetReadProjection(
                spec.decisionPoint(),
                spec.factContractDigest(),
                orgFacts,
                AuthzResourceGovernanceSpec.resolveFactStatuses(Map.of(), orgFacts, spec, orgMatched)
        );
        assertNotNull(orgEval);

        SampleOrgEntity globalRecord = new SampleOrgEntity();
        globalRecord.id = 2L;
        globalRecord.organizationId = null;
        globalRecord.name = "Global Rule";

        Map<String, Object> globalFacts = new LinkedHashMap<>(spec.extractEntityTargetFacts(globalRecord));
        globalFacts.put("subject.principalId", "user-1");
        globalFacts.put("subject.organizationUnitIds", List.of(10L));
        Map<String, FactResolutionStatus> globalStatuses =
                AuthzResourceGovernanceSpec.resolveFactStatuses(Map.of(), globalFacts, spec, globalRecord);
        assertEquals(FactResolutionStatus.NULL, globalStatuses.get("resource.organizationId"));

        var globalEval = seam.evaluateTargetReadProjection(
                spec.decisionPoint(),
                spec.factContractDigest(),
                globalFacts,
                globalStatuses
        );
        assertNotNull(globalEval);

        SampleOrgEntity foreignOrg = new SampleOrgEntity();
        foreignOrg.id = 3L;
        foreignOrg.organizationId = 99L;
        foreignOrg.name = "Foreign Rule";

        Map<String, Object> foreignFacts = new LinkedHashMap<>(spec.extractEntityTargetFacts(foreignOrg));
        foreignFacts.put("subject.principalId", "user-1");
        foreignFacts.put("subject.organizationUnitIds", List.of(10L));
        assertThrows(AuthzAccessDeniedException.class, () ->
                seam.evaluateTargetReadProjection(
                        spec.decisionPoint(),
                        spec.factContractDigest(),
                        foreignFacts,
                        AuthzResourceGovernanceSpec.resolveFactStatuses(Map.of(), foreignFacts, spec, foreignOrg)
                )
        );
    }

    private static final class SampleOrgEntityProxy extends SampleOrgEntity implements HibernateProxy {
        private final transient LazyInitializer lazyInitializer;

        private SampleOrgEntityProxy(SampleOrgEntity target) {
            this.lazyInitializer = (LazyInitializer) Proxy.newProxyInstance(
                    SampleOrgEntityProxy.class.getClassLoader(),
                    new Class<?>[]{LazyInitializer.class},
                    (proxy, method, args) -> switch (method.getName()) {
                        case "getImplementation", "initialize" -> target;
                        case "getPersistentClass" -> SampleOrgEntity.class;
                        case "getEntityName" -> SampleOrgEntity.class.getName();
                        case "getIdentifier" -> target.id;
                        case "isUninitialized" -> false;
                        default -> null;
                    }
            );
        }

        @Override
        public Object writeReplace() {
            return this;
        }

        @Override
        public LazyInitializer getHibernateLazyInitializer() {
            return lazyInitializer;
        }
    }

    @Test
    void hibernateProxyEntitiesAreUnwrappedAcrossSpecAndInterceptor() {
        AuthzResourceGovernanceSpec<SampleOrgEntity> spec = AuthzResourceGovernanceSpec
                .<SampleOrgEntity>builder("workforce.proxy-orgs")
                .serviceKey("workforce-svc")
                .tenantField("organizationId")
                .introspectFromResource(
                        SampleOrgEntity.class,
                        SampleOrgEntity.class,
                        null,
                        SampleOrgEntity.class,
                        SampleOrgEntity.class,
                        null,
                        null
                )
                .build();

        AuthzHostPolicyBootstrapBuilder.AuthzHostPolicyBootstrapBundle bundle =
                AuthzHostPolicyBootstrapBuilder.forService("workforce-svc")
                        .addResourceSpec(spec, SampleOrgEntity.class, SampleOrgEntity.class, SampleOrgEntity.class)
                        .addOrganizationalScopePolicy(
                                spec,
                                "rule-workforce-proxy-orgs-scope",
                                "resource.organizationId",
                                "subject.organizationUnitIds",
                                List.of(),
                                List.of()
                        )
                        .build();

        DriverManagerDataSource ds = new DriverManagerDataSource(
                "jdbc:h2:mem:wave3_hibernate_proxy_test;MODE=PostgreSQL;DB_CLOSE_DELAY=-1", "sa", "");
        JdbcTemplate jdbcTemplate = new JdbcTemplate(ds);
        MetadataResourceAuthorizationSeam seam = createSeam(
                bundle,
                new TransactionTemplate(new DataSourceTransactionManager(ds)),
                jdbcTemplate
        );

        ThreadLocalAuthzCallerContextProvider callerProvider = new ThreadLocalAuthzCallerContextProvider();
        AuthzGovernedResourceServiceSupport serviceSupport =
                new AuthzGovernedResourceServiceSupport(seam, new DetachedDtoMaskingProcessor());
        AuthzResourceGovernanceInterceptor interceptor =
                new AuthzResourceGovernanceInterceptor(serviceSupport, callerProvider)
                        .registerSpec(spec);

        AuthzCallerContext callerCtx = new AuthzCallerContext(
                "10",
                Map.of(
                        "subject.principalId", "user-1",
                        "subject.organizationUnitIds", List.of(10L)
                ),
                Map.of(
                        "subject.principalId", FactResolutionStatus.PRESENT,
                        "subject.organizationUnitIds", FactResolutionStatus.PRESENT
                ),
                Set.of(),
                Map.of(),
                null,
                null
        );

        SampleOrgEntity realTarget = new SampleOrgEntity();
        realTarget.id = 42L;
        realTarget.organizationId = 10L;
        realTarget.name = "Proxy Resolved Dept";
        SampleOrgEntityProxy proxy = new SampleOrgEntityProxy(realTarget);
        // Raw superclass fields on the ByteBuddy-like proxy instance remain null.
        assertNull(((SampleOrgEntity) proxy).organizationId);

        spec.verifyEntityAccessAllowed(proxy, callerCtx, null);
        Map<String, Object> targetFacts = spec.extractEntityTargetFacts(proxy);
        assertEquals(10L, targetFacts.get("resource.organizationId"));
        assertEquals("Proxy Resolved Dept", targetFacts.get("resource.name"));

        var snapshot = spec.toResourceStateSnapshot(proxy);
        assertEquals(10L, snapshot.metadata().get("resource.organizationId"));

        BaseResourceQueryService<?, ?, ?> queryService = (BaseResourceQueryService<?, ?, ?>) Proxy.newProxyInstance(
                Wave3StarterHotfixRegressionTest.class.getClassLoader(),
                new Class<?>[]{BaseResourceQueryService.class},
                (p, m, args) -> "getResourceKey".equals(m.getName()) ? "workforce.proxy-orgs" : null
        );
        callerProvider.runWithContext(
                callerCtx,
                () -> interceptor.verifyEntitiesAccess(queryService, List.of(proxy), AccessMode.READ)
        );

        SampleOrgEntity foreignTarget = new SampleOrgEntity();
        foreignTarget.id = 43L;
        foreignTarget.organizationId = 99L;
        SampleOrgEntityProxy foreignProxy = new SampleOrgEntityProxy(foreignTarget);
        assertThrows(
                SecurityException.class,
                () -> callerProvider.runWithContext(
                        callerCtx,
                        () -> interceptor.verifyEntitiesAccess(queryService, List.of(foreignProxy), AccessMode.READ)
                )
        );
    }

    @Entity(name = "Wave3Beta7BenefitsCaseEntity")
    @Table(name = "wave3_beta7_benefits_cases")
    @AuthzTenantScope(mode = AuthzTenantScopeMode.ORGANIZATIONAL_UNIT, tenantField = "organizationId")
    public static class Beta7BenefitsCaseEntity {
        @Id
        public Long id;
        public Long organizationId;
        public String processNumber;
        public String workflowStatus;

        public Beta7BenefitsCaseEntity() {
        }
    }

    @Entity(name = "Wave3Beta7EmployeeProfileEntity")
    @Table(name = "wave3_beta7_employee_profiles")
    @AuthzTenantScope(mode = AuthzTenantScopeMode.AUTHENTICATED_SHARED)
    public static class Beta7EmployeeProfileEntity {
        @Id
        public Long employeeNumber;
        public String fullName;

        public Beta7EmployeeProfileEntity() {
        }
    }

    public static class Beta7CaseFilter implements GenericFilterDTO {
    }

    public interface Beta7BenefitsCaseRepo extends BaseCrudRepository<Beta7BenefitsCaseEntity, Long> {
    }

    public interface Beta7EmployeeProfileRepo extends BaseCrudRepository<Beta7EmployeeProfileEntity, Long> {
    }

    public static class Beta7BenefitsCaseService extends AbstractBaseResourceService<
            Beta7BenefitsCaseEntity,
            Beta7BenefitsCaseEntity,
            Long,
            Beta7CaseFilter,
            Beta7BenefitsCaseEntity,
            Beta7BenefitsCaseEntity> {

        private final ResourceMapper<
                Beta7BenefitsCaseEntity,
                Beta7BenefitsCaseEntity,
                Beta7BenefitsCaseEntity,
                Beta7BenefitsCaseEntity,
                Long> mapper = new ResourceMapper<>() {
            @Override
            public Beta7BenefitsCaseEntity toResponse(Beta7BenefitsCaseEntity entity) {
                return entity;
            }

            @Override
            public Beta7BenefitsCaseEntity newEntity(Beta7BenefitsCaseEntity dto) {
                return dto;
            }

            @Override
            public void applyUpdate(Beta7BenefitsCaseEntity entity, Beta7BenefitsCaseEntity dto) {
                entity.workflowStatus = dto.workflowStatus;
            }

            @Override
            public Long extractId(Beta7BenefitsCaseEntity entity) {
                return entity.id;
            }
        };

        public Beta7BenefitsCaseService(Beta7BenefitsCaseRepo repository) {
            super(repository, new GenericSpecificationsBuilder<>(), Beta7BenefitsCaseEntity.class);
        }

        @Override
        protected ResourceMapper<
                Beta7BenefitsCaseEntity,
                Beta7BenefitsCaseEntity,
                Beta7BenefitsCaseEntity,
                Beta7BenefitsCaseEntity,
                Long> getResourceMapper() {
            return mapper;
        }

        @Override
        protected String resolveResourceKey() {
            return "workforce.benefits-cases";
        }

        @Override
        protected Optional<ResourceStateSnapshot> toResourceStateSnapshot(Beta7BenefitsCaseEntity entity) {
            // Mirrors host services adding resource.legalBasis display keys not declared in FactContract
            return Optional.of(ResourceStateSnapshot.of(
                    entity.workflowStatus,
                    Map.of(
                            "resource.legalBasis", "Statute Art. 40",
                            "action.homologate.allowed", "DRAFT".equals(entity.workflowStatus)
                    )
            ));
        }

        @Override
        public Optional<ResourceStateSnapshot> findResourceStateSnapshot(Long id) {
            return super.findResourceStateSnapshot(id);
        }
    }

    public static class Beta7EmployeeProfileService extends AbstractBaseResourceService<
            Beta7EmployeeProfileEntity,
            Beta7EmployeeProfileEntity,
            Long,
            Beta7CaseFilter,
            Beta7EmployeeProfileEntity,
            Beta7EmployeeProfileEntity> {

        private final ResourceMapper<
                Beta7EmployeeProfileEntity,
                Beta7EmployeeProfileEntity,
                Beta7EmployeeProfileEntity,
                Beta7EmployeeProfileEntity,
                Long> mapper = new ResourceMapper<>() {
            @Override
            public Beta7EmployeeProfileEntity toResponse(Beta7EmployeeProfileEntity entity) {
                return entity;
            }

            @Override
            public Beta7EmployeeProfileEntity newEntity(Beta7EmployeeProfileEntity dto) {
                return dto;
            }

            @Override
            public void applyUpdate(Beta7EmployeeProfileEntity entity, Beta7EmployeeProfileEntity dto) {
                entity.fullName = dto.fullName;
            }

            @Override
            public Long extractId(Beta7EmployeeProfileEntity entity) {
                return entity.employeeNumber;
            }
        };

        public Beta7EmployeeProfileService(Beta7EmployeeProfileRepo repository) {
            super(repository, new GenericSpecificationsBuilder<>(), Beta7EmployeeProfileEntity.class);
        }

        @Override
        protected ResourceMapper<
                Beta7EmployeeProfileEntity,
                Beta7EmployeeProfileEntity,
                Beta7EmployeeProfileEntity,
                Beta7EmployeeProfileEntity,
                Long> getResourceMapper() {
            return mapper;
        }

        @Override
        protected String resolveResourceKey() {
            return "workforce.employee-profiles";
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    void cglibProxiedServicesResolveSnapshotsWithPreResolvedCustomMetadataNonIdPkAndReadOnlyConsolidation() {
        String dbName = "wave3_beta7_avail_" + UUID.randomUUID().toString().replace("-", "");
        DriverManagerDataSource ds = new DriverManagerDataSource(
                "jdbc:h2:mem:" + dbName + ";MODE=PostgreSQL;DB_CLOSE_DELAY=-1", "sa", "");
        LocalContainerEntityManagerFactoryBean emfBean = new LocalContainerEntityManagerFactoryBean();
        emfBean.setDataSource(ds);
        emfBean.setPackagesToScan(Wave3StarterHotfixRegressionTest.class.getPackageName());
        emfBean.setPersistenceProviderClass(HibernatePersistenceProvider.class);
        emfBean.setJpaVendorAdapter(new HibernateJpaVendorAdapter());
        Properties jpaProps = new Properties();
        jpaProps.setProperty("hibernate.hbm2ddl.auto", "create-drop");
        jpaProps.setProperty("hibernate.dialect", "org.hibernate.dialect.H2Dialect");
        emfBean.setJpaProperties(jpaProps);
        emfBean.afterPropertiesSet();

        var emf = emfBean.getObject();
        assertNotNull(emf);
        JpaTransactionManager txManager = new JpaTransactionManager(emf);
        TransactionTemplate txTemplate = new TransactionTemplate(txManager);
        EntityManager sharedEm = SharedEntityManagerCreator.createSharedEntityManager(emf);
        JdbcTemplate jdbcTemplate = new JdbcTemplate(ds);
        JpaRepositoryFactory repoFactory = new JpaRepositoryFactory(sharedEm);
        Beta7BenefitsCaseRepo caseRepo = repoFactory.getRepository(Beta7BenefitsCaseRepo.class);
        Beta7EmployeeProfileRepo profileRepo = repoFactory.getRepository(Beta7EmployeeProfileRepo.class);

        txTemplate.executeWithoutResult(status -> {
            Beta7BenefitsCaseEntity inScopeCase = new Beta7BenefitsCaseEntity();
            inScopeCase.id = 101L;
            inScopeCase.organizationId = 10L;
            inScopeCase.processNumber = "PROC-101";
            inScopeCase.workflowStatus = "DRAFT";
            caseRepo.save(inScopeCase);

            Beta7BenefitsCaseEntity outOfScopeCase = new Beta7BenefitsCaseEntity();
            outOfScopeCase.id = 102L;
            outOfScopeCase.organizationId = 99L;
            outOfScopeCase.processNumber = "PROC-102";
            outOfScopeCase.workflowStatus = "DRAFT";
            caseRepo.save(outOfScopeCase);

            Beta7EmployeeProfileEntity profile = new Beta7EmployeeProfileEntity();
            profile.employeeNumber = 900212L;
            profile.fullName = "Helena Vasconcellos";
            profileRepo.save(profile);
        });

        AuthzResourceGovernanceSpec<Beta7BenefitsCaseEntity> caseSpec =
                AuthzResourceGovernanceSpec.<Beta7BenefitsCaseEntity>builder("workforce.benefits-cases")
                        .serviceKey("workforce-svc")
                        .tenantField("organizationId")
                        .workflowAction("homologate", Set.of())
                        .uiSurface("detail", "GET", "/api/workforce/benefits-cases/{id}/surfaces/detail")
                        .uiSurface("review-form", "PATCH", "/api/workforce/benefits-cases/{id}/review-form")
                        .introspectFromResource(
                                Beta7BenefitsCaseEntity.class,
                                Beta7BenefitsCaseEntity.class,
                                Beta7CaseFilter.class,
                                Beta7BenefitsCaseEntity.class,
                                Beta7BenefitsCaseEntity.class,
                                null,
                                null
                        )
                        .build();

        AuthzResourceGovernanceSpec<Beta7EmployeeProfileEntity> profileSpec =
                AuthzResourceGovernanceSpec.<Beta7EmployeeProfileEntity>builder("workforce.employee-profiles")
                        .serviceKey("workforce-svc")
                        .uiSurface("profile-sheet", "GET", "/api/workforce/employee-profiles/{id}/surfaces/profile-sheet")
                        .introspectFromResource(
                                Beta7EmployeeProfileEntity.class,
                                Beta7EmployeeProfileEntity.class,
                                Beta7CaseFilter.class,
                                Beta7EmployeeProfileEntity.class,
                                Beta7EmployeeProfileEntity.class,
                                null,
                                null
                        )
                        .build();

        Map<String, Object> principalPresent = Map.of("!=", List.of(Map.of("var", "subject.principalId"), ""));

        AuthzHostPolicyBootstrapBuilder.AuthzHostPolicyBootstrapBundle bundle =
                AuthzHostPolicyBootstrapBuilder.forService("workforce-svc")
                        .addResourceSpec(caseSpec, Beta7BenefitsCaseEntity.class, Beta7BenefitsCaseEntity.class, Beta7BenefitsCaseEntity.class)
                        .addOrganizationalScopePolicy(
                                caseSpec,
                                "rule-workforce-benefits-cases-scope",
                                "resource.organizationId",
                                "subject.organizationUnitIds",
                                List.of(),
                                List.of()
                        )
                        .addActionPolicy(caseSpec, "homologate", "rule-benefits-homologate", principalPresent)
                        .addSurfacePolicy(caseSpec, "detail", "rule-benefits-detail", principalPresent, List.of())
                        .addSurfacePolicy(caseSpec, "review-form", "rule-benefits-review-form", principalPresent, List.of())
                        .addResourceSpec(profileSpec, Beta7EmployeeProfileEntity.class, Beta7EmployeeProfileEntity.class, Beta7EmployeeProfileEntity.class)
                        .addAuthenticatedSharedPolicy(profileSpec, "rule-workforce-profiles-shared", List.of(), List.of())
                        .addSurfacePolicy(profileSpec, "profile-sheet", "rule-profiles-sheet", principalPresent, List.of())
                        .build();

        MetadataResourceAuthorizationSeam seam = createSeam(bundle, txTemplate, jdbcTemplate);
        ThreadLocalAuthzCallerContextProvider callerProvider = new ThreadLocalAuthzCallerContextProvider();
        AuthzGovernedResourceServiceSupport serviceSupport =
                new AuthzGovernedResourceServiceSupport(seam, new DetachedDtoMaskingProcessor());
        AuthzResourceOperationAvailabilityProvider availabilityProvider =
                new AuthzResourceOperationAvailabilityProvider(seam);
        AuthzResourceGovernanceInterceptor interceptor =
                new AuthzResourceGovernanceInterceptor(serviceSupport, callerProvider)
                        .registerSpec(caseSpec)
                        .registerSpec(profileSpec);

        Beta7BenefitsCaseService rawCaseService = new Beta7BenefitsCaseService(caseRepo);
        rawCaseService.setResourceGovernanceInterceptors(List.of(interceptor));
        Beta7EmployeeProfileService rawProfileService = new Beta7EmployeeProfileService(profileRepo);
        rawProfileService.setResourceGovernanceInterceptors(List.of(interceptor));

        TransactionInterceptor txAdvice = new TransactionInterceptor(txManager, new AnnotationTransactionAttributeSource());
        ProxyFactory caseProxyFactory = new ProxyFactory(rawCaseService);
        caseProxyFactory.setProxyTargetClass(true);
        caseProxyFactory.addAdvice(txAdvice);
        Beta7BenefitsCaseService proxiedCaseService = (Beta7BenefitsCaseService) caseProxyFactory.getProxy();

        ProxyFactory profileProxyFactory = new ProxyFactory(rawProfileService);
        profileProxyFactory.setProxyTargetClass(true);
        profileProxyFactory.addAdvice(txAdvice);
        Beta7EmployeeProfileService proxiedProfileService = (Beta7EmployeeProfileService) profileProxyFactory.getProxy();

        // Mirrors PraxisAuthzHostBridgeAutoConfiguration registering the Spring AOP proxy
        interceptor.registerAvailabilityBindingIfSupported(proxiedCaseService, availabilityProvider);
        interceptor.registerAvailabilityBindingIfSupported(proxiedProfileService, availabilityProvider);

        SurfaceDefinition detailSurfaceDef = new SurfaceDefinition(
                "detail", "workforce.benefits-cases", "/api/workforce/benefits-cases",
                "workforce", SurfaceKind.READ_PROJECTION, SurfaceScope.ITEM, "Detail 360", "Detail summary",
                "detail", "visibility", "response", SurfaceResponseCardinality.OBJECT,
                null, null, 1, List.of(), List.of(), List.of(), null
        );
        SurfaceDefinition reviewFormSurfaceDef = new SurfaceDefinition(
                "review-form", "workforce.benefits-cases", "/api/workforce/benefits-cases",
                "workforce", SurfaceKind.PARTIAL_FORM, SurfaceScope.ITEM, "Review Form", "Partial review form",
                "reviewForm", "visibility", "response", SurfaceResponseCardinality.OBJECT,
                null, null, 2, List.of(), List.of(), List.of(), null
        );
        ActionDefinition homologateActionDef = new ActionDefinition(
                "homologate", "workforce.benefits-cases", "/api/workforce/benefits-cases",
                "workforce", ActionScope.ITEM, "Homologate", "Approve case",
                null, null, null, 10, "APPROVED", List.of(), List.of("DRAFT"), List.of(),
                ActionExecutionContract.defaults(ActionScope.ITEM)
        );
        SurfaceDefinition profileSheetSurfaceDef = new SurfaceDefinition(
                "profile-sheet", "workforce.employee-profiles", "/api/workforce/employee-profiles",
                "workforce", SurfaceKind.READ_PROJECTION, SurfaceScope.ITEM, "Profile Sheet", "Shared sheet",
                "profileSheet", "visibility", "response", SurfaceResponseCardinality.OBJECT,
                null, null, 1, List.of(), List.of(), List.of(), null
        );

        try {
            // 1. Single-org caller with pre-resolved host snapshot + open ResourceStateSnapshotScope
            AuthzCallerContext org10Caller = new AuthzCallerContext(
                    "10",
                    Map.of(
                            "subject.principalId", "hr-mgr",
                            "subject.organizationUnitIds", List.of(10L),
                            AuthzCallerContext.FACT_AUTHORIZED_ORGANIZATION_IDS, List.of(10L)
                    ),
                    Map.of(
                            "subject.principalId", FactResolutionStatus.PRESENT,
                            "subject.organizationUnitIds", FactResolutionStatus.PRESENT,
                            AuthzCallerContext.FACT_AUTHORIZED_ORGANIZATION_IDS, FactResolutionStatus.PRESENT
                    ),
                    Set.of(), Map.of(), null, null
            );

            callerProvider.runWithContext(org10Caller, () -> {
                try (var scope = ResourceStateSnapshotScope.open()) {
                    // findById runs verifyEntityAccess(this, ...) with unproxied target AND seeds un-enriched custom snapshot
                    Beta7BenefitsCaseEntity loaded = proxiedCaseService.findById(101L).body();
                    assertNotNull(loaded);

                    ResourceStateSnapshot hostSeededSnapshot = proxiedCaseService.findResourceStateSnapshot(101L).orElseThrow();
                    assertNull(hostSeededSnapshot.metadata().get(AuthzResourceGovernanceSpec.SNAPSHOT_ENRICHED_META_KEY));

                    assertTrue(availabilityProvider.evaluate(
                            detailSurfaceDef,
                            new SurfaceAvailabilityContext(
                                    "workforce.benefits-cases", "/api/workforce/benefits-cases", 101L,
                                    "10", java.util.Locale.ROOT, () -> "hr-mgr", Set.of(), hostSeededSnapshot
                            )
                    ).allowed());
                    assertTrue(availabilityProvider.evaluate(
                            reviewFormSurfaceDef,
                            new SurfaceAvailabilityContext(
                                    "workforce.benefits-cases", "/api/workforce/benefits-cases", 101L,
                                    "10", java.util.Locale.ROOT, () -> "hr-mgr", Set.of(), hostSeededSnapshot
                            )
                    ).allowed());
                    assertTrue(availabilityProvider.evaluate(
                            homologateActionDef,
                            new ActionAvailabilityContext(
                                    "workforce.benefits-cases", "/api/workforce/benefits-cases", 101L,
                                    "10", java.util.Locale.ROOT, () -> "hr-mgr", Set.of(), hostSeededSnapshot
                            )
                    ).allowed());
                    assertTrue(availabilityProvider.evaluate(
                            ResourceOperationAvailabilityContext.item(
                                    "workforce.benefits-cases", "/api/workforce/benefits-cases", "edit", 101L, hostSeededSnapshot
                            )
                    ).allowed());

                    // Out-of-scope #102 remains denied even if caller supplies a host snapshot stub
                    ResourceStateSnapshot foreignStub = ResourceStateSnapshot.of("DRAFT", Map.of("resource.legalBasis", "Statute"));
                    assertFalse(availabilityProvider.evaluate(
                            detailSurfaceDef,
                            new SurfaceAvailabilityContext(
                                    "workforce.benefits-cases", "/api/workforce/benefits-cases", 102L,
                                    "10", java.util.Locale.ROOT, () -> "hr-mgr", Set.of(), foreignStub
                            )
                    ).allowed());

                    // 2. AUTHENTICATED_SHARED non-"id" @Id entity (employeeNumber = 900212L) inside open ResourceStateSnapshotScope
                    Beta7EmployeeProfileEntity profileLoaded = proxiedProfileService.findById(900212L).body();
                    assertNotNull(profileLoaded);
                    AvailabilityDecision sharedSurfaceDecision = availabilityProvider.evaluate(
                            profileSheetSurfaceDef,
                            new SurfaceAvailabilityContext(
                                    "workforce.employee-profiles", "/api/workforce/employee-profiles", 900212L,
                                    "10", java.util.Locale.ROOT, () -> "hr-mgr", Set.of(), null
                            )
                    );
                    assertTrue(sharedSurfaceDecision.allowed(),
                            "AUTHENTICATED_SHARED item with non-'id' @Id must allow read surface without failing resource-state-unavailable");
                }
            });

            // 3. Consolidation read-only scope: allows view & READ_PROJECTION detail, denies mutating surfaces/actions
            AuthzCallerContext consolidationCaller = new AuthzCallerContext(
                    "10",
                    Map.of(
                            "subject.principalId", "auditor-1",
                            "subject.organizationUnitIds", List.of(10L, 99L),
                            AuthzCallerContext.FACT_AUTHORIZED_ORGANIZATION_IDS, List.of(10L, 99L),
                            AuthzCallerContext.FACT_READ_ONLY_CONSOLIDATION_SCOPE, true
                    ),
                    Map.of(
                            "subject.principalId", FactResolutionStatus.PRESENT,
                            "subject.organizationUnitIds", FactResolutionStatus.PRESENT,
                            AuthzCallerContext.FACT_AUTHORIZED_ORGANIZATION_IDS, FactResolutionStatus.PRESENT,
                            AuthzCallerContext.FACT_READ_ONLY_CONSOLIDATION_SCOPE, FactResolutionStatus.PRESENT
                    ),
                    Set.of(), Map.of(), null, null
            );

            callerProvider.runWithContext(consolidationCaller, () -> {
                try (var scope = ResourceStateSnapshotScope.open()) {
                    assertTrue(availabilityProvider.evaluate(
                            detailSurfaceDef,
                            new SurfaceAvailabilityContext(
                                    "workforce.benefits-cases", "/api/workforce/benefits-cases", 101L,
                                    "10", java.util.Locale.ROOT, () -> "auditor-1", Set.of(), null
                            )
                    ).allowed());
                    assertTrue(availabilityProvider.evaluate(
                            ResourceOperationAvailabilityContext.item(
                                    "workforce.benefits-cases", "/api/workforce/benefits-cases", "view", 101L
                            )
                    ).allowed());

                    AvailabilityDecision deniedForm = availabilityProvider.evaluate(
                            reviewFormSurfaceDef,
                            new SurfaceAvailabilityContext(
                                    "workforce.benefits-cases", "/api/workforce/benefits-cases", 101L,
                                    "10", java.util.Locale.ROOT, () -> "auditor-1", Set.of(), null
                            )
                    );
                    assertFalse(deniedForm.allowed());
                    assertEquals("consolidation-read-only-scope", deniedForm.reason());
                    assertEquals(Boolean.TRUE, deniedForm.metadata().get("readOnlyConsolidation"));

                    AvailabilityDecision deniedAction = availabilityProvider.evaluate(
                            homologateActionDef,
                            new ActionAvailabilityContext(
                                    "workforce.benefits-cases", "/api/workforce/benefits-cases", 101L,
                                    "10", java.util.Locale.ROOT, () -> "auditor-1", Set.of(), null
                            )
                    );
                    assertFalse(deniedAction.allowed());
                    assertEquals("consolidation-read-only-scope", deniedAction.reason());
                    assertEquals(Boolean.TRUE, deniedAction.metadata().get("readOnlyConsolidation"));

                    AvailabilityDecision deniedEdit = availabilityProvider.evaluate(
                            ResourceOperationAvailabilityContext.item(
                                    "workforce.benefits-cases", "/api/workforce/benefits-cases", "edit", 101L
                            )
                    );
                    assertFalse(deniedEdit.allowed());
                    assertEquals("consolidation-read-only-scope", deniedEdit.reason());
                    assertEquals(Boolean.TRUE, deniedEdit.metadata().get("readOnlyConsolidation"));
                }
            });
        } finally {
            emfBean.destroy();
        }
    }

    @Test
    void legacyCallerAvailabilityContextConstructorsAndReadOnlyPostOperationsRespectConsolidationScope() {
        AuthzResourceGovernanceSpec<Beta7BenefitsCaseEntity> caseSpec =
                AuthzResourceGovernanceSpec.<Beta7BenefitsCaseEntity>builder("workforce.benefits-cases")
                        .serviceKey("workforce-svc")
                        .tenantField("organizationId")
                        .workflowAction("homologate", Set.of())
                        .uiSurface("detail", "GET", "/api/workforce/benefits-cases/{id}/surfaces/detail")
                        .uiSurface("view-page", "GET", "/api/workforce/benefits-cases/{id}/surfaces/view-page")
                        .uiSurface("create-form", "POST", "/api/workforce/benefits-cases/surfaces/create-form")
                        .uiSurface("review-form", "PATCH", "/api/workforce/benefits-cases/{id}/review-form")
                        .introspectFromResource(
                                Beta7BenefitsCaseEntity.class,
                                Beta7BenefitsCaseEntity.class,
                                Beta7CaseFilter.class,
                                Beta7BenefitsCaseEntity.class,
                                Beta7BenefitsCaseEntity.class,
                                null,
                                null
                        )
                        .build();

        Map<String, Object> principalPresent = Map.of("!=", List.of(Map.of("var", "subject.principalId"), ""));
        AuthzHostPolicyBootstrapBuilder.AuthzHostPolicyBootstrapBundle bundle =
                AuthzHostPolicyBootstrapBuilder.forService("workforce-svc")
                        .addResourceSpec(caseSpec, Beta7BenefitsCaseEntity.class, Beta7BenefitsCaseEntity.class, Beta7BenefitsCaseEntity.class)
                        .addOrganizationalScopePolicy(
                                caseSpec,
                                "rule-workforce-benefits-cases-scope",
                                "resource.organizationId",
                                "subject.organizationUnitIds",
                                List.of(),
                                List.of()
                        )
                        .addActionPolicy(caseSpec, "homologate", "rule-benefits-homologate", principalPresent)
                        .addSurfacePolicy(caseSpec, "detail", "rule-benefits-detail", principalPresent, List.of())
                        .addSurfacePolicy(caseSpec, "view-page", "rule-benefits-view-page", principalPresent, List.of())
                        .addSurfacePolicy(caseSpec, "create-form", "rule-benefits-create-form", principalPresent, List.of())
                        .addSurfacePolicy(caseSpec, "review-form", "rule-benefits-review-form", principalPresent, List.of())
                        .build();

        String dbName = "wave3_beta8_consolidation_" + UUID.randomUUID().toString().replace("-", "");
        DriverManagerDataSource ds = new DriverManagerDataSource(
                "jdbc:h2:mem:" + dbName + ";MODE=PostgreSQL;DB_CLOSE_DELAY=-1", "sa", "");
        JdbcTemplate jdbcTemplate = new JdbcTemplate(ds);
        TransactionTemplate txTemplate = new TransactionTemplate(new DataSourceTransactionManager(ds));
        MetadataResourceAuthorizationSeam seam = createSeam(bundle, txTemplate, jdbcTemplate);

        Beta7BenefitsCaseEntity inScopeCase = new Beta7BenefitsCaseEntity();
        inScopeCase.id = 101L;
        inScopeCase.organizationId = 10L;
        inScopeCase.processNumber = "PROC-101";
        inScopeCase.workflowStatus = "DRAFT";

        SurfaceDefinition detailSurfaceDef = new SurfaceDefinition(
                "detail", "workforce.benefits-cases", "/api/workforce/benefits-cases",
                "workforce", SurfaceKind.READ_PROJECTION, SurfaceScope.ITEM, "Detail 360", "Detail summary",
                "detail", "visibility", "response", SurfaceResponseCardinality.OBJECT,
                null, null, 1, List.of(), List.of(), List.of(), null
        );
        SurfaceDefinition viewSurfaceDef = new SurfaceDefinition(
                "view-page", "workforce.benefits-cases", "/api/workforce/benefits-cases",
                "workforce", SurfaceKind.VIEW, SurfaceScope.ITEM, "View Page", "Read-only view",
                "viewPage", "visibility", "response", SurfaceResponseCardinality.OBJECT,
                null, null, 2, List.of(), List.of(), List.of(), null
        );
        SurfaceDefinition createFormSurfaceDef = new SurfaceDefinition(
                "create-form", "workforce.benefits-cases", "/api/workforce/benefits-cases",
                "workforce", SurfaceKind.FORM, SurfaceScope.COLLECTION, "Create Form", "Collection create form",
                "createForm", "visibility", "request", SurfaceResponseCardinality.OBJECT,
                null, null, 3, List.of(), List.of(), List.of(), null
        );
        SurfaceDefinition reviewFormSurfaceDef = new SurfaceDefinition(
                "review-form", "workforce.benefits-cases", "/api/workforce/benefits-cases",
                "workforce", SurfaceKind.PARTIAL_FORM, SurfaceScope.ITEM, "Review Form", "Partial review form",
                "reviewForm", "visibility", "response", SurfaceResponseCardinality.OBJECT,
                null, null, 4, List.of(), List.of(), List.of(), null
        );
        ActionDefinition homologateActionDef = new ActionDefinition(
                "homologate", "workforce.benefits-cases", "/api/workforce/benefits-cases",
                "workforce", ActionScope.ITEM, "Homologate", "Approve case",
                null, null, null, 10, "APPROVED", List.of(), List.of("DRAFT"), List.of(),
                ActionExecutionContract.defaults(ActionScope.ITEM)
        );

        Map<String, Object> consolidationFacts = Map.of(
                "subject.principalId", "auditor-1",
                "subject.organizationUnitIds", List.of(10L, 99L),
                AuthzCallerContext.FACT_AUTHORIZED_ORGANIZATION_IDS, List.of(10L, 99L),
                AuthzCallerContext.FACT_READ_ONLY_CONSOLIDATION_SCOPE, true
        );
        Map<String, FactResolutionStatus> consolidationStatuses = Map.of(
                "subject.principalId", FactResolutionStatus.PRESENT,
                "subject.organizationUnitIds", FactResolutionStatus.PRESENT,
                AuthzCallerContext.FACT_AUTHORIZED_ORGANIZATION_IDS, FactResolutionStatus.PRESENT,
                AuthzCallerContext.FACT_READ_ONLY_CONSOLIDATION_SCOPE, FactResolutionStatus.PRESENT
        );

        List<AuthzResourceOperationAvailabilityProvider.CallerAvailabilityFactContext> legacyContexts = List.of(
                new AuthzResourceOperationAvailabilityProvider.CallerAvailabilityFactContext(
                        consolidationFacts,
                        consolidationStatuses,
                        true,
                        false
                ),
                new AuthzResourceOperationAvailabilityProvider.CallerAvailabilityFactContext(
                        consolidationFacts,
                        consolidationStatuses,
                        true,
                        false,
                        "10"
                )
        );

        for (AuthzResourceOperationAvailabilityProvider.CallerAvailabilityFactContext callerFactCtx : legacyContexts) {
            assertTrue(callerFactCtx.readOnlyConsolidation(),
                    "Legacy 4/5-arg constructors must inherit readOnlyConsolidation from trustedSubjectFacts");

            AuthzResourceOperationAvailabilityProvider provider = new AuthzResourceOperationAvailabilityProvider(seam);
            provider.registerResourceBinding(new AuthzResourceOperationAvailabilityProvider.ResourceAvailabilityPolicyBinding(
                    caseSpec.resourceKey(),
                    caseSpec.decisionPoint(),
                    caseSpec.factContractDigest(),
                    caseSpec.dualScopeDelegationSpec(),
                    caseSpec.operationModifiedAttributes(),
                    () -> callerFactCtx,
                    caseSpec::extractSnapshotTargetFacts,
                    rawId -> Optional.of(caseSpec.toResourceStateSnapshot(inScopeCase)),
                    null,
                    null,
                    caseSpec.actionDecisionPoints(),
                    caseSpec.surfaceDecisionPoints()
            ));

            // Mutating operations, workflow actions, and FORM / PARTIAL_FORM surfaces must be denied
            List<AvailabilityDecision> mutatingDenials = List.of(
                    provider.evaluate(new ResourceOperationAvailabilityContext(
                            "workforce.benefits-cases", "/api/workforce/benefits-cases", "create",
                            "COLLECTION", null, null, Map.of("preferredMethod", "POST")
                    )),
                    provider.evaluate(new ResourceOperationAvailabilityContext(
                            "workforce.benefits-cases", "/api/workforce/benefits-cases", "edit",
                            "ITEM", 101L, null, Map.of("preferredMethod", "PATCH")
                    )),
                    provider.evaluate(new ResourceOperationAvailabilityContext(
                            "workforce.benefits-cases", "/api/workforce/benefits-cases", "delete",
                            "ITEM", 101L, null, Map.of("preferredMethod", "DELETE")
                    )),
                    provider.evaluate(
                            homologateActionDef,
                            new ActionAvailabilityContext(
                                    "workforce.benefits-cases", "/api/workforce/benefits-cases", 101L,
                                    "10", java.util.Locale.ROOT, () -> "auditor-1", Set.of(), null
                            )
                    ),
                    provider.evaluate(
                            createFormSurfaceDef,
                            new SurfaceAvailabilityContext(
                                    "workforce.benefits-cases", "/api/workforce/benefits-cases", null,
                                    "10", java.util.Locale.ROOT, () -> "auditor-1", Set.of(), null
                            )
                    ),
                    provider.evaluate(
                            reviewFormSurfaceDef,
                            new SurfaceAvailabilityContext(
                                    "workforce.benefits-cases", "/api/workforce/benefits-cases", 101L,
                                    "10", java.util.Locale.ROOT, () -> "auditor-1", Set.of(), null
                            )
                    )
            );
            for (AvailabilityDecision denied : mutatingDenials) {
                assertFalse(denied.allowed(), "Expected mutating operation/action/form surface to be denied");
                assertEquals("consolidation-read-only-scope", denied.reason());
                assertEquals(Boolean.TRUE, denied.metadata().get("readOnlyConsolidation"));
            }

            // VIEW and READ_PROJECTION surfaces remain allowed
            assertTrue(provider.evaluate(
                    viewSurfaceDef,
                    new SurfaceAvailabilityContext(
                            "workforce.benefits-cases", "/api/workforce/benefits-cases", 101L,
                            "10", java.util.Locale.ROOT, () -> "auditor-1", Set.of(), null
                    )
            ).allowed());
            assertTrue(provider.evaluate(
                    detailSurfaceDef,
                    new SurfaceAvailabilityContext(
                            "workforce.benefits-cases", "/api/workforce/benefits-cases", 101L,
                            "10", java.util.Locale.ROOT, () -> "auditor-1", Set.of(), null
                    )
            ).allowed());

            // Canonical read-only POST (and GET) capability operations remain allowed
            for (String collectionReadOp : List.of(
                    "cursor",
                    "filter-cursor",
                    "optionSources",
                    "option-sources",
                    "by-ids",
                    "statsGroupBy",
                    "statsTimeSeries",
                    "statsDistribution",
                    "statsComparison",
                    "locate",
                    "all"
            )) {
                AvailabilityDecision readDecision = provider.evaluate(new ResourceOperationAvailabilityContext(
                        "workforce.benefits-cases",
                        "/api/workforce/benefits-cases",
                        collectionReadOp,
                        "COLLECTION",
                        null,
                        null,
                        Map.of("preferredMethod", "POST")
                ));
                assertTrue(readDecision.allowed(),
                        "Expected canonical read-only operation '" + collectionReadOp
                                + "' with preferredMethod=POST to remain allowed, got reason="
                                + readDecision.reason());
            }

            AvailabilityDecision byIdDecision = provider.evaluate(new ResourceOperationAvailabilityContext(
                    "workforce.benefits-cases",
                    "/api/workforce/benefits-cases",
                    "byId",
                    "ITEM",
                    101L,
                    null,
                    Map.of("preferredMethod", "POST")
            ));
            assertTrue(byIdDecision.allowed(),
                    "Expected canonical read-only operation 'byId' to remain allowed, got reason="
                            + byIdDecision.reason());
        }
    }
}
