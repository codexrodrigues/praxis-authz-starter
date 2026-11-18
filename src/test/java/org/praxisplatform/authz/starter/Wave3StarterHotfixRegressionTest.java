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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.praxisplatform.authz.autoconfigure.PraxisAuthzHostBridgeAutoConfiguration;
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
import org.praxisplatform.authz.host.metadata.PraxisAuthzExceptionHandler;
import org.praxisplatform.authz.host.metadata.ThreadLocalAuthzCallerContextProvider;
import org.praxisplatform.authz.opa.client.OpaAuthorizationProviderAdapter;
import org.praxisplatform.authz.opa.revision.SameInstanceSearchRevisionGuard;
import org.praxisplatform.authz.outbox.JdbcTransactionalAuditOutbox;
import org.praxisplatform.authz.seams.MetadataResourceAuthorizationSeam;
import org.praxisplatform.authz.telemetry.SanitizedAuthorizationTelemetryPublisher;
import org.praxisplatform.uischema.mapper.base.ResourceMapper;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.util.ReflectionTestUtils;
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
    private static final class SampleOrgEntity {
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
}
