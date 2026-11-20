package org.praxisplatform.authz.starter;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.praxisplatform.authz.autoconfigure.PraxisAuthzAutoConfiguration;
import org.praxisplatform.authz.autoconfigure.PraxisAuthzBootstrapException;
import org.praxisplatform.authz.catalog.MethodBindingAdmissionRecord;
import org.praxisplatform.authz.catalog.SemanticDecisionPointCatalogService;
import org.praxisplatform.authz.compatibility.HostPolicyCompatibilityStartupVerifier;
import org.praxisplatform.authz.compatibility.HostRuntimePolicyCoordinates;
import org.praxisplatform.authz.compatibility.PraxisAuthzReadinessHealthIndicator;
import org.praxisplatform.authz.contracts.binding.WriteIntent;
import org.praxisplatform.authz.contracts.compatibility.ImpactCompletenessStatus;
import org.praxisplatform.authz.contracts.compatibility.ImpactGraphBaseline;
import org.praxisplatform.authz.contracts.context.ProviderInputProjection;
import org.praxisplatform.authz.contracts.envelope.ProviderEvaluationEnvelope;
import org.praxisplatform.authz.enforcement.pipeline.AuthorizationProviderPort;
import org.praxisplatform.authz.enforcement.pipeline.EnforcementPipelineExecutor;
import org.praxisplatform.authz.host.metadata.AuthzHostPolicyBootstrapBuilder.AuthzHostPolicyBootstrapBundle;
import org.praxisplatform.authz.opa.client.HttpClientOpaTransport;
import org.praxisplatform.authz.opa.client.OpaClientTransport;
import org.praxisplatform.authz.pilot.WorkforceLeaveAuthzPilotBlueprint;
import org.springframework.boot.actuate.health.Status;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

/**
 * Conformance tests for {@link PraxisAuthzAutoConfiguration}, {@link HostPolicyCompatibilityStartupVerifier},
 * and {@link PraxisAuthzReadinessHealthIndicator} ({@code CC08}, {@code P20}, {@code P39}, {@code P48}, {@code P59}).
 */
class PraxisAuthzAutoConfigurationAndBootstrapTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(PraxisAuthzAutoConfiguration.class));

    @Test
    void cc08_p20_autoConfigurationStartsCleanlyWithValidPilotCoordinatesAndReportsHealthUp() {
        WorkforceLeaveAuthzPilotBlueprint blueprint = WorkforceLeaveAuthzPilotBlueprint.createWorkforceLeaveBlueprint();

        contextRunner
                .withBean(OpaClientTransport.class, blueprint::localOpaTransport)
                .withBean(HostRuntimePolicyCoordinates.class, blueprint::coordinates)
                .withBean(MethodBindingAdmissionRecord.class, () -> blueprint.admissionRecords().getFirst())
                .run(context -> {
                    assertNotNull(context.getStartupFailure() == null ? context : null);
                    assertTrue(context.containsBean("enforcementPipelineExecutor"));
                    assertNotNull(context.getBean(EnforcementPipelineExecutor.class));
                    assertNotNull(context.getBean(SemanticDecisionPointCatalogService.class));

                    HostPolicyCompatibilityStartupVerifier verifier =
                            context.getBean(HostPolicyCompatibilityStartupVerifier.class);
                    assertTrue(verifier.currentStatus().ready());
                    assertEquals("UP", verifier.currentStatus().statusCode());
                    assertEquals(1, verifier.currentStatus().verifiedDecisionPointCount());

                    PraxisAuthzReadinessHealthIndicator healthIndicator =
                            context.getBean(PraxisAuthzReadinessHealthIndicator.class);
                    assertEquals(Status.UP, healthIndicator.health().getStatus());
                });
    }

    @Test
    void p20_startupFailsClosedWhenProviderOrBindingsAreMissingOrWhenTwoProvidersCompete() {
        WorkforceLeaveAuthzPilotBlueprint blueprint = WorkforceLeaveAuthzPilotBlueprint.createWorkforceLeaveBlueprint();

        // 1. P20: Missing provider -> startup fails closed with AUTHZ_BOOTSTRAP_MISSING_PROVIDER
        contextRunner
                .withBean(HostRuntimePolicyCoordinates.class, blueprint::coordinates)
                .run(context -> {
                    assertNotNull(context.getStartupFailure());
                    Throwable root = findBootstrapCause(context.getStartupFailure());
                    assertTrue(root instanceof PraxisAuthzBootstrapException);
                    assertEquals("AUTHZ_BOOTSTRAP_MISSING_PROVIDER", ((PraxisAuthzBootstrapException) root).errorCode());
                });

        // 2. P20: Two competing AuthorizationProviderPort beans -> startup fails closed with AUTHZ_BOOTSTRAP_AMBIGUOUS_PROVIDERS
        AuthorizationProviderPort dummyProvider1 = new NoopAuthorizationProviderPort();
        AuthorizationProviderPort dummyProvider2 = new NoopAuthorizationProviderPort();
        contextRunner
                .withBean("providerOne", AuthorizationProviderPort.class, () -> dummyProvider1)
                .withBean("providerTwo", AuthorizationProviderPort.class, () -> dummyProvider2)
                .withBean(HostRuntimePolicyCoordinates.class, blueprint::coordinates)
                .run(context -> {
                    assertNotNull(context.getStartupFailure());
                    Throwable root = findBootstrapCause(context.getStartupFailure());
                    assertTrue(root instanceof PraxisAuthzBootstrapException);
                    assertEquals("AUTHZ_BOOTSTRAP_AMBIGUOUS_PROVIDERS", ((PraxisAuthzBootstrapException) root).errorCode());
                });
    }

    @Test
    void p39_p48_p59_startupFailsClosedOnImpactGraphIncompletenessOrContractDigestDrift() {
        WorkforceLeaveAuthzPilotBlueprint blueprint = WorkforceLeaveAuthzPilotBlueprint.createWorkforceLeaveBlueprint();

        ImpactGraphBaseline incompleteImpact = new ImpactGraphBaseline(
                "imp-incomplete",
                ImpactCompletenessStatus.PARTIAL,
                Set.of(),
                Set.of(blueprint.decisionPoint().identity().pointKey()),
                Set.of("REDACT_CONSTANT"),
                Set.of("DURABLE_AUDIT_EVIDENCE"),
                Set.of("UNRESOLVED_SELECTOR_LINEAGE")
        );

        HostRuntimePolicyCoordinates brokenCoordinates = new HostRuntimePolicyCoordinates(
                blueprint.coordinates().hostManifest(),
                blueprint.coordinates().runtimeRelease(),
                incompleteImpact,
                Map.of(), // missing FactContract triggers COMPAT_MISSING_FACT_CONTRACT as well
                blueprint.coordinates().queryProjectionsByRef(),
                Map.of(
                        blueprint.decisionPoint().identity().pointKey(),
                        blueprint.enforcementBinding(),
                        "resource-operation:praxis-workforce-showcase:orphan.resource:read",
                        blueprint.enforcementBinding() // P4-R01: orphan binding not in manifest!
                )
        );

        // 1. With failClosedOnBootstrapError=true (default), startup throws PraxisAuthzBootstrapException
        contextRunner
                .withBean(OpaClientTransport.class, blueprint::localOpaTransport)
                .withBean(HostRuntimePolicyCoordinates.class, () -> brokenCoordinates)
                .run(context -> {
                    assertNotNull(context.getStartupFailure());
                    Throwable root = findBootstrapCause(context.getStartupFailure());
                    assertTrue(root instanceof PraxisAuthzBootstrapException);
                    List<String> diagnostics = ((PraxisAuthzBootstrapException) root).diagnostics();
                    assertTrue(diagnostics.stream().anyMatch(d -> d.startsWith("COMPAT_IMPACT_NOT_COMPLETE")));
                    assertTrue(diagnostics.stream().anyMatch(d -> d.startsWith("COMPAT_MISSING_FACT_CONTRACT")));
                    assertTrue(diagnostics.stream().anyMatch(d -> d.startsWith("COMPAT_ORPHAN_RUNTIME_BINDING")));
                });

        // 2. With failClosedOnBootstrapError=false, context starts in OUT_OF_SERVICE readiness state (never UP)
        contextRunner
                .withPropertyValues("praxis.authz.fail-closed-on-bootstrap-error=false")
                .withBean(OpaClientTransport.class, blueprint::localOpaTransport)
                .withBean(HostRuntimePolicyCoordinates.class, () -> brokenCoordinates)
                .run(context -> {
                    HostPolicyCompatibilityStartupVerifier verifier =
                            context.getBean(HostPolicyCompatibilityStartupVerifier.class);
                    assertFalse(verifier.currentStatus().ready());
                    assertEquals("OUT_OF_SERVICE", verifier.currentStatus().statusCode());
                    PraxisAuthzReadinessHealthIndicator healthIndicator =
                            context.getBean(PraxisAuthzReadinessHealthIndicator.class);
                    assertEquals(Status.OUT_OF_SERVICE, healthIndicator.health().getStatus());
                });
    }

    @Test
    void p4r1_p4r4_httpTransportPropertyAutoWiresHttpClientOpaTransportAndManifestMaskStrategyIsVerifiedAgainstRegistry() {
        WorkforceLeaveAuthzPilotBlueprint blueprint = WorkforceLeaveAuthzPilotBlueprint.createWorkforceLeaveBlueprint();

        // 1. P4-R1: praxis.authz.opa.http-transport-enabled=true registers HttpClientOpaTransport out-of-the-box
        contextRunner
                .withPropertyValues(
                        "praxis.authz.opa.http-transport-enabled=true",
                        "praxis.authz.opa.base-url=http://127.0.0.1:8181",
                        "praxis.authz.opa.instance-id=opa-node-1"
                )
                .withBean(HostRuntimePolicyCoordinates.class, blueprint::coordinates)
                .run(context -> {
                    assertNotNull(context.getStartupFailure() == null ? context : null);
                    assertTrue(context.containsBean("httpClientOpaTransport"));
                    assertTrue(context.containsBean("opaAuthorizationProviderAdapter"));
                });

        // 2. P4-R4: Host manifest claiming a mask strategy not present in MaskStrategyRegistry fails closed
        org.praxisplatform.authz.contracts.compatibility.HostPolicyCompatibilityManifest manifestWithPhantomStrategy =
                new org.praxisplatform.authz.contracts.compatibility.HostPolicyCompatibilityManifest(
                        blueprint.coordinates().hostManifest().schemaVersion(),
                        blueprint.coordinates().hostManifest().hostApplicationId(),
                        blueprint.coordinates().hostManifest().serviceKey(),
                        blueprint.coordinates().hostManifest().hostReleaseVersion(),
                        blueprint.coordinates().hostManifest().generatedAt(),
                        blueprint.coordinates().hostManifest().supportedProviderIoSchemas(),
                        Set.of("REDACT_CONSTANT", "PHANTOM_UNREGISTERED_STRATEGY"),
                        blueprint.coordinates().hostManifest().registeredObligationTypes(),
                        blueprint.coordinates().hostManifest().decisionPointBindings()
                );
        HostRuntimePolicyCoordinates phantomCoordinates = new HostRuntimePolicyCoordinates(
                manifestWithPhantomStrategy,
                blueprint.coordinates().runtimeRelease(),
                blueprint.coordinates().impactBaseline(),
                blueprint.coordinates().factContractsById(),
                blueprint.coordinates().queryProjectionsByRef(),
                blueprint.coordinates().bindingsByPointKey()
        );

        contextRunner
                .withBean(OpaClientTransport.class, blueprint::localOpaTransport)
                .withBean(HostRuntimePolicyCoordinates.class, () -> phantomCoordinates)
                .run(context -> {
                    assertNotNull(context.getStartupFailure());
                    Throwable root = findBootstrapCause(context.getStartupFailure());
                    assertTrue(root instanceof PraxisAuthzBootstrapException);
                    List<String> diagnostics = ((PraxisAuthzBootstrapException) root).diagnostics();
                    assertTrue(diagnostics.contains("COMPAT_UNREGISTERED_HOST_MASK_STRATEGY:PHANTOM_UNREGISTERED_STRATEGY"));
                });
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(booleans = {false, true})
    void bootstrapBundleUsesHttpOnlyWhenEnabledAndAnExplicitHostTransportTakesPrecedence(Boolean httpEnabled) {
        var blueprint = WorkforceLeaveAuthzPilotBlueprint.createWorkforceLeaveBlueprint();
        var bundle = new AuthzHostPolicyBootstrapBundle(
                blueprint.serviceKey(),
                blueprint.coordinates(),
                blueprint.admissionRecords(),
                blueprint.bundleArtifact(),
                blueprint.localOpaTransport(),
                List.of(blueprint.policyDefinition())
        );
        var runner = contextRunner.withBean(AuthzHostPolicyBootstrapBundle.class, () -> bundle);
        if (httpEnabled != null) {
            runner = runner.withPropertyValues("praxis.authz.opa.http-transport-enabled=" + httpEnabled);
        }

        runner.run(context -> {
            assertEquals(1, context.getBeansOfType(OpaClientTransport.class).size());
            OpaClientTransport selected = context.getBean(OpaClientTransport.class);
            if (Boolean.TRUE.equals(httpEnabled)) {
                assertTrue(selected instanceof HttpClientOpaTransport);
                assertFalse(context.containsBean("bootstrapBundleLocalOpaTransport"));
            } else {
                assertSame(bundle.localOpaTransport(), selected);
                assertFalse(context.containsBean("httpClientOpaTransport"));
            }
            assertNotNull(context.getBean(AuthorizationProviderPort.class));
            assertSame(bundle.coordinates(), context.getBean(HostRuntimePolicyCoordinates.class));
        });

        OpaClientTransport hostTransport = WorkforceLeaveAuthzPilotBlueprint
                .createWorkforceLeaveBlueprint().localOpaTransport();
        runner.withBean(OpaClientTransport.class, () -> hostTransport).run(context -> {
            assertEquals(1, context.getBeansOfType(OpaClientTransport.class).size());
            assertSame(hostTransport, context.getBean(OpaClientTransport.class));
            assertFalse(context.containsBean("httpClientOpaTransport"));
            assertFalse(context.containsBean("bootstrapBundleLocalOpaTransport"));
            assertNotNull(context.getBean(AuthorizationProviderPort.class));
        });
    }

    private static Throwable findBootstrapCause(Throwable throwable) {
        Throwable curr = throwable;
        while (curr != null) {
            if (curr instanceof PraxisAuthzBootstrapException) {
                return curr;
            }
            curr = curr.getCause();
        }
        return throwable;
    }

    private static final class NoopAuthorizationProviderPort implements AuthorizationProviderPort {
        @Override
        public ProviderEvaluationEnvelope evaluateTarget(
                ProviderInputProjection inputProjection, WriteIntent writeIntent) {
            throw new UnsupportedOperationException("Noop");
        }

        @Override
        public SearchProviderEvaluationResult evaluateSearch(ProviderInputProjection inputProjection) {
            throw new UnsupportedOperationException("Noop");
        }
    }
}
