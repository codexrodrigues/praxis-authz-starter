package org.praxisplatform.authz.autoconfigure;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.praxisplatform.authz.catalog.MethodBindingAdmissionRecord;
import org.praxisplatform.authz.catalog.SemanticDecisionPointCatalogService;
import org.praxisplatform.authz.channel.GovernedChannelInvocationExecutor;
import org.praxisplatform.authz.compatibility.HostPolicyCompatibilityStartupVerifier;
import org.praxisplatform.authz.compatibility.HostRuntimePolicyCoordinates;
import org.praxisplatform.authz.compatibility.PraxisAuthzReadinessHealthIndicator;
import org.praxisplatform.authz.host.metadata.AuthzHostPolicyBootstrapBuilder.AuthzHostPolicyBootstrapBundle;
import org.praxisplatform.authz.contracts.compatibility.DefaultHostPolicyCompatibilityVerifier;
import org.praxisplatform.authz.contracts.compatibility.HostPolicyCompatibilityVerifier;
import org.praxisplatform.authz.contracts.masking.DefaultMaskStrategyRegistry;
import org.praxisplatform.authz.contracts.masking.MaskStrategyRegistry;
import org.praxisplatform.authz.contracts.obligation.DefaultObligationHandlerRegistry;
import org.praxisplatform.authz.contracts.obligation.ObligationHandlerRegistry;
import org.praxisplatform.authz.enforcement.context.ContextCompositionCoordinator;
import org.praxisplatform.authz.enforcement.context.TrustedFactSource;
import org.praxisplatform.authz.enforcement.fielduse.FieldUseQueryGuard;
import org.praxisplatform.authz.enforcement.masking.DetachedDtoMaskingProcessor;
import org.praxisplatform.authz.enforcement.obligation.InMemoryTransactionalAuditOutbox;
import org.praxisplatform.authz.enforcement.obligation.ObligationBarrierCoordinator;
import org.praxisplatform.authz.enforcement.obligation.TransactionalAuditOutboxPort;
import org.praxisplatform.authz.enforcement.pipeline.AuthorizationProviderPort;
import org.praxisplatform.authz.enforcement.pipeline.EnforcementPipelineExecutor;
import org.praxisplatform.authz.enforcement.pipeline.HostDecisionNormalizationEngine;
import org.praxisplatform.authz.enforcement.writeintent.DtoWriteIntentExtractor;
import org.praxisplatform.authz.enforcement.writeintent.FieldWriteAuthorizer;
import org.praxisplatform.authz.export.GovernedCollectionExportGuard;
import org.praxisplatform.authz.opa.bundle.OpaBundleAssembler;
import org.praxisplatform.authz.opa.client.HttpClientOpaTransport;
import org.praxisplatform.authz.opa.client.OpaAuthorizationProviderAdapter;
import org.praxisplatform.authz.opa.client.OpaClientTransport;
import org.praxisplatform.authz.opa.compiler.RegoV1PolicyCompiler;
import org.praxisplatform.authz.opa.governance.GovernedOpaReleaseCoordinator;
import org.praxisplatform.authz.opa.revision.SameInstanceSearchRevisionGuard;
import org.praxisplatform.authz.controlplane.ConfigMaterializationToOpaReconciler;
import org.praxisplatform.authz.controlplane.GovernedPapAdminOperationsService;
import org.praxisplatform.authz.outbox.AuditOutboxDeliverySinkPort;
import org.praxisplatform.authz.outbox.JdbcAuditOutboxRelayExecutor;
import org.praxisplatform.authz.outbox.JdbcTransactionalAuditOutbox;
import org.praxisplatform.authz.pilot.GovernedPolicyAuthoringGateway;
import org.praxisplatform.authz.pilot.JdbcSessionContextIsolationGuard;
import org.praxisplatform.authz.seams.DeclarativeDecisionPointExecutionTemplate;
import org.praxisplatform.authz.seams.GovernedExportAndAiToolAuthorizationSeam;
import org.praxisplatform.authz.seams.MetadataResourceAuthorizationSeam;
import org.praxisplatform.authz.seams.RuntimeDecisionPointRegistry;
import org.praxisplatform.authz.telemetry.AuthorizationTelemetrySinkPort;
import org.praxisplatform.authz.telemetry.SanitizedAuthorizationTelemetryPublisher;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.actuate.health.HealthIndicator;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnSingleCandidate;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.jdbc.core.JdbcOperations;

/**
 * Canonical Spring Boot auto-configuration for {@code praxis-authz-starter} ({@code CC01–CC12},
 * {@code P20}, {@code P34}, {@code P35}, {@code P39}).
 *
 * <p>Wires the 15-step enforcement pipeline, OPA compiler/bundle/release services, semantic PAP
 * catalog discovery, and fail-closed startup compatibility handshake without permitting silent
 * {@code allowAll} fallbacks or ambiguous authoritative providers ({@code P20}).</p>
 */
@AutoConfiguration
@EnableConfigurationProperties(PraxisAuthzProperties.class)
@ConditionalOnProperty(prefix = "praxis.authz", name = "enabled", havingValue = "true", matchIfMissing = true)
public class PraxisAuthzAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean
    public ContextCompositionCoordinator contextCompositionCoordinator(
            ObjectProvider<TrustedFactSource> trustedFactSources
    ) {
        return new ContextCompositionCoordinator(trustedFactSources.orderedStream().toList());
    }

    @Bean
    @ConditionalOnMissingBean
    public HostDecisionNormalizationEngine hostDecisionNormalizationEngine() {
        return new HostDecisionNormalizationEngine();
    }

    @Bean
    @ConditionalOnMissingBean
    public FieldUseQueryGuard fieldUseQueryGuard() {
        return new FieldUseQueryGuard();
    }

    @Bean
    @ConditionalOnMissingBean
    public DtoWriteIntentExtractor dtoWriteIntentExtractor() {
        return new DtoWriteIntentExtractor();
    }

    @Bean
    @ConditionalOnMissingBean
    public FieldWriteAuthorizer fieldWriteAuthorizer() {
        return new FieldWriteAuthorizer();
    }

    @Bean
    @ConditionalOnMissingBean
    public MaskStrategyRegistry maskStrategyRegistry() {
        return new DefaultMaskStrategyRegistry();
    }

    @Bean
    @ConditionalOnMissingBean
    public DetachedDtoMaskingProcessor detachedDtoMaskingProcessor(
            MaskStrategyRegistry maskStrategyRegistry,
            PraxisAuthzProperties properties
    ) {
        return new DetachedDtoMaskingProcessor(
                maskStrategyRegistry,
                properties.getMaskingHmacSecret().getBytes(StandardCharsets.UTF_8)
        );
    }

    @Bean
    @ConditionalOnMissingBean
    public ObligationHandlerRegistry obligationHandlerRegistry() {
        return new DefaultObligationHandlerRegistry();
    }

    @Bean
    @ConditionalOnClass(JdbcOperations.class)
    @ConditionalOnBean(JdbcOperations.class)
    @ConditionalOnProperty(prefix = "praxis.authz.outbox", name = "jdbc-enabled", havingValue = "true", matchIfMissing = true)
    @ConditionalOnMissingBean(TransactionalAuditOutboxPort.class)
    public JdbcTransactionalAuditOutbox jdbcTransactionalAuditOutbox(
            JdbcOperations jdbcOperations,
            PraxisAuthzProperties properties
    ) {
        return new JdbcTransactionalAuditOutbox(
                jdbcOperations,
                properties.getOutbox().getTableName(),
                properties.getOutbox().isInitializeSchema(),
                properties.getOutbox().isRequireActiveTransaction()
        );
    }

    @Bean
    @ConditionalOnMissingBean(TransactionalAuditOutboxPort.class)
    public TransactionalAuditOutboxPort transactionalAuditOutboxPort() {
        return new InMemoryTransactionalAuditOutbox();
    }

    @Bean
    @ConditionalOnMissingBean
    public ObligationBarrierCoordinator obligationBarrierCoordinator(
            ObligationHandlerRegistry obligationHandlerRegistry,
            TransactionalAuditOutboxPort transactionalAuditOutboxPort
    ) {
        return new ObligationBarrierCoordinator(obligationHandlerRegistry, transactionalAuditOutboxPort);
    }

    @Bean
    @ConditionalOnMissingBean
    public SameInstanceSearchRevisionGuard sameInstanceSearchRevisionGuard(PraxisAuthzProperties properties) {
        return new SameInstanceSearchRevisionGuard(properties.getOpa().getSearchMaxSameInstanceRetries());
    }

    @Bean
    @ConditionalOnBean(AuthzHostPolicyBootstrapBundle.class)
    @ConditionalOnMissingBean(HostRuntimePolicyCoordinates.class)
    public HostRuntimePolicyCoordinates bootstrapBundleHostRuntimePolicyCoordinates(
            AuthzHostPolicyBootstrapBundle bundle
    ) {
        return bundle.coordinates();
    }

    @Bean
    @ConditionalOnBean(AuthzHostPolicyBootstrapBundle.class)
    @ConditionalOnMissingBean(OpaClientTransport.class)
    public OpaClientTransport bootstrapBundleLocalOpaTransport(
            AuthzHostPolicyBootstrapBundle bundle
    ) {
        return bundle.localOpaTransport();
    }

    @Bean
    @ConditionalOnProperty(prefix = "praxis.authz.opa", name = "http-transport-enabled", havingValue = "true")
    @ConditionalOnMissingBean(OpaClientTransport.class)
    public OpaClientTransport httpClientOpaTransport(PraxisAuthzProperties properties) {
        String instanceId = properties.getOpa().getInstanceId();
        URI baseUri = URI.create(properties.getOpa().getBaseUrl());
        return new HttpClientOpaTransport(
                instanceId,
                Map.of(instanceId, baseUri),
                properties.getOpa().getRequestTimeout()
        );
    }

    @Bean
    @ConditionalOnBean(OpaClientTransport.class)
    @ConditionalOnMissingBean(AuthorizationProviderPort.class)
    public AuthorizationProviderPort opaAuthorizationProviderAdapter(
            OpaClientTransport transport,
            SameInstanceSearchRevisionGuard searchRevisionGuard
    ) {
        return new OpaAuthorizationProviderAdapter(transport, searchRevisionGuard);
    }

    @Bean
    @ConditionalOnSingleCandidate(AuthorizationProviderPort.class)
    @ConditionalOnMissingBean
    public EnforcementPipelineExecutor enforcementPipelineExecutor(
            AuthorizationProviderPort providerPort,
            HostDecisionNormalizationEngine normalizationEngine,
            FieldUseQueryGuard fieldUseQueryGuard,
            FieldWriteAuthorizer fieldWriteAuthorizer,
            DetachedDtoMaskingProcessor maskingProcessor,
            ObligationBarrierCoordinator obligationCoordinator
    ) {
        return new EnforcementPipelineExecutor(
                providerPort,
                normalizationEngine,
                fieldUseQueryGuard,
                fieldWriteAuthorizer,
                maskingProcessor,
                obligationCoordinator
        );
    }

    @Bean
    @ConditionalOnMissingBean
    public RegoV1PolicyCompiler regoV1PolicyCompiler() {
        return new RegoV1PolicyCompiler();
    }

    @Bean
    @ConditionalOnMissingBean
    public OpaBundleAssembler opaBundleAssembler() {
        return new OpaBundleAssembler();
    }

    @Bean
    @ConditionalOnMissingBean
    public GovernedOpaReleaseCoordinator governedOpaReleaseCoordinator() {
        return new GovernedOpaReleaseCoordinator();
    }

    @Bean
    @ConditionalOnMissingBean
    public HostPolicyCompatibilityVerifier hostPolicyCompatibilityVerifier() {
        return new DefaultHostPolicyCompatibilityVerifier();
    }

    @Bean
    @ConditionalOnMissingBean
    public HostPolicyCompatibilityStartupVerifier hostPolicyCompatibilityStartupVerifier(
            PraxisAuthzProperties properties,
            ObjectProvider<AuthorizationProviderPort> providerPorts,
            HostPolicyCompatibilityVerifier compatibilityVerifier,
            MaskStrategyRegistry maskStrategyRegistry,
            ObligationHandlerRegistry obligationHandlerRegistry,
            ObjectProvider<HostRuntimePolicyCoordinates> coordinatesProvider,
            ObjectProvider<AuthzHostPolicyBootstrapBundle> bootstrapBundleProvider
    ) {
        HostRuntimePolicyCoordinates coordinates = coordinatesProvider.getIfAvailable();
        if (coordinates == null) {
            AuthzHostPolicyBootstrapBundle bundle = bootstrapBundleProvider.getIfAvailable();
            if (bundle != null) {
                coordinates = bundle.coordinates();
            }
        }
        return new HostPolicyCompatibilityStartupVerifier(
                properties,
                providerPorts.orderedStream().toList(),
                compatibilityVerifier,
                maskStrategyRegistry,
                obligationHandlerRegistry,
                coordinates
        );
    }

    @Bean
    @ConditionalOnClass(HealthIndicator.class)
    @ConditionalOnMissingBean(name = "praxisAuthzReadinessHealthIndicator")
    public PraxisAuthzReadinessHealthIndicator praxisAuthzReadinessHealthIndicator(
            HostPolicyCompatibilityStartupVerifier startupVerifier
    ) {
        return new PraxisAuthzReadinessHealthIndicator(startupVerifier);
    }

    @Bean
    @ConditionalOnMissingBean
    public SemanticDecisionPointCatalogService semanticDecisionPointCatalogService(
            PraxisAuthzProperties properties,
            ObjectProvider<MethodBindingAdmissionRecord> admissionRecords,
            ObjectProvider<List<MethodBindingAdmissionRecord>> admissionRecordLists,
            ObjectProvider<AuthzHostPolicyBootstrapBundle> bootstrapBundleProvider
    ) {
        return new SemanticDecisionPointCatalogService(
                properties,
                resolveAdmissionRecords(admissionRecords, admissionRecordLists, bootstrapBundleProvider)
        );
    }

    @Bean
    @ConditionalOnMissingBean
    public GovernedChannelInvocationExecutor governedChannelInvocationExecutor() {
        return new GovernedChannelInvocationExecutor();
    }

    @Bean
    @ConditionalOnMissingBean
    public GovernedCollectionExportGuard governedCollectionExportGuard(
            DetachedDtoMaskingProcessor maskingProcessor
    ) {
        return new GovernedCollectionExportGuard(maskingProcessor);
    }

    @Bean
    @ConditionalOnMissingBean
    public JdbcSessionContextIsolationGuard jdbcSessionContextIsolationGuard(PraxisAuthzProperties properties) {
        return new JdbcSessionContextIsolationGuard(properties.getJdbc().getAdmittedDbRoles());
    }

    @Bean
    @ConditionalOnMissingBean
    public GovernedPolicyAuthoringGateway governedPolicyAuthoringGateway(
            GovernedOpaReleaseCoordinator releaseCoordinator
    ) {
        return new GovernedPolicyAuthoringGateway(releaseCoordinator);
    }

    @Bean
    @ConditionalOnMissingBean
    public ConfigMaterializationToOpaReconciler configMaterializationToOpaReconciler(
            RegoV1PolicyCompiler regoV1PolicyCompiler,
            GovernedOpaReleaseCoordinator releaseCoordinator
    ) {
        return new ConfigMaterializationToOpaReconciler(regoV1PolicyCompiler, releaseCoordinator);
    }

    @Bean
    @ConditionalOnSingleCandidate(AuthorizationProviderPort.class)
    @ConditionalOnMissingBean
    public MetadataResourceAuthorizationSeam metadataResourceAuthorizationSeam(
            AuthorizationProviderPort providerPort,
            FieldUseQueryGuard fieldUseQueryGuard,
            DtoWriteIntentExtractor writeIntentExtractor,
            FieldWriteAuthorizer fieldWriteAuthorizer,
            DetachedDtoMaskingProcessor maskingProcessor,
            ObligationBarrierCoordinator obligationCoordinator,
            SanitizedAuthorizationTelemetryPublisher telemetryPublisher
    ) {
        return new MetadataResourceAuthorizationSeam(
                providerPort,
                fieldUseQueryGuard,
                writeIntentExtractor,
                fieldWriteAuthorizer,
                maskingProcessor,
                obligationCoordinator,
                telemetryPublisher
        );
    }

    @Bean
    @ConditionalOnBean({JdbcTransactionalAuditOutbox.class, AuditOutboxDeliverySinkPort.class})
    @ConditionalOnMissingBean
    public JdbcAuditOutboxRelayExecutor jdbcAuditOutboxRelayExecutor(
            JdbcTransactionalAuditOutbox outbox,
            AuditOutboxDeliverySinkPort sinkPort,
            PraxisAuthzProperties properties
    ) {
        return new JdbcAuditOutboxRelayExecutor(
                outbox,
                sinkPort,
                properties.getOutbox().getRelayBatchSize(),
                properties.getOutbox().getMaxDeliveryAttempts()
        );
    }

    @Bean
    @ConditionalOnMissingBean
    public RuntimeDecisionPointRegistry runtimeDecisionPointRegistry(
            ObjectProvider<MethodBindingAdmissionRecord> admissionRecords,
            ObjectProvider<List<MethodBindingAdmissionRecord>> admissionRecordLists,
            ObjectProvider<HostRuntimePolicyCoordinates> coordinatesProvider,
            ObjectProvider<AuthzHostPolicyBootstrapBundle> bootstrapBundleProvider
    ) {
        HostRuntimePolicyCoordinates coordinates = coordinatesProvider.getIfAvailable();
        if (coordinates == null) {
            AuthzHostPolicyBootstrapBundle bundle = bootstrapBundleProvider.getIfAvailable();
            if (bundle != null) {
                coordinates = bundle.coordinates();
            }
        }
        return new RuntimeDecisionPointRegistry(
                resolveAdmissionRecords(admissionRecords, admissionRecordLists, bootstrapBundleProvider),
                coordinates
        );
    }

    private static List<MethodBindingAdmissionRecord> resolveAdmissionRecords(
            ObjectProvider<MethodBindingAdmissionRecord> admissionRecords,
            ObjectProvider<List<MethodBindingAdmissionRecord>> admissionRecordLists,
            ObjectProvider<AuthzHostPolicyBootstrapBundle> bootstrapBundleProvider
    ) {
        Map<String, MethodBindingAdmissionRecord> merged = new LinkedHashMap<>();
        if (admissionRecords != null) {
            admissionRecords.orderedStream().forEach(record -> {
                if (record != null && record.decisionPoint() != null) {
                    merged.putIfAbsent(record.decisionPoint().identity().pointKey(), record);
                }
            });
        }
        if (admissionRecordLists != null) {
            admissionRecordLists.orderedStream().forEach(list -> {
                if (list != null) {
                    for (MethodBindingAdmissionRecord record : list) {
                        if (record != null && record.decisionPoint() != null) {
                            merged.putIfAbsent(record.decisionPoint().identity().pointKey(), record);
                        }
                    }
                }
            });
        }
        if (bootstrapBundleProvider != null) {
            bootstrapBundleProvider.orderedStream().forEach(bundle -> {
                if (bundle != null && bundle.admissionRecords() != null) {
                    for (MethodBindingAdmissionRecord record : bundle.admissionRecords()) {
                        if (record != null && record.decisionPoint() != null) {
                            merged.putIfAbsent(record.decisionPoint().identity().pointKey(), record);
                        }
                    }
                }
            });
        }
        return List.copyOf(merged.values());
    }

    @Bean
    @ConditionalOnBean(MetadataResourceAuthorizationSeam.class)
    @ConditionalOnMissingBean
    public DeclarativeDecisionPointExecutionTemplate declarativeDecisionPointExecutionTemplate(
            RuntimeDecisionPointRegistry registry,
            MetadataResourceAuthorizationSeam seam,
            GovernedChannelInvocationExecutor channelExecutor,
            ObjectProvider<GovernedExportAndAiToolAuthorizationSeam> exportAndAiSeamProvider
    ) {
        return new DeclarativeDecisionPointExecutionTemplate(
                registry,
                seam,
                channelExecutor,
                exportAndAiSeamProvider.getIfAvailable()
        );
    }

    @Bean
    @ConditionalOnProperty(prefix = "praxis.authz.admin-endpoints", name = "enabled", havingValue = "true")
    @ConditionalOnMissingBean
    public GovernedPapAdminOperationsService governedPapAdminOperationsService(
            PraxisAuthzProperties properties,
            SemanticDecisionPointCatalogService catalogService,
            ConfigMaterializationToOpaReconciler reconciler,
            RuntimeDecisionPointRegistry registry
    ) {
        return new GovernedPapAdminOperationsService(properties, catalogService, reconciler, registry);
    }

    @Bean
    @ConditionalOnMissingBean
    public SanitizedAuthorizationTelemetryPublisher sanitizedAuthorizationTelemetryPublisher(
            ObjectProvider<AuthorizationTelemetrySinkPort> sinks,
            PraxisAuthzProperties properties
    ) {
        return new SanitizedAuthorizationTelemetryPublisher(
                sinks.orderedStream().toList(),
                properties.getTelemetry().getMaxBufferedEvents()
        );
    }

    @Bean
    @ConditionalOnSingleCandidate(AuthorizationProviderPort.class)
    @ConditionalOnMissingBean
    public GovernedExportAndAiToolAuthorizationSeam governedExportAndAiToolAuthorizationSeam(
            RuntimeDecisionPointRegistry registry,
            AuthorizationProviderPort providerPort,
            FieldUseQueryGuard fieldUseQueryGuard,
            DetachedDtoMaskingProcessor maskingProcessor,
            ObligationBarrierCoordinator obligationCoordinator,
            GovernedCollectionExportGuard exportGuard,
            SanitizedAuthorizationTelemetryPublisher telemetryPublisher
    ) {
        return new GovernedExportAndAiToolAuthorizationSeam(
                registry,
                providerPort,
                fieldUseQueryGuard,
                maskingProcessor,
                obligationCoordinator,
                exportGuard,
                telemetryPublisher
        );
    }
}
