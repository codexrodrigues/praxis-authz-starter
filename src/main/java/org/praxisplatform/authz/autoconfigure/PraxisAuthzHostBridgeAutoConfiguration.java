package org.praxisplatform.authz.autoconfigure;

import org.praxisplatform.authz.controlplane.ConfigMaterializationToOpaReconciler;
import org.praxisplatform.authz.catalog.SemanticDecisionPointCatalogService;
import org.praxisplatform.authz.compatibility.HostRuntimePolicyCoordinates;
import org.praxisplatform.authz.enforcement.masking.DetachedDtoMaskingProcessor;
import org.praxisplatform.authz.host.config.OperationalPolicyResolutionBridge;
import org.praxisplatform.authz.host.metadata.AbstractAuthzGovernedReadOnlyResourceService;
import org.praxisplatform.authz.host.metadata.AbstractAuthzGovernedResourceService;
import org.praxisplatform.authz.host.metadata.AuthzCallerContext;
import org.praxisplatform.authz.host.metadata.AuthzCallerContextFilter;
import org.praxisplatform.authz.host.metadata.AuthzCallerContextHttpResolver;
import org.praxisplatform.authz.host.metadata.AuthzCallerContextProvider;
import org.praxisplatform.authz.host.metadata.AuthzGovernedResourceServiceSupport;
import org.praxisplatform.authz.host.metadata.AuthzHostPolicyBootstrapBuilder.AuthzHostPolicyBootstrapBundle;
import org.praxisplatform.authz.host.metadata.AuthzHostReadinessReviewer;
import org.praxisplatform.authz.host.metadata.AuthzResourceOperationAvailabilityProvider;
import org.praxisplatform.authz.host.metadata.MetadataDtoGovernanceIntrospector;
import org.praxisplatform.authz.host.metadata.ThreadLocalAuthzCallerContextProvider;
import org.praxisplatform.authz.seams.MetadataResourceAuthorizationSeam;
import org.praxisplatform.authz.seams.RuntimeDecisionPointRegistry;
import org.praxisplatform.uischema.capability.ResourceServiceDelegatingStateSnapshotProvider;
import org.praxisplatform.uischema.capability.ResourceStateSnapshotProvider;
import org.praxisplatform.uischema.command.GovernedResourceCommandExecutor;
import org.praxisplatform.uischema.command.ResourceCommandEvidenceSanitizer;
import org.praxisplatform.uischema.command.ResourceCommandExecutionProvider;
import org.praxisplatform.uischema.customfields.CustomFieldDefinitionProvider;
import org.praxisplatform.uischema.customfields.ResourceTenantContextResolver;
import org.praxisplatform.uischema.determination.ReactiveDeterminationDefinition;
import org.praxisplatform.uischema.determination.ReactiveDeterminationDefinitionProvider;
import org.praxisplatform.uischema.exporting.CollectionExportExecutor;
import org.praxisplatform.uischema.options.service.OptionSourceQueryExecutor;
import org.praxisplatform.uischema.service.base.BaseResourceQueryService;
import org.praxisplatform.uischema.stats.StatsProperties;
import org.praxisplatform.uischema.stats.service.StatsQueryExecutor;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Spring Boot Auto-Configuration that activates direct host bridges for
 * {@code praxis-metadata-starter} ({@link AuthzGovernedResourceServiceSupport},
 * {@link AuthzResourceOperationAvailabilityProvider}, {@link MetadataDtoGovernanceIntrospector},
 * {@link AuthzCallerContextFilter}) and {@code praxis-config-starter}
 * ({@link OperationalPolicyResolutionBridge}) whenever those starters are present on the classpath
 * ({@code Fases P10.1..P10.9}).
 *
 * <p>Ordered before {@code OpenApiUiSchemaAutoConfiguration} so that
 * {@link AuthzResourceOperationAvailabilityProvider} takes precedence over
 * {@code NoOpResourceOperationAvailabilityProvider} when {@code @ConditionalOnMissingBean}
 * is evaluated ({@code P10.4-R01}).</p>
 */
@AutoConfiguration(
        after = PraxisAuthzAutoConfiguration.class,
        beforeName = "org.praxisplatform.uischema.configuration.OpenApiUiSchemaAutoConfiguration"
)
@EnableConfigurationProperties(PraxisAuthzProperties.class)
@ConditionalOnProperty(prefix = "praxis.authz", name = "enabled", havingValue = "true", matchIfMissing = true)
public class PraxisAuthzHostBridgeAutoConfiguration {

    /** Creates a new {@link PraxisAuthzHostBridgeAutoConfiguration} instance. */
    public PraxisAuthzHostBridgeAutoConfiguration() {
    }

    /**
     * Registers {@link AuthzGovernedResourceServiceSupport},
     * {@link AuthzResourceOperationAvailabilityProvider}, {@link ResourceStateSnapshotProvider},
     * and the {@link SmartInitializingSingleton} auto-wiring for governed resource services when
     * {@code praxis-metadata-starter} is present on the classpath.
     */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = "org.praxisplatform.uischema.service.base.ResourceFilterAccessScope")
    static class MetadataStarterBridgeConfiguration {

        @Bean
        @ConditionalOnMissingBean
        public MetadataDtoGovernanceIntrospector metadataDtoGovernanceIntrospector() {
            return new MetadataDtoGovernanceIntrospector();
        }

        @Bean
        @ConditionalOnMissingBean
        public AuthzHostReadinessReviewer authzHostReadinessReviewer(
                MetadataDtoGovernanceIntrospector dtoIntrospector,
                ObjectProvider<RuntimeDecisionPointRegistry> decisionPointRegistryProvider,
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
            return new AuthzHostReadinessReviewer(
                    dtoIntrospector,
                    decisionPointRegistryProvider.getIfAvailable(),
                    coordinates
            );
        }

        @Bean
        @ConditionalOnMissingBean(AuthzCallerContextProvider.class)
        public ThreadLocalAuthzCallerContextProvider authzCallerContextProvider() {
            return new ThreadLocalAuthzCallerContextProvider();
        }

        @Bean
        @ConditionalOnMissingBean(ResourceTenantContextResolver.class)
        public ResourceTenantContextResolver resourceTenantContextResolver(
                AuthzCallerContextProvider callerContextProvider
        ) {
            return () -> {
                if (callerContextProvider instanceof ThreadLocalAuthzCallerContextProvider threadLocalProvider) {
                    return threadLocalProvider.currentCallerContextOptional()
                            .map(AuthzCallerContext::tenantId);
                }
                try {
                    return Optional.of(callerContextProvider.currentCallerContext().tenantId());
                } catch (SecurityException ex) {
                    return Optional.empty();
                }
            };
        }

        @Bean
        @ConditionalOnMissingBean(ResourceStateSnapshotProvider.class)
        public ResourceStateSnapshotProvider resourceStateSnapshotProvider(
                ObjectProvider<BaseResourceQueryService<?, ?, ?>> services
        ) {
            return new ResourceServiceDelegatingStateSnapshotProvider(services);
        }

        @Bean
        @ConditionalOnMissingBean
        @ConditionalOnBean({MetadataResourceAuthorizationSeam.class, DetachedDtoMaskingProcessor.class})
        public AuthzGovernedResourceServiceSupport authzGovernedResourceServiceSupport(
                MetadataResourceAuthorizationSeam authorizationSeam,
                DetachedDtoMaskingProcessor maskingProcessor,
                MetadataDtoGovernanceIntrospector dtoIntrospector
        ) {
            return new AuthzGovernedResourceServiceSupport(authorizationSeam, maskingProcessor, dtoIntrospector);
        }

        @Bean
        @Order(300)
        @ConditionalOnMissingBean(AuthzResourceOperationAvailabilityProvider.class)
        @ConditionalOnBean(MetadataResourceAuthorizationSeam.class)
        public AuthzResourceOperationAvailabilityProvider authzResourceOperationAvailabilityProvider(
                MetadataResourceAuthorizationSeam authorizationSeam,
                ObjectProvider<ResourceStateSnapshotProvider> snapshotProvider
        ) {
            return new AuthzResourceOperationAvailabilityProvider(
                    authorizationSeam,
                    snapshotProvider.getIfAvailable()
            );
        }

        @Bean
        @ConditionalOnMissingBean(GovernedResourceCommandExecutor.class)
        @ConditionalOnBean({
                AuthzGovernedResourceServiceSupport.class,
                ResourceCommandExecutionProvider.class
        })
        public GovernedResourceCommandExecutor governedResourceCommandExecutor(
                AuthzGovernedResourceServiceSupport serviceSupport,
                ResourceCommandExecutionProvider rawProvider,
                ObjectProvider<AuthzResourceOperationAvailabilityProvider> availabilityProvider
        ) {
            return new GovernedResourceCommandExecutor(
                    serviceSupport.wrapCommandExecutionProvider(rawProvider),
                    availabilityProvider.getIfAvailable(),
                    ResourceCommandEvidenceSanitizer.defaults()
            );
        }

        @Bean
        @ConditionalOnMissingBean(org.praxisplatform.authz.host.metadata.HardScopeResolver.class)
        public org.praxisplatform.authz.host.metadata.HardScopeResolver hardScopeResolver() {
            return new org.praxisplatform.authz.host.metadata.MultiOrganizationHardScopeResolver();
        }

        @Bean
        @ConditionalOnClass(org.praxisplatform.uischema.capability.ResourceOperationAvailabilityRule.class)
        @ConditionalOnMissingBean(org.praxisplatform.authz.host.metadata.AuthzResourceOperationAvailabilityRule.class)
        @ConditionalOnBean(AuthzResourceOperationAvailabilityProvider.class)
        public org.praxisplatform.authz.host.metadata.AuthzResourceOperationAvailabilityRule authzResourceOperationAvailabilityRule(
                AuthzResourceOperationAvailabilityProvider availabilityProvider
        ) {
            return new org.praxisplatform.authz.host.metadata.AuthzResourceOperationAvailabilityRule(availabilityProvider);
        }

        @Bean
        @org.springframework.context.annotation.Primary
        @ConditionalOnClass(org.praxisplatform.uischema.capability.CompositeResourceOperationAvailabilityEvaluator.class)
        @ConditionalOnBean(org.praxisplatform.uischema.capability.ResourceOperationAvailabilityRule.class)
        @ConditionalOnMissingBean(
                value = org.praxisplatform.uischema.capability.ResourceOperationAvailabilityProvider.class,
                ignored = AuthzResourceOperationAvailabilityProvider.class
        )
        public org.praxisplatform.uischema.capability.CompositeResourceOperationAvailabilityEvaluator compositeResourceOperationAvailabilityProvider(
                ObjectProvider<org.praxisplatform.uischema.capability.ResourceOperationAvailabilityRule> rules
        ) {
            return new org.praxisplatform.uischema.capability.CompositeResourceOperationAvailabilityEvaluator(
                    rules.orderedStream().toList()
            );
        }

        @Bean
        @ConditionalOnClass(org.praxisplatform.uischema.governance.ResourceGovernanceInterceptor.class)
        @ConditionalOnMissingBean(org.praxisplatform.authz.host.metadata.AuthzResourceGovernanceInterceptor.class)
        @ConditionalOnBean({
                AuthzGovernedResourceServiceSupport.class,
                org.praxisplatform.authz.host.metadata.AuthzCallerContextProvider.class
        })
        public org.praxisplatform.authz.host.metadata.AuthzResourceGovernanceInterceptor authzResourceGovernanceInterceptor(
                AuthzGovernedResourceServiceSupport serviceSupport,
                org.praxisplatform.authz.host.metadata.AuthzCallerContextProvider callerContextProvider,
                ObjectProvider<org.praxisplatform.authz.seams.RuntimeDecisionPointRegistry> decisionPointRegistry,
                ObjectProvider<AuthzHostPolicyBootstrapBundle> bootstrapBundleProvider,
                ObjectProvider<org.praxisplatform.authz.host.metadata.AuthzResourceGovernanceSpec<?>> registeredSpecs,
                org.springframework.context.ApplicationContext applicationContext,
                PraxisAuthzProperties properties
        ) {
            java.util.List<org.praxisplatform.authz.host.metadata.AuthzResourceGovernanceSpec<?>> effectiveSpecs =
                    new java.util.ArrayList<>();
            if (bootstrapBundleProvider != null) {
                bootstrapBundleProvider.orderedStream()
                        .flatMap(bundle -> bundle.resourceSpecs().stream())
                        .forEach(effectiveSpecs::add);
            }
            if (registeredSpecs != null) {
                registeredSpecs.orderedStream().forEach(effectiveSpecs::add);
            }
            return new org.praxisplatform.authz.host.metadata.AuthzResourceGovernanceInterceptor(
                    serviceSupport,
                    callerContextProvider,
                    decisionPointRegistry.getIfAvailable(),
                    effectiveSpecs,
                    applicationContext,
                    properties.getInterceptor().isFailClosedOnUnconfiguredServices()
            );
        }

        @Bean
        @ConditionalOnClass({
                org.praxisplatform.uischema.governance.ResourceGovernanceInterceptor.class,
                org.praxisplatform.uischema.service.base.BaseResourceQueryService.class
        })
        public org.springframework.beans.factory.SmartInitializingSingleton authzInterceptorServicesInitializer(
                ObjectProvider<org.praxisplatform.authz.host.metadata.AuthzResourceGovernanceInterceptor> interceptorProvider,
                ObjectProvider<org.praxisplatform.uischema.service.base.BaseResourceQueryService<?, ?, ?>> queryServicesProvider,
                ObjectProvider<AuthzResourceOperationAvailabilityProvider> availabilityProvider,
                ObjectProvider<org.praxisplatform.authz.seams.RuntimeDecisionPointRegistry> registryProvider,
                ObjectProvider<org.praxisplatform.authz.catalog.SemanticDecisionPointCatalogService> catalogServiceProvider,
                ObjectProvider<org.praxisplatform.authz.host.metadata.AuthzHostReadinessReviewer> readinessReviewerProvider,
                ObjectProvider<PraxisAuthzProperties> propertiesProvider
        ) {
            return () -> {
                var interceptor = interceptorProvider.getIfAvailable();
                if (interceptor == null) {
                    return;
                }
                var avail = availabilityProvider.getIfAvailable();
                var registry = registryProvider.getIfAvailable();
                var catalog = catalogServiceProvider.getIfAvailable();
                java.util.List<org.praxisplatform.uischema.service.base.BaseResourceQueryService<?, ?, ?>> governedPlainServices =
                        new java.util.ArrayList<>();
                java.util.Map<String, org.praxisplatform.authz.host.metadata.AuthzResourceGovernanceSpec<?>> resolvedSpecs =
                        new java.util.LinkedHashMap<>();

                for (var svc : queryServicesProvider.orderedStream().toList()) {
                    var spec = interceptor.resolvedSpecFor(svc);
                    if (spec != null) {
                        governedPlainServices.add(svc);
                        resolvedSpecs.put(spec.resourceKey(), spec);
                        interceptor.registerAvailabilityBindingIfSupported(svc, avail);
                        interceptor.synchronizeCatalogAndRegistryIfSupported(svc, registry, catalog);
                    }
                }
                var props = propertiesProvider.getIfAvailable();
                var reviewer = readinessReviewerProvider.getIfAvailable();
                if (props != null && props.getReadinessGate().isVerifyOnStartup()
                        && reviewer != null && !governedPlainServices.isEmpty()) {
                    var report = reviewer.reviewInterceptorBoundServices(governedPlainServices, resolvedSpecs);
                    if (props.getReadinessGate().isFailOnWarning()) {
                        report.assertZeroIssues();
                    } else {
                        report.assertReady();
                    }
                }
            };
        }

        @Bean
        @ConditionalOnMissingBean
        @ConditionalOnClass(name = "org.springframework.web.filter.OncePerRequestFilter")
        @ConditionalOnBean(AuthzCallerContextHttpResolver.class)
        public AuthzCallerContextFilter authzCallerContextFilter(
                AuthzCallerContextHttpResolver resolver,
                ThreadLocalAuthzCallerContextProvider callerContextProvider,
                org.springframework.beans.factory.ObjectProvider<org.praxisplatform.authz.host.metadata.PraxisAuthzExceptionHandler> exceptionHandlerProvider,
                org.springframework.beans.factory.ObjectProvider<com.fasterxml.jackson.databind.ObjectMapper> objectMapperProvider
        ) {
            return new AuthzCallerContextFilter(
                    resolver,
                    callerContextProvider,
                    exceptionHandlerProvider.getIfAvailable(),
                    objectMapperProvider.getIfAvailable()
            );
        }

        @Bean
        @ConditionalOnMissingBean
        @ConditionalOnClass(name = {
                "org.springframework.web.bind.annotation.RestControllerAdvice",
                "org.praxisplatform.uischema.rest.response.RestApiResponse"
        })
        public org.praxisplatform.authz.host.metadata.PraxisAuthzExceptionHandler praxisAuthzExceptionHandler() {
            return new org.praxisplatform.authz.host.metadata.PraxisAuthzExceptionHandler();
        }

        @Bean
        @ConditionalOnMissingBean(name = "authzGovernedServicesReactiveDeterminationProvider")
        public ReactiveDeterminationDefinitionProvider authzGovernedServicesReactiveDeterminationProvider(
                ObjectProvider<AbstractAuthzGovernedReadOnlyResourceService<?, ?, ?, ?>> readOnlyServices,
                ObjectProvider<AbstractAuthzGovernedResourceService<?, ?, ?, ?, ?, ?>> mutableServices
        ) {
            return () -> {
                List<ReactiveDeterminationDefinition> definitions = new ArrayList<>();
                readOnlyServices.orderedStream().forEach(service ->
                        definitions.addAll(service.getGovernedReactiveDeterminationProvider().definitions())
                );
                mutableServices.orderedStream().forEach(service ->
                        definitions.addAll(service.getGovernedReactiveDeterminationProvider().definitions())
                );
                return List.copyOf(definitions);
            };
        }

        @Bean
        public SmartInitializingSingleton authzGovernedResourceServiceInfrastructureInitializer(
                ObjectProvider<AbstractAuthzGovernedReadOnlyResourceService<?, ?, ?, ?>> readOnlyServices,
                ObjectProvider<AbstractAuthzGovernedResourceService<?, ?, ?, ?, ?, ?>> mutableServices,
                ObjectProvider<CollectionExportExecutor> exportExecutor,
                ObjectProvider<OptionSourceQueryExecutor> optionSourceExecutor,
                ObjectProvider<StatsQueryExecutor> statsExecutor,
                ObjectProvider<StatsProperties> statsProperties,
                ObjectProvider<AuthzResourceOperationAvailabilityProvider> availabilityProvider,
                ObjectProvider<CustomFieldDefinitionProvider> customFieldDefinitionsProvider,
                ObjectProvider<ResourceTenantContextResolver> tenantResolverProvider,
                ObjectProvider<RuntimeDecisionPointRegistry> decisionPointRegistryProvider,
                ObjectProvider<SemanticDecisionPointCatalogService> catalogServiceProvider,
                ObjectProvider<AuthzHostReadinessReviewer> readinessReviewerProvider,
                ObjectProvider<PraxisAuthzProperties> authzPropertiesProvider
        ) {
            return () -> {
                CollectionExportExecutor export = exportExecutor.getIfAvailable();
                OptionSourceQueryExecutor optionSource = optionSourceExecutor.getIfAvailable();
                StatsQueryExecutor stats = statsExecutor.getIfAvailable();
                StatsProperties props = statsProperties.getIfAvailable();
                AuthzResourceOperationAvailabilityProvider availability = availabilityProvider.getIfAvailable();
                CustomFieldDefinitionProvider customFieldDefs = customFieldDefinitionsProvider.getIfAvailable();
                ResourceTenantContextResolver tenantResolver = tenantResolverProvider.getIfAvailable();
                RuntimeDecisionPointRegistry registry = decisionPointRegistryProvider.getIfAvailable();
                SemanticDecisionPointCatalogService catalogService = catalogServiceProvider.getIfAvailable();
                List<AbstractAuthzGovernedReadOnlyResourceService<?, ?, ?, ?>> roList =
                        readOnlyServices.orderedStream().toList();
                List<AbstractAuthzGovernedResourceService<?, ?, ?, ?, ?, ?>> mutList =
                        mutableServices.orderedStream().toList();
                roList.forEach(service -> {
                    service.configureGovernedQueryInfrastructure(export, optionSource, stats, props);
                    service.registerAvailabilityBindingIfSupported(availability);
                    service.synchronizeCatalogAndRegistryIfSupported(registry, catalogService);
                    if (customFieldDefs != null && tenantResolver != null) {
                        service.configureCustomFieldFiltering(customFieldDefs, tenantResolver);
                    }
                });
                mutList.forEach(service -> {
                    service.configureGovernedQueryInfrastructure(export, optionSource, stats, props);
                    service.registerAvailabilityBindingIfSupported(availability);
                    service.synchronizeCatalogAndRegistryIfSupported(registry, catalogService);
                    if (customFieldDefs != null && tenantResolver != null) {
                        service.configureCustomFieldFiltering(customFieldDefs, tenantResolver);
                    }
                });
                PraxisAuthzProperties authzProps = authzPropertiesProvider.getIfAvailable();
                AuthzHostReadinessReviewer reviewer = readinessReviewerProvider.getIfAvailable();
                if (authzProps != null && authzProps.getReadinessGate().isVerifyOnStartup() && reviewer != null) {
                    AuthzHostReadinessReviewer.ReadinessReport report = reviewer.reviewAll(roList, mutList);
                    if (authzProps.getReadinessGate().isFailOnWarning()) {
                        report.assertZeroIssues();
                    } else {
                        report.assertReady();
                    }
                }
            };
        }
    }

    /**
     * Registers {@link OperationalPolicyResolutionBridge} when {@code praxis-config-starter}
     * is present on the classpath.
     */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = "org.praxisplatform.config.service.OperationalPolicyResolution")
    static class ConfigStarterBridgeConfiguration {

        @Bean
        @ConditionalOnMissingBean
        @ConditionalOnBean(ConfigMaterializationToOpaReconciler.class)
        public OperationalPolicyResolutionBridge operationalPolicyResolutionBridge(
                ConfigMaterializationToOpaReconciler reconciler
        ) {
            return new OperationalPolicyResolutionBridge(reconciler);
        }
    }
}
