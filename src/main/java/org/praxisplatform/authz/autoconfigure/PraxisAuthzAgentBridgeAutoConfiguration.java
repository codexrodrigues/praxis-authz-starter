package org.praxisplatform.authz.autoconfigure;

import java.util.Map;
import org.praxisplatform.authz.agent.AuthzAgentAuthorizationBridge;
import org.praxisplatform.authz.agent.AuthzAgentThreadContextPropagator;
import org.praxisplatform.authz.host.metadata.AuthzResourceOperationAvailabilityProvider;
import org.praxisplatform.authz.host.metadata.MetadataDtoGovernanceIntrospector;
import org.praxisplatform.authz.host.metadata.ThreadLocalAuthzCallerContextProvider;
import org.praxisplatform.authz.seams.GovernedExportAndAiToolAuthorizationSeam;
import org.praxisplatform.authz.seams.RuntimeDecisionPointRegistry;
import org.praxisplatform.config.ai.agent.bridge.DefaultMetadataGovernanceAgentAuthorizationBridge;
import org.praxisplatform.config.ai.agent.spi.AgentAuthorizationBridge;
import org.praxisplatform.config.ai.agent.spi.AgentThreadContextPropagator;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

/**
 * Conecta o assistente operacional de {@code praxis-config-starter} ao motor OPA e ao caller
 * context de {@code praxis-authz-starter} quando ambos estao presentes e habilitados.
 */
@AutoConfiguration(
        after = PraxisAuthzHostBridgeAutoConfiguration.class,
        beforeName = "org.praxisplatform.config.autoconfig.OperationalAgentAutoConfiguration")
@ConditionalOnClass({AgentAuthorizationBridge.class, DefaultMetadataGovernanceAgentAuthorizationBridge.class})
@ConditionalOnProperty(prefix = "praxis.authz", name = "enabled", havingValue = "true", matchIfMissing = true)
public class PraxisAuthzAgentBridgeAutoConfiguration {

    @Bean
    @ConditionalOnBean(ThreadLocalAuthzCallerContextProvider.class)
    @ConditionalOnMissingBean(AuthzAgentThreadContextPropagator.class)
    public AgentThreadContextPropagator authzAgentThreadContextPropagator(
            ThreadLocalAuthzCallerContextProvider callerContextProvider) {
        return new AuthzAgentThreadContextPropagator(callerContextProvider);
    }

    @Bean
    @Primary
    @ConditionalOnMissingBean(AuthzAgentAuthorizationBridge.class)
    public AuthzAgentAuthorizationBridge authzAgentAuthorizationBridge(
            ObjectProvider<DefaultMetadataGovernanceAgentAuthorizationBridge> metadataFallbackProvider,
            ObjectProvider<GovernedExportAndAiToolAuthorizationSeam> aiToolSeamProvider,
            ObjectProvider<RuntimeDecisionPointRegistry> decisionPointRegistryProvider,
            ObjectProvider<ThreadLocalAuthzCallerContextProvider> callerContextProvider,
            ObjectProvider<MetadataDtoGovernanceIntrospector> dtoIntrospectorProvider,
            ObjectProvider<AuthzResourceOperationAvailabilityProvider> availabilityProvider) {
        return new AuthzAgentAuthorizationBridge(
                metadataFallbackProvider.getIfAvailable(DefaultMetadataGovernanceAgentAuthorizationBridge::new),
                aiToolSeamProvider.getIfAvailable(),
                decisionPointRegistryProvider.getIfAvailable(),
                callerContextProvider.getIfAvailable(),
                dtoIntrospectorProvider.getIfAvailable(),
                availabilityProvider.getIfAvailable(),
                Map.of());
    }
}
