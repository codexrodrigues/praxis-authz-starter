package org.praxisplatform.authz.autoconfigure;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.praxisplatform.authz.catalog.PapCatalogServiceScopeResolver;
import org.praxisplatform.authz.controlplane.GovernedPapAdminOperationsService;
import org.praxisplatform.authz.controlplane.release.AccessPolicyReleaseController;
import org.praxisplatform.authz.controlplane.release.AccessPolicyReleaseService;
import org.praxisplatform.authz.controlplane.release.AccessPolicyReleaseSettings;
import org.praxisplatform.authz.controlplane.release.AccessPolicyVerificationCorpus;
import org.praxisplatform.authz.host.metadata.AuthzHostPolicyBootstrapBuilder.AuthzHostPolicyBootstrapBundle;
import org.praxisplatform.authz.opa.client.HttpClientOpaTransport;
import org.praxisplatform.authz.opa.compiler.RegoV1PolicyCompiler;
import org.praxisplatform.authz.opa.governance.GovernedOpaReleaseCoordinator;
import org.praxisplatform.authz.seams.RuntimeDecisionPointRegistry;
import org.praxisplatform.config.repository.DomainRuleDefinitionApprovalRepository;
import org.praxisplatform.config.repository.DomainRuleDefinitionRepository;
import org.praxisplatform.config.service.DomainRuleDefinitionFingerprint;
import org.praxisplatform.config.service.DomainRuleGovernancePrincipalResolver;
import org.praxisplatform.config.tx.ConfigTransactionManagerNames;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

@AutoConfiguration(after = {PraxisAuthzAutoConfiguration.class, PraxisAuthzPapCatalogAutoConfiguration.class},
        afterName = "org.praxisplatform.config.autoconfig.DomainRuleSnapshotAutoConfiguration")
@ConditionalOnClass(name = {"org.springframework.security.core.Authentication",
        "org.praxisplatform.config.service.DomainRuleGovernancePrincipalResolver"})
@ConditionalOnProperty(prefix = "praxis.authz.access-release", name = "enabled", havingValue = "true")
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@EnableConfigurationProperties(AccessPolicyReleaseSettings.class)
public class PraxisAuthzAccessReleaseAutoConfiguration {
    @Bean
    AccessPolicyReleaseService accessPolicyReleaseService(
            AccessPolicyReleaseSettings settings,
            PraxisAuthzProperties properties,
            @Qualifier("configNamedParameterJdbcTemplate") NamedParameterJdbcTemplate jdbc,
            @Qualifier(ConfigTransactionManagerNames.CONFIG) PlatformTransactionManager manager,
            DomainRuleDefinitionRepository definitions,
            DomainRuleDefinitionApprovalRepository approvals,
            DomainRuleDefinitionFingerprint fingerprint,
            ObjectMapper json,
            GovernedOpaReleaseCoordinator coordinator,
            RegoV1PolicyCompiler compiler,
            HttpClientOpaTransport transport,
            RuntimeDecisionPointRegistry registry,
            GovernedPapAdminOperationsService pap,
            AccessPolicyVerificationCorpus corpus,
            AuthzHostPolicyBootstrapBundle bootstrap) {
        return new AccessPolicyReleaseService(settings, properties.getOpa().getInstanceId(), jdbc.getJdbcOperations(),
                new TransactionTemplate(manager), definitions, approvals, fingerprint, json, coordinator, compiler,
                transport, registry, pap, corpus, bootstrap);
    }

    @Bean
    AccessPolicyReleaseController accessPolicyReleaseController(AccessPolicyReleaseService releases,
            DomainRuleGovernancePrincipalResolver principals, PapCatalogServiceScopeResolver scopes,
            AccessPolicyReleaseSettings settings) {
        return new AccessPolicyReleaseController(releases, principals, scopes, settings);
    }
}
