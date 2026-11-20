package org.praxisplatform.authz.autoconfigure;

import org.praxisplatform.authz.catalog.PapAuthoringCatalogController;
import org.praxisplatform.authz.catalog.PapCatalogServiceScopeResolver;
import org.praxisplatform.authz.controlplane.GovernedPapAdminOperationsService;
import org.praxisplatform.authz.seams.RuntimeDecisionPointRegistry;
import org.praxisplatform.config.service.DomainRuleGovernancePrincipalResolver;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.annotation.Bean;

@AutoConfiguration(after = PraxisAuthzAutoConfiguration.class,
        afterName = "org.praxisplatform.config.autoconfig.DomainRuleSnapshotAutoConfiguration")
@ConditionalOnClass(name = {"org.springframework.security.core.Authentication",
        "org.springframework.web.servlet.DispatcherServlet",
        "org.praxisplatform.config.service.DomainRuleGovernancePrincipalResolver"})
@ConditionalOnProperty(prefix = "praxis.authz.admin-endpoints", name = "enabled", havingValue = "true")
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
public class PraxisAuthzPapCatalogAutoConfiguration {
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnBean({GovernedPapAdminOperationsService.class, RuntimeDecisionPointRegistry.class,
            DomainRuleGovernancePrincipalResolver.class, PapCatalogServiceScopeResolver.class})
    PapAuthoringCatalogController papAuthoringCatalogController(PraxisAuthzProperties properties,
            GovernedPapAdminOperationsService admin, RuntimeDecisionPointRegistry registry,
            DomainRuleGovernancePrincipalResolver principals, PapCatalogServiceScopeResolver scopes) {
        return new PapAuthoringCatalogController(properties, admin, registry, principals, scopes);
    }
}
