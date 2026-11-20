package org.praxisplatform.authz.catalog;

import java.util.Set;
import org.praxisplatform.config.service.DomainRuleGovernancePrincipal;
import org.springframework.security.core.Authentication;

/** Host-owned PAP service delegations for the authenticated identity, tenant and environment. */
@FunctionalInterface
public interface PapCatalogServiceScopeResolver {
    Set<String> allowedServiceKeys(DomainRuleGovernancePrincipal principal, Authentication authentication);
}
