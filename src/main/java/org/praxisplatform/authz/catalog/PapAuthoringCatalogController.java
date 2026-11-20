package org.praxisplatform.authz.catalog;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import org.praxisplatform.authz.autoconfigure.PraxisAuthzProperties;
import org.praxisplatform.authz.controlplane.GovernedPapAdminOperationsService;
import org.praxisplatform.authz.seams.RuntimeDecisionPointRegistry;
import org.praxisplatform.config.service.DomainRuleGovernancePrincipalResolver;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

@RestController
@ConditionalOnBean({PapCatalogServiceScopeResolver.class, GovernedPapAdminOperationsService.class,
        RuntimeDecisionPointRegistry.class, DomainRuleGovernancePrincipalResolver.class})
@ConditionalOnProperty(prefix = "praxis.authz.admin-endpoints", name = "enabled", havingValue = "true")
public final class PapAuthoringCatalogController {
    private final AuthenticationTrustResolverImpl trust = new AuthenticationTrustResolverImpl();
    private final PraxisAuthzProperties properties;
    private final GovernedPapAdminOperationsService admin;
    private final RuntimeDecisionPointRegistry registry;
    private final DomainRuleGovernancePrincipalResolver principals;
    private final PapCatalogServiceScopeResolver scopes;

    public PapAuthoringCatalogController(PraxisAuthzProperties properties, GovernedPapAdminOperationsService admin,
            RuntimeDecisionPointRegistry registry, DomainRuleGovernancePrincipalResolver principals,
            PapCatalogServiceScopeResolver scopes) {
        this.properties = properties;
        this.admin = admin;
        this.registry = registry;
        this.principals = principals;
        this.scopes = scopes;
    }

    @GetMapping("/api/praxis/config/domain-rules/authorization/catalog")
    public ResponseEntity<PapAuthoringCatalog> catalog(HttpServletRequest request) {
        if (!(request.getUserPrincipal() instanceof Authentication auth)
                || !trust.isAuthenticated(auth)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
        }
        Set<String> authorities = auth.getAuthorities().stream().map(GrantedAuthority::getAuthority)
                .filter(Objects::nonNull).collect(Collectors.toUnmodifiableSet());
        if (!authorities.contains(properties.getDiscovery().getRequiredCatalogAuthority())) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN);
        }
        var principal = principals.resolve(request, null, null, "RULE_DEFINITION_READER");
        if (!auth.getName().equals(principal.actorRef())) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN);
        }
        try {
            var allowed = scopes.allowedServiceKeys(principal, auth);
            if (allowed == null || allowed.isEmpty()) {
                throw new ResponseStatusException(HttpStatus.FORBIDDEN);
            }
            var services = allowed.stream().sorted().map(service -> {
                var view = admin.querySemanticCatalog(new PapCatalogQueryRequest(principal.actorRef(), authorities, allowed, service));
                return PapAuthoringCatalog.project(view, registry);
            }).toList();
            return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(new PapAuthoringCatalog(services));
        } catch (SecurityException ex) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN);
        } catch (IllegalStateException ex) {
            throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE);
        }
    }
}
