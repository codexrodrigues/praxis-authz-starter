package org.praxisplatform.authz.controlplane.release;

import static org.praxisplatform.authz.opa.governance.GovernedOpaReleaseCoordinator.REQUIRED_ADMIN_AUTHORITY;

import jakarta.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Set;
import java.util.UUID;
import java.util.Objects;
import java.util.stream.Collectors;
import org.praxisplatform.authz.catalog.PapCatalogServiceScopeResolver;
import org.praxisplatform.authz.controlplane.release.AccessPolicyReleaseService.View;
import org.praxisplatform.config.service.DomainRuleGovernancePrincipal;
import org.praxisplatform.config.service.DomainRuleGovernancePrincipalResolver;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.server.ResponseStatusException;

@RestController
@ConditionalOnProperty(prefix = "praxis.authz.access-release", name = "enabled", havingValue = "true")
public final class AccessPolicyReleaseController {
    public static final String RELEASES = "/api/praxis/config/domain-rules/authorization/releases";
    public static final String OPA_BUNDLE = "/api/praxis/authz/opa/bundle";

    public record PublishRequest(UUID definitionId) {}
    private record Operator(DomainRuleGovernancePrincipal principal, Set<String> services, Set<String> authorities) {}

    private final AccessPolicyReleaseService releases;
    private final DomainRuleGovernancePrincipalResolver principals;
    private final PapCatalogServiceScopeResolver scopes;
    private final byte[] bearer;
    private final AuthenticationTrustResolverImpl trust = new AuthenticationTrustResolverImpl();

    public AccessPolicyReleaseController(AccessPolicyReleaseService releases,
                                         DomainRuleGovernancePrincipalResolver principals,
                                         PapCatalogServiceScopeResolver scopes,
                                         AccessPolicyReleaseSettings settings) {
        this.releases = releases;
        this.principals = principals;
        this.scopes = scopes;
        this.bearer = ("Bearer " + settings.bundleToken()).getBytes(StandardCharsets.UTF_8);
    }

    @PostMapping(RELEASES)
    public ResponseEntity<View> publish(HttpServletRequest request, @RequestBody PublishRequest body) {
        var operator = operator(request);
        if (body.definitionId() == null) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "definitionId is required.");
        }
        return response(releases.publish(body.definitionId(), operator.principal(), operator.services(), operator.authorities()));
    }

    @GetMapping(RELEASES + "/{releaseId}")
    public ResponseEntity<View> read(HttpServletRequest request, @PathVariable UUID releaseId) {
        var operator = operator(request);
        return response(releases.read(releaseId, operator.principal(), operator.services()));
    }

    @PostMapping(RELEASES + "/{releaseId}/activate")
    public ResponseEntity<View> activate(HttpServletRequest request, @PathVariable UUID releaseId) {
        return transition(request, releaseId, false);
    }

    @PostMapping(RELEASES + "/{releaseId}/rollback")
    public ResponseEntity<View> rollback(HttpServletRequest request, @PathVariable UUID releaseId) {
        return transition(request, releaseId, true);
    }

    @GetMapping(OPA_BUNDLE)
    public ResponseEntity<byte[]> bundle(WebRequest request,
                                        @RequestHeader(name = HttpHeaders.AUTHORIZATION, required = false) String authorization) {
        if (authorization == null || !MessageDigest.isEqual(bearer, authorization.getBytes(StandardCharsets.UTF_8))) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
        }
        var bundle = releases.bundle();
        if (request.checkNotModified(bundle.etag())) {
            return ResponseEntity.status(HttpStatus.NOT_MODIFIED)
                    .cacheControl(CacheControl.noCache().cachePrivate()).eTag(bundle.etag()).build();
        }
        return ResponseEntity.ok().cacheControl(CacheControl.noCache().cachePrivate()).eTag(bundle.etag())
                .contentType(MediaType.APPLICATION_OCTET_STREAM).body(bundle.archive());
    }

    private ResponseEntity<View> transition(HttpServletRequest request, UUID releaseId, boolean restoring) {
        var operator = operator(request);
        return response(releases.request(releaseId, restoring, operator.principal(), operator.services(), operator.authorities()));
    }

    private Operator operator(HttpServletRequest request) {
        if (!(request.getUserPrincipal() instanceof Authentication auth) || !trust.isAuthenticated(auth)) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
        }
        if (!request.isUserInRole(REQUIRED_ADMIN_AUTHORITY)) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN);
        }
        var principal = principals.resolve(request, null, null, REQUIRED_ADMIN_AUTHORITY);
        if (!auth.getName().equals(principal.actorRef())) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN);
        }
        var allowed = scopes.allowedServiceKeys(principal, auth);
        if (allowed == null || allowed.isEmpty()) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN);
        }
        return new Operator(principal, Set.copyOf(allowed), auth.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority).filter(Objects::nonNull).collect(Collectors.toUnmodifiableSet()));
    }

    private ResponseEntity<View> response(View view) {
        return ResponseEntity.status(view.pending() ? HttpStatus.ACCEPTED : HttpStatus.OK)
                .cacheControl(CacheControl.noStore()).body(view);
    }
}
