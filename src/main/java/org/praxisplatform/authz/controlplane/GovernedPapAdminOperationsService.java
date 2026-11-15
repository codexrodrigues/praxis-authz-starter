package org.praxisplatform.authz.controlplane;

import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import org.praxisplatform.authz.autoconfigure.PraxisAuthzProperties;
import org.praxisplatform.authz.catalog.PapCatalogQueryRequest;
import org.praxisplatform.authz.catalog.PapCatalogViewResponse;
import org.praxisplatform.authz.catalog.SemanticDecisionPointCatalogService;
import org.praxisplatform.authz.contracts.digest.OpaRuntimeHead;
import org.praxisplatform.authz.controlplane.ConfigMaterializationToOpaReconciler.ConfigRuleMaterializationSnapshot;
import org.praxisplatform.authz.controlplane.ConfigMaterializationToOpaReconciler.ReconciliationOutcome;
import org.praxisplatform.authz.seams.RuntimeDecisionPointRegistry;

/**
 * Opt-in, fail-closed administrative control-plane service for PAP catalog queries and
 * {@code DomainRuleMaterialization} -> OPA release reconciliation ({@code G0}, {@code P28},
 * {@code P32}, {@code P35}, {@code P55}).
 *
 * <p>Disabled by default ({@code praxis.authz.admin-endpoints.enabled=false}) so lab fixtures or
 * consumer hosts never expose administrative surfaces unless explicitly enabled and authorized.</p>
 */
public final class GovernedPapAdminOperationsService {

    private final PraxisAuthzProperties properties;
    private final SemanticDecisionPointCatalogService catalogService;
    private final ConfigMaterializationToOpaReconciler reconciler;
    private final RuntimeDecisionPointRegistry registry;

    public GovernedPapAdminOperationsService(
            PraxisAuthzProperties properties,
            SemanticDecisionPointCatalogService catalogService,
            ConfigMaterializationToOpaReconciler reconciler,
            RuntimeDecisionPointRegistry registry
    ) {
        this.properties = Objects.requireNonNull(properties, "properties is required");
        this.catalogService = Objects.requireNonNull(catalogService, "catalogService is required");
        this.reconciler = Objects.requireNonNull(reconciler, "reconciler is required");
        this.registry = Objects.requireNonNull(registry, "registry is required");
    }

    /**
     * Queries the semantic decision-point catalog for the PAP after verifying that admin endpoints
     * are enabled and the caller holds {@code praxis.authz.discovery.required-catalog-authority}
     * ({@code P32}, {@code P35}, {@code P43}).
     */
    public PapCatalogViewResponse querySemanticCatalog(PapCatalogQueryRequest request) {
        assertAdminSurfaceEnabled();
        return catalogService.queryCatalogForPap(request);
    }

    /**
     * Reconciles a governed {@link ConfigRuleMaterializationSnapshot} against the host's
     * {@link RuntimeDecisionPointRegistry}, enforcing the configured administrative authority
     * and tenant-scope isolation ({@code P28}, {@code P32}, {@code P43}, {@code P54}, {@code P55}).
     */
    public ReconciliationOutcome reconcileMaterialization(
            ConfigRuleMaterializationSnapshot snapshot,
            String opaCapabilitiesDigest,
            String operatorPrincipalId,
            Set<String> operatorAuthorities,
            Set<String> allowedTenantIds
    ) {
        assertAdminSurfaceEnabled();
        Objects.requireNonNull(snapshot, "snapshot is required");
        Objects.requireNonNull(operatorPrincipalId, "operatorPrincipalId is required");
        String requiredReconcileAuth = properties.getAdminEndpoints().getRequiredReconcileAuthority();
        if (operatorAuthorities == null || !operatorAuthorities.contains(requiredReconcileAuth)) {
            throw new SecurityException("AUTHZ_PAP_ADMIN_RECONCILE_DENIED: Operator '"
                    + operatorPrincipalId + "' lacks required authority '"
                    + requiredReconcileAuth + "' (P28/P32)");
        }
        if (allowedTenantIds == null || !allowedTenantIds.contains(snapshot.tenantId())) {
            throw new SecurityException("AUTHZ_PAP_ADMIN_TENANT_SCOPE_DENIED: Operator '"
                    + operatorPrincipalId + "' is not authorized for tenant '"
                    + snapshot.tenantId() + "' (P43/P54)");
        }
        return reconciler.reconcileOrWithdraw(
                snapshot,
                properties.getOpa().getInstanceId(),
                opaCapabilitiesDigest,
                operatorPrincipalId,
                operatorAuthorities,
                registry.getDecisionPointsByKey(),
                registry.getFactContractsById(),
                registry.getQueryProjectionsById()
        );
    }

    /**
     * Reconciles a governed {@link ConfigRuleMaterializationSnapshot} when the operator is scoped
     * to the snapshot's tenant.
     */
    public ReconciliationOutcome reconcileMaterialization(
            ConfigRuleMaterializationSnapshot snapshot,
            String opaCapabilitiesDigest,
            String operatorPrincipalId,
            Set<String> operatorAuthorities
    ) {
        Objects.requireNonNull(snapshot, "snapshot is required");
        return reconcileMaterialization(
                snapshot,
                opaCapabilitiesDigest,
                operatorPrincipalId,
                operatorAuthorities,
                Set.of(snapshot.tenantId())
        );
    }

    /**
     * Inspects the active {@link OpaRuntimeHead} for a tenant, environment, and target artifact key,
     * enforcing administrative authority and tenant-scope isolation ({@code P28}, {@code P35}, {@code P43}).
     */
    public Optional<OpaRuntimeHead> findActiveRuntimeHead(
            String tenantId,
            String environment,
            String targetArtifactKey,
            String callerPrincipalId,
            Set<String> callerAuthorities,
            Set<String> allowedTenantIds
    ) {
        assertAdminSurfaceEnabled();
        String catalogAuth = properties.getDiscovery().getRequiredCatalogAuthority();
        String reconcileAuth = properties.getAdminEndpoints().getRequiredReconcileAuthority();
        if (callerAuthorities == null
                || (!callerAuthorities.contains(catalogAuth) && !callerAuthorities.contains(reconcileAuth))) {
            throw new SecurityException("AUTHZ_PAP_ADMIN_HEAD_INSPECT_DENIED: Caller '"
                    + callerPrincipalId + "' lacks required administrative authority (P28/P35)");
        }
        if (allowedTenantIds == null || !allowedTenantIds.contains(tenantId)) {
            throw new SecurityException("AUTHZ_PAP_ADMIN_TENANT_SCOPE_DENIED: Caller '"
                    + callerPrincipalId + "' is not authorized for tenant '" + tenantId + "' (P43/P54)");
        }
        return reconciler.findActiveHead(tenantId, environment, targetArtifactKey);
    }

    private void assertAdminSurfaceEnabled() {
        if (!properties.getAdminEndpoints().isEnabled()) {
            throw new SecurityException("AUTHZ_PAP_ADMIN_SURFACE_DISABLED: PAP administrative operations are disabled by default (G0/P32)");
        }
    }
}
