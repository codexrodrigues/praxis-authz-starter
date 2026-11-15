package org.praxisplatform.authz.compatibility;

import java.util.Map;
import java.util.Objects;
import org.praxisplatform.authz.contracts.binding.RuntimeEnforcementBinding;
import org.praxisplatform.authz.contracts.compatibility.HostPolicyCompatibilityManifest;
import org.praxisplatform.authz.contracts.compatibility.ImpactGraphBaseline;
import org.praxisplatform.authz.contracts.context.FactContract;
import org.praxisplatform.authz.contracts.datascope.QueryableResourceProjection;
import org.praxisplatform.authz.contracts.digest.OpaRuntimeRelease;

/**
 * Bundles the host's compatibility manifest, active OPA runtime release, impact graph baseline,
 * and registered runtime contracts for startup and reload verification ({@code CC08}, {@code P20},
 * {@code P39}, {@code P48}, {@code P59}).
 */
public record HostRuntimePolicyCoordinates(
        HostPolicyCompatibilityManifest hostManifest,
        OpaRuntimeRelease runtimeRelease,
        ImpactGraphBaseline impactBaseline,
        Map<String, FactContract> factContractsById,
        Map<String, QueryableResourceProjection> queryProjectionsByRef,
        Map<String, RuntimeEnforcementBinding> bindingsByPointKey
) {

    /** Validates required coordinates and creates immutable copies of contract maps. */
    public HostRuntimePolicyCoordinates {
        Objects.requireNonNull(hostManifest, "hostManifest is required");
        Objects.requireNonNull(runtimeRelease, "runtimeRelease is required");
        Objects.requireNonNull(impactBaseline, "impactBaseline is required");
        factContractsById = factContractsById == null ? Map.of() : Map.copyOf(factContractsById);
        queryProjectionsByRef = queryProjectionsByRef == null ? Map.of() : Map.copyOf(queryProjectionsByRef);
        bindingsByPointKey = bindingsByPointKey == null ? Map.of() : Map.copyOf(bindingsByPointKey);
    }
}
