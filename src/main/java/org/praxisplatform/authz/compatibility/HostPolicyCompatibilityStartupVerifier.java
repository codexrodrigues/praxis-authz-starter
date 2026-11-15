package org.praxisplatform.authz.compatibility;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;
import org.praxisplatform.authz.autoconfigure.PraxisAuthzBootstrapException;
import org.praxisplatform.authz.autoconfigure.PraxisAuthzProperties;
import org.praxisplatform.authz.contracts.binding.RuntimeEnforcementBinding;
import org.praxisplatform.authz.contracts.compatibility.CompatibilityVerificationReport;
import org.praxisplatform.authz.contracts.compatibility.DecisionPointCompatibilityEntry;
import org.praxisplatform.authz.contracts.compatibility.HostPolicyCompatibilityVerifier;
import org.praxisplatform.authz.contracts.context.FactContract;
import org.praxisplatform.authz.contracts.datascope.QueryableResourceProjection;
import org.praxisplatform.authz.contracts.masking.MaskStrategyRegistry;
import org.praxisplatform.authz.contracts.obligation.ObligationHandlerRegistry;
import org.praxisplatform.authz.enforcement.pipeline.AuthorizationProviderPort;
import org.springframework.beans.factory.SmartInitializingSingleton;

/**
 * Verifies single authoritative provider identity, runtime binding presence, contract digest parity,
 * registered mask strategies/obligation handlers, and {@link HostPolicyCompatibilityVerifier}
 * handshake at context startup and reload ({@code CC08}, {@code P20}, {@code P39}, {@code P48}, {@code P59}).
 */
public final class HostPolicyCompatibilityStartupVerifier implements SmartInitializingSingleton {

    private final PraxisAuthzProperties properties;
    private final List<AuthorizationProviderPort> providers;
    private final HostPolicyCompatibilityVerifier compatibilityVerifier;
    private final MaskStrategyRegistry maskStrategyRegistry;
    private final ObligationHandlerRegistry obligationHandlerRegistry;
    private final HostRuntimePolicyCoordinates coordinates;
    private final AtomicReference<PraxisAuthzReadinessStatus> latestStatus = new AtomicReference<>(
            new PraxisAuthzReadinessStatus(
                    false,
                    "OUT_OF_SERVICE",
                    "UNVERIFIED",
                    "UNVERIFIED",
                    0,
                    List.of("AUTHZ_BOOTSTRAP_NOT_YET_VERIFIED"),
                    Instant.now()
            )
    );

    /**
     * Constructs the startup compatibility verifier without host strategy/obligation registry cross-checks.
     */
    public HostPolicyCompatibilityStartupVerifier(
            PraxisAuthzProperties properties,
            List<AuthorizationProviderPort> providers,
            HostPolicyCompatibilityVerifier compatibilityVerifier,
            HostRuntimePolicyCoordinates coordinates
    ) {
        this(properties, providers, compatibilityVerifier, null, null, coordinates);
    }

    /**
     * Constructs the startup compatibility verifier with full host strategy and obligation registry cross-checks.
     */
    public HostPolicyCompatibilityStartupVerifier(
            PraxisAuthzProperties properties,
            List<AuthorizationProviderPort> providers,
            HostPolicyCompatibilityVerifier compatibilityVerifier,
            MaskStrategyRegistry maskStrategyRegistry,
            ObligationHandlerRegistry obligationHandlerRegistry,
            HostRuntimePolicyCoordinates coordinates
    ) {
        this.properties = Objects.requireNonNull(properties, "properties is required");
        this.providers = providers == null ? List.of() : List.copyOf(providers);
        this.compatibilityVerifier = Objects.requireNonNull(compatibilityVerifier, "compatibilityVerifier is required");
        this.maskStrategyRegistry = maskStrategyRegistry;
        this.obligationHandlerRegistry = obligationHandlerRegistry;
        this.coordinates = coordinates;
    }

    @Override
    public void afterSingletonsInstantiated() {
        verifyAndRefreshReadiness(this.coordinates);
    }

    /**
     * Executes full bootstrap and compatibility verification against the given {@link HostRuntimePolicyCoordinates},
     * updating readiness state and failing closed when configured ({@code P20}, {@code P39}, {@code P48}, {@code P59}).
     */
    public PraxisAuthzReadinessStatus verifyAndRefreshReadiness(HostRuntimePolicyCoordinates activeCoordinates) {
        List<String> diagnostics = new ArrayList<>();

        // 1. P20: Verify exactly one authoritative AuthorizationProviderPort exists
        if (providers.isEmpty()) {
            diagnostics.add("AUTHZ_BOOTSTRAP_MISSING_PROVIDER:No AuthorizationProviderPort bean registered (P20)");
        } else if (providers.size() > 1) {
            diagnostics.add("AUTHZ_BOOTSTRAP_AMBIGUOUS_PROVIDERS:Multiple (" + providers.size()
                    + ") AuthorizationProviderPort beans registered without single authority (P20)");
        }

        String runtimeRevision = "UNVERIFIED";
        String policySetDigest = "UNVERIFIED";
        int verifiedPoints = 0;

        // 2. P20: Verify runtime bindings and compatibility coordinates
        if (activeCoordinates == null) {
            if (properties.isRequireBindingsOnStartup() || properties.getCompatibility().isVerifyOnStartup()) {
                diagnostics.add("AUTHZ_BOOTSTRAP_MISSING_COORDINATES:HostRuntimePolicyCoordinates bean is required when requireBindingsOnStartup or verifyOnStartup is true (P20)");
            }
        } else {
            runtimeRevision = activeCoordinates.runtimeRelease().runtimeRevision();
            policySetDigest = activeCoordinates.runtimeRelease().policySetDigest();

            if (properties.isRequireBindingsOnStartup() && activeCoordinates.bindingsByPointKey().isEmpty()) {
                diagnostics.add("AUTHZ_BOOTSTRAP_MISSING_BINDINGS:Zero RuntimeEnforcementBinding entries registered (P20)");
            }

            if (properties.getCompatibility().isVerifyOnStartup()) {
                CompatibilityVerificationReport report = compatibilityVerifier.verify(
                        activeCoordinates.hostManifest(),
                        activeCoordinates.runtimeRelease(),
                        activeCoordinates.impactBaseline()
                );
                if (!report.compatible()) {
                    diagnostics.addAll(report.blockingMismatches());
                }

                // 3. P39, P48, P59, P4-R01: Verify exact digest parity, readiness stages, and orphan bindings across Manifest, RuntimeEnforcementBinding, FactContract, and QueryableResourceProjection
                java.util.Set<String> manifestPointKeys = new java.util.HashSet<>();
                for (DecisionPointCompatibilityEntry entry : activeCoordinates.hostManifest().decisionPointBindings()) {
                    String pointKey = entry.pointKey();
                    manifestPointKeys.add(pointKey);
                    RuntimeEnforcementBinding binding = activeCoordinates.bindingsByPointKey().get(pointKey);
                    if (binding == null) {
                        diagnostics.add("COMPAT_UNREGISTERED_RUNTIME_BINDING:" + pointKey);
                        continue;
                    }
                    if (!binding.isAuthoritativeReady()) {
                        diagnostics.add("COMPAT_BINDING_NOT_AUTHORITATIVE_READY:" + pointKey);
                    } else if (!runtimeRevision.equals(binding.readinessEvidence().activeRuntimeRevision())
                            || !policySetDigest.equals(binding.readinessEvidence().activePolicySetDigest())) {
                        diagnostics.add("COMPAT_BINDING_READINESS_REVISION_DRIFT:" + pointKey);
                    }
                    if (!entry.bindingDigest().equals(binding.bindingDigest())) {
                        diagnostics.add("COMPAT_BINDING_DIGEST_DRIFT:" + pointKey);
                    }
                    if (!entry.descriptorDigest().equals(binding.decisionPointRef().descriptorDigest())) {
                        diagnostics.add("COMPAT_BINDING_DESCRIPTOR_DIGEST_DRIFT:" + pointKey);
                    }
                    FactContract factContract = activeCoordinates.factContractsById().get(entry.factContractId());
                    if (factContract == null) {
                        diagnostics.add("COMPAT_MISSING_FACT_CONTRACT:" + entry.factContractId());
                    } else if (!entry.factContractDigest().equals(factContract.factContractDigest())) {
                        diagnostics.add("COMPAT_FACT_CONTRACT_DIGEST_DRIFT:" + entry.factContractId());
                    }

                    if (entry.queryProjectionRef() != null) {
                        QueryableResourceProjection proj = activeCoordinates.queryProjectionsByRef()
                                .get(entry.queryProjectionRef());
                        if (proj == null) {
                            diagnostics.add("COMPAT_MISSING_QUERY_PROJECTION:" + entry.queryProjectionRef());
                        } else if (!entry.queryProjectionDigest().equals(proj.projectionDigest())) {
                            diagnostics.add("COMPAT_QUERY_PROJECTION_DIGEST_DRIFT:" + entry.queryProjectionRef());
                        }
                    }
                    verifiedPoints++;
                }

                for (String registeredPointKey : activeCoordinates.bindingsByPointKey().keySet()) {
                    if (!manifestPointKeys.contains(registeredPointKey)) {
                        diagnostics.add("COMPAT_ORPHAN_RUNTIME_BINDING:" + registeredPointKey);
                    }
                }

                if (maskStrategyRegistry != null) {
                    for (String strategyId : activeCoordinates.hostManifest().registeredMaskStrategyIds()) {
                        if (maskStrategyRegistry.findById(strategyId).isEmpty()) {
                            diagnostics.add("COMPAT_UNREGISTERED_HOST_MASK_STRATEGY:" + strategyId);
                        }
                    }
                }
                if (obligationHandlerRegistry != null) {
                    for (String obligationType : activeCoordinates.hostManifest().registeredObligationTypes()) {
                        if (obligationHandlerRegistry.findHandler(obligationType).isEmpty()) {
                            diagnostics.add("COMPAT_UNREGISTERED_HOST_OBLIGATION_HANDLER:" + obligationType);
                        }
                    }
                }
            }
        }

        boolean ready = diagnostics.isEmpty();
        PraxisAuthzReadinessStatus status = new PraxisAuthzReadinessStatus(
                ready,
                ready ? "UP" : "OUT_OF_SERVICE",
                runtimeRevision,
                policySetDigest,
                ready ? verifiedPoints : 0,
                diagnostics,
                Instant.now()
        );
        latestStatus.set(status);

        if (!ready && properties.isFailClosedOnBootstrapError()) {
            throw new PraxisAuthzBootstrapException(
                    diagnostics.getFirst().split(":")[0],
                    "Praxis Authorization bootstrap failed closed with " + diagnostics.size()
                            + " diagnostic(s): " + diagnostics,
                    diagnostics
            );
        }
        return status;
    }

    /** Returns the latest verified readiness snapshot. */
    public PraxisAuthzReadinessStatus currentStatus() {
        return latestStatus.get();
    }
}
