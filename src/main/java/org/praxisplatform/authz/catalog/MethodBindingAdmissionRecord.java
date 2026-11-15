package org.praxisplatform.authz.catalog;

import java.util.List;
import java.util.Objects;
import java.util.Set;
import org.praxisplatform.authz.contracts.binding.RuntimeEnforcementBinding;
import org.praxisplatform.authz.contracts.decisionpoint.DecisionPointDescriptor;

/**
 * Admitted semantic decision-point registration combining its {@link DecisionPointDescriptor},
 * {@link RuntimeEnforcementBinding}, admitted invocation channels ({@code REST_ENDPOINT},
 * {@code PROXIED_INTERNAL_SERVICE}, {@code GOVERNED_DURABLE_WORKER}), proxy-enforcement attestation,
 * and governed {@link FieldLineageCatalogEntry} list ({@code P34}, {@code P35}, {@code P41},
 * {@code P44}, {@code P45}, {@code P57}, {@code P58}).
 */
public record MethodBindingAdmissionRecord(
        String serviceKey,
        DecisionPointDescriptor decisionPoint,
        RuntimeEnforcementBinding enforcementBinding,
        Set<AdmittedInvocationChannel> admittedChannels,
        boolean proxyEnforcedWithoutSelfInvocationBypass,
        List<FieldLineageCatalogEntry> fieldLineageEntries
) {

    /** Validates consistency between decisionPoint and enforcementBinding. */
    public MethodBindingAdmissionRecord {
        Objects.requireNonNull(serviceKey, "serviceKey is required");
        serviceKey = serviceKey.trim();
        if (serviceKey.isEmpty()) {
            throw new IllegalArgumentException("serviceKey must not be blank");
        }
        Objects.requireNonNull(decisionPoint, "decisionPoint is required");
        Objects.requireNonNull(enforcementBinding, "enforcementBinding is required");
        if (!decisionPoint.identity().pointKey().equals(enforcementBinding.decisionPointRef().pointKey())) {
            throw new IllegalArgumentException("decisionPoint.pointKey (" + decisionPoint.identity().pointKey()
                    + ") must match enforcementBinding.decisionPointKey ("
                    + enforcementBinding.decisionPointRef().pointKey() + ")");
        }
        admittedChannels = admittedChannels == null ? Set.of() : Set.copyOf(admittedChannels);
        fieldLineageEntries = fieldLineageEntries == null ? List.of() : List.copyOf(fieldLineageEntries);
    }
}
