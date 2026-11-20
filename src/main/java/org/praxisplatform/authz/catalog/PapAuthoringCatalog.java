package org.praxisplatform.authz.catalog;

import java.util.Comparator;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import org.praxisplatform.authz.contracts.context.ContextEvaluationPhase;
import org.praxisplatform.authz.contracts.context.FactCardinality;
import org.praxisplatform.authz.contracts.context.FactDescriptor;
import org.praxisplatform.authz.contracts.context.FactPresenceModel;
import org.praxisplatform.authz.contracts.context.FactValueType;
import org.praxisplatform.authz.contracts.decisionpoint.DecisionPointDescriptor;
import org.praxisplatform.authz.contracts.decisionpoint.EvaluationMode;
import org.praxisplatform.authz.seams.RuntimeDecisionPointRegistry;

/** Metadata for authoring exact ACCESS targets. No fact values or provider queries. */
public record PapAuthoringCatalog(List<Service> services) {
    public record Service(String serviceKey, String catalogDigest, List<Point> decisionPoints) {}
    public record Point(String pointKey, String resourceKey, String descriptorDigest, String factContractId,
                        String factContractDigest, Map<EvaluationMode, List<Fact>> factsByMode) {}
    public record Fact(String factPath, FactValueType valueType, FactCardinality cardinality, FactPresenceModel presenceModel) {}

    static Service project(PapCatalogViewResponse view, RuntimeDecisionPointRegistry registry) {
        var points = view.admittedDecisionPoints().stream()
                .sorted(Comparator.comparing(point -> point.identity().pointKey()))
                .map(point -> project(view.serviceKey(), point, registry))
                .toList();
        return new Service(view.serviceKey(), view.catalogDigest(), points);
    }

    private static Point project(String service, DecisionPointDescriptor point, RuntimeDecisionPointRegistry registry) {
        var identity = point.identity();
        var registered = registry.findRegisteredPoint(identity.pointKey())
                .filter(entry -> service.equals(identity.serviceKey()) && service.equals(entry.admissionRecord().serviceKey()))
                .filter(entry -> point.equals(entry.decisionPoint()))
                .orElseThrow(() -> new IllegalStateException("PAP catalog and runtime registry disagree"));
        var contract = registered.factContract();
        Map<EvaluationMode, List<Fact>> byMode = new EnumMap<>(EvaluationMode.class);
        for (EvaluationMode mode : point.evaluationModes()) {
            var phase = switch (mode) {
                case SEARCH -> ContextEvaluationPhase.ADMISSION;
                case TARGET -> ContextEvaluationPhase.TARGET;
            };
            byMode.put(mode, contract.descriptorsByPath().values().stream()
                    .filter(fact -> fact.availableInPhases().contains(phase))
                    .sorted(Comparator.comparing(FactDescriptor::factPath))
                    .map(fact -> new Fact(fact.factPath(), fact.valueType(), fact.cardinality(), fact.presenceModel()))
                    .toList());
        }
        return new Point(identity.pointKey(), identity.resourceKey(), point.descriptorDigest(), contract.factContractId(),
                contract.factContractDigest(), byMode);
    }
}
