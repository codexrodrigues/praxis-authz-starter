package org.praxisplatform.authz.catalog;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.praxisplatform.authz.contracts.decisionpoint.DecisionPointDescriptor;

/**
 * Sanitized, metadata-only PAP catalog discovery response ({@code P35}, {@code P43}, {@code P62}).
 *
 * <p>Never contains live domain data samples, never invokes business methods, and never creates
 * HTTP routes ({@code P35}, {@code P54}, {@code P62}).</p>
 */
public record PapCatalogViewResponse(
        String serviceKey,
        String catalogDigest,
        List<DecisionPointDescriptor> admittedDecisionPoints,
        Map<String, List<FieldLineageCatalogEntry>> fieldLineageByPointKey,
        List<String> rejectedPointDiagnostics
) {

    /** Validates non-null response collections. */
    public PapCatalogViewResponse {
        Objects.requireNonNull(serviceKey, "serviceKey is required");
        Objects.requireNonNull(catalogDigest, "catalogDigest is required");
        admittedDecisionPoints = admittedDecisionPoints == null ? List.of() : List.copyOf(admittedDecisionPoints);
        fieldLineageByPointKey = fieldLineageByPointKey == null ? Map.of() : Map.copyOf(fieldLineageByPointKey);
        rejectedPointDiagnostics = rejectedPointDiagnostics == null ? List.of() : List.copyOf(rejectedPointDiagnostics);
    }
}
