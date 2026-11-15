package org.praxisplatform.authz.starter;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.praxisplatform.authz.autoconfigure.PraxisAuthzProperties;
import org.praxisplatform.authz.catalog.AdmittedInvocationChannel;
import org.praxisplatform.authz.catalog.FieldLineageCatalogEntry;
import org.praxisplatform.authz.catalog.MethodBindingAdmissionRecord;
import org.praxisplatform.authz.catalog.PapCatalogQueryRequest;
import org.praxisplatform.authz.catalog.PapCatalogViewResponse;
import org.praxisplatform.authz.catalog.SemanticDecisionPointCatalogService;
import org.praxisplatform.authz.contracts.decisionpoint.FieldUseCategory;
import org.praxisplatform.authz.pilot.AfastamentoAuthzPilotBlueprint;

/**
 * Conformance tests for {@link SemanticDecisionPointCatalogService} ({@code P34}, {@code P35},
 * {@code P41}, {@code P43}, {@code P44}, {@code P45}, {@code P54}, {@code P57}, {@code P58},
 * {@code P62}, {@code P64}).
 */
class SemanticDecisionPointCatalogServiceTest {

    @Test
    void p34_p35_p41_p43_p44_p45_p54_p57_p58_p62_p64_catalogEnforcesScopeProxyLineageAndCycleBudgets() {
        PraxisAuthzProperties props = new PraxisAuthzProperties();
        AfastamentoAuthzPilotBlueprint validBlueprint = AfastamentoAuthzPilotBlueprint.createErgonAfastamentoBlueprint();
        MethodBindingAdmissionRecord validRecord = validBlueprint.admissionRecords().getFirst();

        // Build an unproxied / self-invocation record (P41)
        AfastamentoAuthzPilotBlueprint selfInvBlueprint = AfastamentoAuthzPilotBlueprint.createHostBlueprint(
                "praxis-ergon-showcase", "human-resources.unproxied-internal", "ergon.unproxied");
        MethodBindingAdmissionRecord unproxiedRecord = new MethodBindingAdmissionRecord(
                "praxis-ergon-showcase",
                selfInvBlueprint.decisionPoint(),
                selfInvBlueprint.enforcementBinding(),
                Set.of(AdmittedInvocationChannel.PROXIED_INTERNAL_SERVICE),
                false, // P41: self-invocation / unproxied!
                selfInvBlueprint.admissionRecords().getFirst().fieldLineageEntries()
        );

        // Build a record with ambiguous homonym wirePath (P45/P58), heuristic default AI usage (P57), and cyclic lineage (P64)
        AfastamentoAuthzPilotBlueprint badLineageBlueprint = AfastamentoAuthzPilotBlueprint.createHostBlueprint(
                "praxis-ergon-showcase", "human-resources.bad-lineage", "ergon.bad");
        List<FieldLineageCatalogEntry> badLineageEntries = List.of(
                new FieldLineageCatalogEntry(
                        "ergon.bad.attr_a",
                        "concept:a",
                        "schema://bad/ResponseDTO",
                        "documento",
                        "READ_PROJECTION",
                        "PII_RESTRICTED",
                        "DENIED",
                        false,
                        Set.of(FieldUseCategory.VALUE),
                        List.of("ergon.bad.attr_b"), // Cycle: attr_a -> attr_b -> attr_a (P64)
                        true
                ),
                new FieldLineageCatalogEntry(
                        "ergon.bad.attr_b",
                        "concept:b",
                        "schema://bad/ResponseDTO",
                        "documento", // P45/P58: Ambiguous homonym on same schemaRef + operationRole + wirePath!
                        "READ_PROJECTION",
                        "HEURISTIC", // P57: Heuristic classification!
                        "DEFAULT_PERMISSIVE", // P57: Permissive default AI usage!
                        true,
                        Set.of(FieldUseCategory.VALUE),
                        List.of("ergon.bad.attr_a"),
                        false
                )
        );
        MethodBindingAdmissionRecord badLineageRecord = new MethodBindingAdmissionRecord(
                "praxis-ergon-showcase",
                badLineageBlueprint.decisionPoint(),
                badLineageBlueprint.enforcementBinding(),
                Set.of(AdmittedInvocationChannel.REST_ENDPOINT),
                true,
                badLineageEntries
        );

        SemanticDecisionPointCatalogService catalogService = new SemanticDecisionPointCatalogService(
                props,
                List.of(validRecord, unproxiedRecord, badLineageRecord)
        );

        // 1. P35 / P62: Missing administrative authority is rejected
        assertThrows(SecurityException.class, () ->
                catalogService.queryCatalogForPap(new PapCatalogQueryRequest(
                        "author-1",
                        Set.of("REGULAR_AUTHOR"),
                        Set.of("praxis-ergon-showcase"),
                        "praxis-ergon-showcase"
                ))
        );

        // 2. P43 / P54: Querying another service scope not granted to the author is rejected
        assertThrows(SecurityException.class, () ->
                catalogService.queryCatalogForPap(new PapCatalogQueryRequest(
                        "author-1",
                        Set.of("praxis:authz:pap:catalog:read"),
                        Set.of("praxis-ergon-showcase"),
                        "praxis-finance-service"
                ))
        );

        // 3. Valid query admits only the valid decision point and rejects the offending points with actionable diagnostics (P41, P45, P57, P64)
        PapCatalogViewResponse response = catalogService.queryCatalogForPap(new PapCatalogQueryRequest(
                "author-1",
                Set.of("praxis:authz:pap:catalog:read"),
                Set.of("praxis-ergon-showcase"),
                "praxis-ergon-showcase"
        ));

        assertEquals(1, response.admittedDecisionPoints().size());
        assertEquals(validBlueprint.decisionPoint().identity().pointKey(),
                response.admittedDecisionPoints().getFirst().identity().pointKey());

        // P44, P58, P62: Metadata for cidCodigo (READ_PROJECTION) and codigoCid10 (CREATE_INPUT) is exposed to PAP even though aiUsageMode=DENIED
        List<FieldLineageCatalogEntry> admittedLineage =
                response.fieldLineageByPointKey().get(validBlueprint.decisionPoint().identity().pointKey());
        assertEquals(3, admittedLineage.size());
        assertTrue(admittedLineage.stream().anyMatch(e ->
                e.wirePath().equals("cidCodigo") && e.attributeId().equals("ergon.afastamentos.cid_codigo")));
        assertTrue(admittedLineage.stream().anyMatch(e ->
                e.wirePath().equals("codigoCid10") && e.attributeId().equals("ergon.afastamentos.cid_codigo")));

        // Verify diagnostics for the rejected points (P41, P45, P46, P49, P56, P57, P64)
        List<String> rejected = response.rejectedPointDiagnostics();
        assertTrue(rejected.stream().anyMatch(d -> d.startsWith("CATALOG_REJECT_UNPROXIED_OR_SELF_INVOCATION:")));
        assertTrue(rejected.stream().anyMatch(d -> d.startsWith("CATALOG_REJECT_HEURISTIC_OR_PERMISSIVE_DEFAULT:")));
        assertTrue(rejected.stream().anyMatch(d -> d.startsWith("CATALOG_REJECT_AMBIGUOUS_HOMONYM_WIRE_PATH:")));
        assertTrue(rejected.stream().anyMatch(d -> d.startsWith("CATALOG_REJECT_DERIVED_EXPORT_WIDENING:")));
        assertTrue(rejected.stream().anyMatch(d -> d.startsWith("CATALOG_REJECT_DERIVED_AI_USAGE_WIDENING:")));
        assertTrue(rejected.stream().anyMatch(d -> d.startsWith("CATALOG_REJECT_UNAPPROVED_DERIVED_DECLASSIFICATION:")));
        assertTrue(rejected.stream().anyMatch(d -> d.startsWith("CATALOG_REJECT_LINEAGE_CYCLE:")));
    }
}
