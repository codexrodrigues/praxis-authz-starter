package org.praxisplatform.authz.starter;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.praxisplatform.authz.autoconfigure.PraxisAuthzAutoConfiguration;
import org.praxisplatform.authz.catalog.FieldLineageCatalogEntry;
import org.praxisplatform.authz.catalog.MethodBindingAdmissionRecord;
import org.praxisplatform.authz.compatibility.HostRuntimePolicyCoordinates;
import org.praxisplatform.authz.contracts.context.FactResolutionStatus;
import org.praxisplatform.authz.contracts.context.FactValueType;
import org.praxisplatform.authz.contracts.context.ProviderInputProjection;
import org.praxisplatform.authz.contracts.context.TemporalContext;
import org.praxisplatform.authz.contracts.datascope.DataScopeOutcome;
import org.praxisplatform.authz.contracts.decisionpoint.FieldUseCategory;
import org.praxisplatform.authz.contracts.digest.OpaRuntimeHead;
import org.praxisplatform.authz.contracts.envelope.GateOutcome;
import org.praxisplatform.authz.enforcement.masking.DtoFieldSchemaMetadata;
import org.praxisplatform.authz.enforcement.obligation.InMemoryTransactionalAuditOutbox;
import org.praxisplatform.authz.enforcement.obligation.TransactionalAuditOutboxPort;
import org.praxisplatform.authz.enforcement.pipeline.AuthorizationProviderPort;
import org.praxisplatform.authz.export.GovernedCollectionExportGuard.ExportFormat;
import org.praxisplatform.authz.export.GovernedCollectionExportGuard.SanitizedExportArtifact;
import org.praxisplatform.authz.opa.client.OpaClientTransport;
import org.praxisplatform.authz.opa.client.OpaTransportResponse;
import org.praxisplatform.authz.opa.revision.OpaEvaluationFailureException;
import org.praxisplatform.authz.pilot.WorkforceLeaveAuthzPilotBlueprint;
import org.praxisplatform.authz.seams.DeclarativeDecisionPointExecutionTemplate;
import org.praxisplatform.authz.seams.GovernedExportAndAiToolAuthorizationSeam;
import org.praxisplatform.authz.seams.GovernedExportAndAiToolAuthorizationSeam.AiGovernanceMetadataView;
import org.praxisplatform.authz.seams.GovernedExportAndAiToolAuthorizationSeam.SanitizedAiToolProjection;
import org.praxisplatform.authz.telemetry.AuthorizationTelemetrySinkPort;
import org.praxisplatform.authz.telemetry.SanitizedAuthorizationTelemetryPublisher;
import org.praxisplatform.authz.telemetry.SanitizedAuthorizationTelemetryPublisher.SanitizedDecisionTelemetryEvent;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

/**
 * Verifies Phase {@code P9} enterprise operational closure across {@code praxis-authz-opa} and
 * {@code praxis-authz-starter}:
 * <ul>
 *   <li>Real loopback HTTP sidecar evaluation via {@code HttpClientOpaTransport} and
 *       {@code OpaAuthorizationProviderAdapter} ({@code CC11}, {@code P03}, {@code P17});</li>
 *   <li>{@link GovernedExportAndAiToolAuthorizationSeam} for {@code CSV}/{@code JSON} collection
 *       exports and AI tool payload projection + metadata-only authoring discovery ({@code P11},
 *       {@code P12}, {@code P18}, {@code P19}, {@code P56}, {@code P57}, {@code P60}, {@code P62});</li>
 *   <li>{@link SanitizedAuthorizationTelemetryPublisher} ensuring zero raw sensitive values in
 *       observability telemetry ({@code CC07}, {@code P21}).</li>
 * </ul>
 */
class P9HttpOpaSidecarExportAiSeamAndTelemetryTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(PraxisAuthzAutoConfiguration.class));

    @Test
    void verifyP9HttpClientOpaTransportOverLoopbackSidecarAndFailClosedErrors() throws Exception {
        WorkforceLeaveAuthzPilotBlueprint blueprint = WorkforceLeaveAuthzPilotBlueprint.createWorkforceLeaveBlueprint();
        AtomicReference<String> faultMode = new AtomicReference<>("NONE");

        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.setExecutor(java.util.concurrent.Executors.newCachedThreadPool());
        server.createContext("/v1/data", exchange -> {
            try {
                String mode = faultMode.get();
                if ("HTTP_503".equals(mode)) {
                    byte[] err = "{\"error\":\"service unavailable\"}".getBytes(StandardCharsets.UTF_8);
                    exchange.sendResponseHeaders(503, err.length);
                    try (OutputStream os = exchange.getResponseBody()) {
                        os.write(err);
                    }
                    return;
                }
                if ("MISSING_RESULT".equals(mode)) {
                    byte[] emptyObj = "{}".getBytes(StandardCharsets.UTF_8);
                    exchange.getResponseHeaders().add("Content-Type", "application/json");
                    exchange.sendResponseHeaders(200, emptyObj.length);
                    try (OutputStream os = exchange.getResponseBody()) {
                        os.write(emptyObj);
                    }
                    return;
                }
                if ("MALFORMED_JSON".equals(mode)) {
                    byte[] broken = "{not-valid-json".getBytes(StandardCharsets.UTF_8);
                    exchange.getResponseHeaders().add("Content-Type", "application/json");
                    exchange.sendResponseHeaders(200, broken.length);
                    try (OutputStream os = exchange.getResponseBody()) {
                        os.write(broken);
                    }
                    return;
                }
                if ("TIMEOUT".equals(mode)) {
                    try {
                        Thread.sleep(2200L);
                    } catch (InterruptedException ignored) {
                        Thread.currentThread().interrupt();
                    }
                }

                String reqBody = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
                String path = exchange.getRequestURI().getPath();
                OpaTransportResponse localResp = blueprint.localOpaTransport().postDataQuery(
                        blueprint.bundleArtifact().runtimeHead().instanceId(),
                        path,
                        reqBody
                );
                byte[] respBytes = localResp.rawJsonBody().getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().add("Content-Type", "application/json");
                exchange.getResponseHeaders().add("X-OPA-Instance-Id", localResp.instanceId());
                exchange.sendResponseHeaders(localResp.statusCode(), respBytes.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(respBytes);
                }
            } finally {
                exchange.close();
            }
        });
        server.start();

        int port = server.getAddress().getPort();
        String baseUrl = "http://127.0.0.1:" + port;
        String instanceId = blueprint.bundleArtifact().runtimeHead().instanceId();

        try {
            contextRunner
                    .withPropertyValues(
                            "praxis.authz.opa.http-transport-enabled=true",
                            "praxis.authz.opa.base-url=" + baseUrl,
                            "praxis.authz.opa.instance-id=" + instanceId,
                            "praxis.authz.opa.request-timeout=1500ms"
                    )
                    .withBean(HostRuntimePolicyCoordinates.class, blueprint::coordinates)
                    .withBean(MethodBindingAdmissionRecord.class, () -> blueprint.admissionRecords().getFirst())
                    .run(context -> {
                        AuthorizationProviderPort providerPort = context.getBean(AuthorizationProviderPort.class);
                        String dpKey = blueprint.decisionPoint().identity().pointKey();
                        String fcDigest = blueprint.factContract().factContractDigest();

                        // 1. Live HTTP TARGET evaluation -> ALLOW
                        ProviderInputProjection targetInput = new ProviderInputProjection(
                                ProviderInputProjection.SCHEMA_VERSION_V1,
                                dpKey,
                                "TARGET",
                                fcDigest,
                                new TemporalContext(Instant.now(), ZoneOffset.UTC),
                                Map.of(
                                        "subject.principalId", "usr-gestor-101",
                                        "subject.organizationUnitIds", List.of(100L),
                                        "resource.lotacaoSetorId", 100L
                                ),
                                Map.of(
                                        "subject.principalId", FactResolutionStatus.PRESENT,
                                        "subject.organizationUnitIds", FactResolutionStatus.PRESENT,
                                        "resource.lotacaoSetorId", FactResolutionStatus.PRESENT
                                ),
                                Set.of()
                        );
                        var targetEnv = providerPort.evaluateTarget(targetInput, null);
                        assertEquals(GateOutcome.ALLOW, targetEnv.gateOutcome());

                        // 2. Live HTTP 3-step SEARCH evaluation -> FILTER
                        ProviderInputProjection searchInput = new ProviderInputProjection(
                                ProviderInputProjection.SCHEMA_VERSION_V1,
                                dpKey,
                                "SEARCH",
                                fcDigest,
                                new TemporalContext(Instant.now(), ZoneOffset.UTC),
                                Map.of(
                                        "subject.principalId", "usr-gestor-101",
                                        "subject.organizationUnitIds", List.of(100L)
                                ),
                                Map.of(
                                        "subject.principalId", FactResolutionStatus.PRESENT,
                                        "subject.organizationUnitIds", FactResolutionStatus.PRESENT
                                ),
                                Set.of()
                        );
                        var searchRes = providerPort.evaluateSearch(searchInput);
                        assertEquals(GateOutcome.ALLOW, searchRes.admissionEnvelope().gateOutcome());
                        assertEquals(DataScopeOutcome.FILTER, searchRes.dataScopePlan().scopeOutcome());

                        // 3. P03: HTTP 503 fails closed with AUTHZ_OPA_HTTP_STATUS_503
                        faultMode.set("HTTP_503");
                        OpaEvaluationFailureException ex503 = assertThrows(
                                OpaEvaluationFailureException.class,
                                () -> providerPort.evaluateTarget(targetInput, null)
                        );
                        assertEquals("AUTHZ_OPA_HTTP_STATUS_503", ex503.getErrorCode());

                        // 4. P03: HTTP 200 without "result" fails closed with AUTHZ_OPA_UNDEFINED_RESULT
                        faultMode.set("MISSING_RESULT");
                        OpaEvaluationFailureException exUndef = assertThrows(
                                OpaEvaluationFailureException.class,
                                () -> providerPort.evaluateTarget(targetInput, null)
                        );
                        assertEquals("AUTHZ_OPA_UNDEFINED_RESULT", exUndef.getErrorCode());

                        // 5. P03: Malformed JSON fails closed with AUTHZ_OPA_MALFORMED_JSON
                        faultMode.set("MALFORMED_JSON");
                        OpaEvaluationFailureException exMalformed = assertThrows(
                                OpaEvaluationFailureException.class,
                                () -> providerPort.evaluateTarget(targetInput, null)
                        );
                        assertEquals("AUTHZ_OPA_MALFORMED_JSON", exMalformed.getErrorCode());

                        // 6. P03: Request exceeding 200ms timeout fails closed with AUTHZ_OPA_TIMEOUT
                        faultMode.set("TIMEOUT");
                        OpaEvaluationFailureException exTimeout = assertThrows(
                                OpaEvaluationFailureException.class,
                                () -> providerPort.evaluateTarget(targetInput, null)
                        );
                        assertEquals("AUTHZ_OPA_TIMEOUT", exTimeout.getErrorCode());
                    });
        } finally {
            server.stop(0);
        }
    }

    @Test
    void verifyP9GovernedExportAndAiToolSeamAndSanitizedTelemetry() {
        WorkforceLeaveAuthzPilotBlueprint blueprint = WorkforceLeaveAuthzPilotBlueprint.createWorkforceLeaveBlueprint();
        MethodBindingAdmissionRecord baseRecord = blueprint.admissionRecords().getFirst();
        String pointKey = baseRecord.decisionPoint().identity().pointKey();

        // Enrich lineage entries to test P56 (ancestor restriction inheritance), P57 (un-governed fail-closed), and P62 (METADATA_ONLY vs ALLOWED)
        List<FieldLineageCatalogEntry> enrichedLineage = List.of(
                new FieldLineageCatalogEntry(
                        "workforce.leaves.lotacao_setor_id",
                        "concept:hr:org-unit",
                        "schema://human-resources.afastamentos/ResponseDTO",
                        "lotacaoSetorId",
                        "READ_PROJECTION",
                        "OPERATIONAL_INTERNAL",
                        "ALLOWED",
                        true,
                        Set.of(FieldUseCategory.VALUE, FieldUseCategory.FILTER),
                        List.of(),
                        true
                ),
                new FieldLineageCatalogEntry(
                        "workforce.leaves.cid_codigo",
                        "concept:health:icd10",
                        "schema://human-resources.afastamentos/ResponseDTO",
                        "cidCodigo",
                        "READ_PROJECTION",
                        "HEALTH_SENSITIVE",
                        "DENIED",
                        false, // non-exportable!
                        Set.of(FieldUseCategory.VALUE),
                        List.of(),
                        true
                ),
                new FieldLineageCatalogEntry(
                        "workforce.leaves.cid_resumo_derivado",
                        "concept:health:icd10-summary",
                        "schema://human-resources.afastamentos/ResponseDTO",
                        "cidResumoDerivado",
                        "READ_PROJECTION",
                        "HEALTH_SENSITIVE",
                        "ALLOWED", // attempts to widen AI usage, but ancestor cid_codigo is DENIED and exportable=false (P56/P60)!
                        true,
                        Set.of(FieldUseCategory.VALUE),
                        List.of("workforce.leaves.cid_codigo"),
                        true
                ),
                new FieldLineageCatalogEntry(
                        "workforce.leaves.substituto_servidor_id",
                        "concept:hr:substitute-employee",
                        "schema://human-resources.afastamentos/ResponseDTO",
                        "substitutoServidorId",
                        "READ_PROJECTION",
                        "OPERATIONAL_INTERNAL",
                        "SCHEMA_METADATA_ONLY", // P62: exportable=true, but AI value projection is forbidden!
                        true,
                        Set.of(FieldUseCategory.VALUE, FieldUseCategory.FILTER),
                        List.of(),
                        true
                ),
                new FieldLineageCatalogEntry(
                        "workforce.leaves.observacao_sem_governanca",
                        "concept:hr:unclassified-note",
                        "schema://human-resources.afastamentos/ResponseDTO",
                        "observacaoSemGovernanca",
                        "READ_PROJECTION",
                        "UNCLASSIFIED",
                        "ALLOWED",
                        true,
                        Set.of(FieldUseCategory.VALUE),
                        List.of(),
                        false // P57: explicitGovernanceDeclared = false -> must fail closed for AI!
                ),
                new FieldLineageCatalogEntry(
                        "workforce.leaves.derivado_ancestral_inexistente",
                        "concept:hr:dangling-parent",
                        "schema://human-resources.afastamentos/ResponseDTO",
                        "derivadoAncestralInexistente",
                        "READ_PROJECTION",
                        "OPERATIONAL_INTERNAL",
                        "ALLOWED",
                        true,
                        Set.of(FieldUseCategory.VALUE),
                        List.of("workforce.leaves.ancestral_fantasma"), // P45/P56/P60: dangling upstream parent -> fail closed!
                        true
                )
        );

        MethodBindingAdmissionRecord enrichedRecord = new MethodBindingAdmissionRecord(
                baseRecord.serviceKey(),
                baseRecord.decisionPoint(),
                baseRecord.enforcementBinding(),
                baseRecord.admittedChannels(),
                true,
                enrichedLineage
        );

        List<SanitizedDecisionTelemetryEvent> sinkEvents = new ArrayList<>();
        AuthorizationTelemetrySinkPort failingSink = event -> {
            throw new IllegalStateException("Simulated telemetry exporter outage");
        };
        AuthorizationTelemetrySinkPort healthySink = sinkEvents::add;

        contextRunner
                .withBean(OpaClientTransport.class, blueprint::localOpaTransport)
                .withBean(HostRuntimePolicyCoordinates.class, blueprint::coordinates)
                .withBean(MethodBindingAdmissionRecord.class, () -> enrichedRecord)
                .withBean("failingTelemetrySink", AuthorizationTelemetrySinkPort.class, () -> failingSink)
                .withBean("healthyTelemetrySink", AuthorizationTelemetrySinkPort.class, () -> healthySink)
                .run(context -> {
                    DeclarativeDecisionPointExecutionTemplate template =
                            context.getBean(DeclarativeDecisionPointExecutionTemplate.class);
                    GovernedExportAndAiToolAuthorizationSeam exportAiSeam =
                            context.getBean(GovernedExportAndAiToolAuthorizationSeam.class);
                    SanitizedAuthorizationTelemetryPublisher telemetryPublisher =
                            context.getBean(SanitizedAuthorizationTelemetryPublisher.class);
                    InMemoryTransactionalAuditOutbox outbox =
                            (InMemoryTransactionalAuditOutbox) context.getBean(TransactionalAuditOutboxPort.class);

                    List<DtoFieldSchemaMetadata> fieldSchemas = List.of(
                            new DtoFieldSchemaMetadata("lotacaoSetorId", "workforce.leaves.lotacao_setor_id", FactValueType.INT64, false),
                            new DtoFieldSchemaMetadata("cidCodigo", "workforce.leaves.cid_codigo", FactValueType.STRING, true),
                            new DtoFieldSchemaMetadata("cidResumoDerivado", "workforce.leaves.cid_resumo_derivado", FactValueType.STRING, true),
                            new DtoFieldSchemaMetadata("substitutoServidorId", "workforce.leaves.substituto_servidor_id", FactValueType.INT64, true),
                            new DtoFieldSchemaMetadata("observacaoSemGovernanca", "workforce.leaves.observacao_sem_governanca", FactValueType.STRING, true),
                            new DtoFieldSchemaMetadata("derivadoAncestralInexistente", "workforce.leaves.derivado_ancestral_inexistente", FactValueType.STRING, true),
                            new DtoFieldSchemaMetadata("campoNaoCatalogado", "workforce.leaves.campo_nao_catalogado", FactValueType.STRING, true)
                    );

                    Map<String, Object> row1 = Map.of(
                            "lotacaoSetorId", 100L,
                            "cidCodigo", "F32.1-SECRET-HEALTH-CODE",
                            "cidResumoDerivado", "DERIVED-F32.1-SECRET",
                            "substitutoServidorId", 7777L,
                            "observacaoSemGovernanca", "UNCLASSIFIED-INTERNAL-NOTE",
                            "derivadoAncestralInexistente", "DANGLING-LINEAGE-VALUE",
                            "campoNaoCatalogado", "UNMAPPED-DTO-FIELD-VALUE"
                    );
                    Map<String, Object> row2 = Map.of(
                            "lotacaoSetorId", 100L,
                            "cidCodigo", "J01.9-SECRET-HEALTH-CODE",
                            "cidResumoDerivado", "DERIVED-J01.9-SECRET",
                            "substitutoServidorId", 8888L,
                            "observacaoSemGovernanca", "UNCLASSIFIED-INTERNAL-NOTE-2",
                            "derivadoAncestralInexistente", "DANGLING-LINEAGE-VALUE-2",
                            "campoNaoCatalogado", "UNMAPPED-DTO-FIELD-VALUE-2"
                    );

                    OpaRuntimeHead activeHead = blueprint.bundleArtifact().runtimeHead();

                    // 1. Governed CSV Export via DeclarativeDecisionPointExecutionTemplate (P9-R01, P9-R02, P9-R04):
                    // Suppresses cidCodigo (exportable=false), cidResumoDerivado (inherited exportable=false per P56/P60),
                    // and derivadoAncestralInexistente (dangling ancestor per P45/P56), while deduplicating outbox obligations across 2 rows!
                    SanitizedExportArtifact csvArtifact = template.exportCollectionByPointKey(
                            pointKey,
                            "tenant-gov-br",
                            "prod",
                            ExportFormat.CSV,
                            () -> activeHead,
                            fieldSchemas,
                            List.of(row1, row2),
                            r -> Map.of(
                                    "subject.principalId", "usr-gestor-101",
                                    "subject.organizationUnitIds", List.of(100L),
                                    "resource.lotacaoSetorId", r.get("lotacaoSetorId"),
                                    "resource.cidCodigo", r.get("cidCodigo")
                            ),
                            Map.of()
                    );
                    assertEquals(
                            List.of("lotacaoSetorId", "substitutoServidorId", "observacaoSemGovernanca", "campoNaoCatalogado"),
                            csvArtifact.exportedColumns()
                    );
                    String csvText = new String(csvArtifact.bytes(), StandardCharsets.UTF_8);
                    assertFalse(csvText.contains("F32.1-SECRET-HEALTH-CODE"));
                    assertFalse(csvText.contains("DERIVED-F32.1-SECRET"));
                    assertFalse(csvText.contains("DANGLING-LINEAGE-VALUE"));
                    assertFalse(csvText.contains("cidCodigo"));
                    assertTrue(csvText.contains("7777"));
                    assertTrue(csvText.contains("8888"));
                    // P9-R01: 2 exported rows produce exactly 1 deduplicated BEFORE_COMMIT_OUTBOX entry with exportedRowCount=2
                    assertEquals(1, outbox.listEntries().size());
                    assertEquals(2, outbox.listEntries().getFirst().obligationParameters().get("exportedRowCount"));

                    // 2. P17 & P18 (P9-R01): Export fails closed if initialHead revision differs from row evaluation revision or is revoked
                    OpaRuntimeHead driftedHead = new OpaRuntimeHead(
                            activeHead.instanceId(),
                            "rev-drifted-999",
                            activeHead.headEtag(),
                            activeHead.activationRevision(),
                            "sha256:0000000000000000000000000000000000000000000000000000000000000000",
                            activeHead.bundleArtifactDigest(),
                            activeHead.compilerProfileVersion(),
                            activeHead.opaCapabilitiesDigest()
                    );
                    SecurityException driftEx = assertThrows(SecurityException.class, () ->
                            exportAiSeam.authorizeAndExecuteCollectionExportByPointKey(
                                    pointKey,
                                    "tenant-gov-br",
                                    "prod",
                                    ExportFormat.JSON,
                                    () -> driftedHead, // head revision differs from OPA evaluation revision!
                                    fieldSchemas,
                                    List.of(row1),
                                    r -> Map.of("subject.principalId", "usr-gestor-101", "subject.organizationUnitIds", List.of(100L), "resource.lotacaoSetorId", 100L),
                                    Map.of()
                            )
                    );
                    assertTrue(driftEx.getMessage().contains("AUTHZ_EXPORT_ROW_REVISION_DRIFT"));

                    // 3. Governed AI Tool Payload Projection via DeclarativeDecisionPointExecutionTemplate (P11, P47, P56, P57, P62):
                    // Suppresses cidCodigo (DENIED), cidResumoDerivado (inherited DENIED per P56),
                    // substitutoServidorId (SCHEMA_METADATA_ONLY per P62), observacaoSemGovernanca (explicitGovernanceDeclared=false per P57),
                    // derivadoAncestralInexistente (dangling parent per P45/P56), and campoNaoCatalogado (unmapped DTO field per P47/P57)!
                    SanitizedAiToolProjection aiProjection = template.projectAiToolPayloadByPointKey(
                            pointKey,
                            "tenant-gov-br",
                            "prod",
                            row1,
                            fieldSchemas,
                            Map.of(
                                    "subject.principalId", "usr-gestor-101",
                                    "subject.organizationUnitIds", List.of(100L),
                                    "resource.lotacaoSetorId", 100L,
                                    "resource.cidCodigo", "F32.1-SECRET-HEALTH-CODE"
                            ),
                            Map.of()
                    );
                    assertEquals(List.of("lotacaoSetorId"), aiProjection.allowedWireColumns());
                    assertEquals(Map.of("lotacaoSetorId", 100L), aiProjection.detachedPayload());
                    assertTrue(aiProjection.suppressedAiAttributeIds().containsAll(Set.of(
                            "workforce.leaves.cid_codigo",
                            "workforce.leaves.cid_resumo_derivado",
                            "workforce.leaves.substituto_servidor_id",
                            "workforce.leaves.observacao_sem_governanca",
                            "workforce.leaves.derivado_ancestral_inexistente",
                            "workforce.leaves.campo_nao_catalogado"
                    )));

                    // 4. P62: Metadata-only governance inspection for AI authoring succeeds for authorized catalog reader without exposing values
                    List<AiGovernanceMetadataView> metadataViews = template.inspectAiGovernanceMetadataByPointKey(
                            pointKey,
                            "usr-ai-author",
                            Set.of("praxis:authz:pap:catalog:read"),
                            Set.of("tenant-gov-br"),
                            "tenant-gov-br",
                            "praxis:authz:pap:catalog:read"
                    );
                    assertEquals(6, metadataViews.size());
                    assertThrows(SecurityException.class, () ->
                            template.inspectAiGovernanceMetadataByPointKey(
                                    pointKey,
                                    "usr-ai-author",
                                    Set.of("praxis:authz:pap:catalog:read"),
                                    Set.of("other-tenant"),
                                    "tenant-gov-br",
                                    "praxis:authz:pap:catalog:read"
                            )
                    );

                    // 5. P21 & P9-R03: SanitizedAuthorizationTelemetryPublisher isolates failing sink and records zero raw sensitive values
                    assertEquals(4, sinkEvents.size());
                    assertEquals(4, telemetryPublisher.failedSinkDeliveriesCount());
                    assertEquals(4, telemetryPublisher.recentEvents(10).size());
                    String telemetryJson = telemetryPublisher.toStructuredJsonLog(sinkEvents.getFirst());
                    assertTrue(telemetryJson.contains(pointKey));
                    assertTrue(telemetryJson.contains("workforce.leaves.cid_codigo"));
                    assertTrue(telemetryJson.contains("DURABLE_AUDIT_EVIDENCE"));
                    assertFalse(telemetryJson.contains("F32.1-SECRET-HEALTH-CODE"));
                    assertFalse(telemetryJson.contains("***CID-RESTRITO***"));
                    assertFalse(telemetryJson.contains("UNCLASSIFIED-INTERNAL-NOTE"));
                });
    }
}
