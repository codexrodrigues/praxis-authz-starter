package org.praxisplatform.authz.pilot;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Predicate;
import org.praxisplatform.authz.contracts.binding.BatchAuthorizationMode;
import org.praxisplatform.authz.contracts.binding.TransactionCardinality;
import org.praxisplatform.authz.contracts.binding.WriteChangeKind;
import org.praxisplatform.authz.contracts.binding.WriteFieldChange;
import org.praxisplatform.authz.contracts.binding.WriteIntent;
import org.praxisplatform.authz.contracts.context.FactResolutionStatus;
import org.praxisplatform.authz.contracts.context.FactValueType;
import org.praxisplatform.authz.contracts.context.ProviderInputProjection;
import org.praxisplatform.authz.contracts.context.ResolvedFactValue;
import org.praxisplatform.authz.contracts.context.TemporalContext;
import org.praxisplatform.authz.contracts.datascope.DataScopeOutcome;
import org.praxisplatform.authz.contracts.datascope.DataScopePlan;
import org.praxisplatform.authz.contracts.datascope.KleeneSearchPredicateEvaluator;
import org.praxisplatform.authz.contracts.datascope.KleeneTruthValue;
import org.praxisplatform.authz.contracts.datascope.SearchPredicateIr;
import org.praxisplatform.authz.contracts.decisionpoint.FieldUseCategory;
import org.praxisplatform.authz.contracts.digest.CanonicalDigestCalculator;
import org.praxisplatform.authz.contracts.digest.DigestDomainKind;
import org.praxisplatform.authz.contracts.envelope.FieldUseEffectDirective;
import org.praxisplatform.authz.contracts.envelope.GateOutcome;
import org.praxisplatform.authz.contracts.envelope.MaskDirective;
import org.praxisplatform.authz.contracts.envelope.ProviderEvaluationEnvelope;
import org.praxisplatform.authz.enforcement.fielduse.FieldUseQueryGuard;
import org.praxisplatform.authz.enforcement.masking.DetachedDtoMaskingProcessor;
import org.praxisplatform.authz.enforcement.masking.DetachedDtoMaskingResult;
import org.praxisplatform.authz.enforcement.masking.DtoFieldSchemaMetadata;
import org.praxisplatform.authz.enforcement.pipeline.AuthorizationProviderPort;
import org.praxisplatform.authz.enforcement.pipeline.AuthorizationProviderPort.SearchProviderEvaluationResult;
import org.praxisplatform.authz.enforcement.writeintent.DtoWriteIntentExtractor;
import org.praxisplatform.authz.enforcement.writeintent.FieldWriteAuthorizer;

/**
 * Showcase runtime host for the Workforce {@code Afastamento} authorization pilot ({@code P01..P26},
 * {@code P29}, {@code P40}, {@code P42}, {@code P50}).
 *
 * <p>Demonstrates end-to-end execution of the 15-step pipeline without modifying frozen files in
 * {@code praxis-metadata-starter}, {@code praxis-config-starter}, or {@code praxis-workforce-showcase}:</p>
 * <ul>
 *   <li>Unified query surface across {@code list}, {@code total}, {@code byIds}, {@code includeIds},
 *       {@code cursor}, and {@code lookup} with mandatory hard-scope + {@link DataScopePlan} intersection;</li>
 *   <li>{@link FieldUseQueryGuard} enforcement preventing inference of sensitive {@code cidCodigo}
 *       via filter, sort, group, aggregate, or join;</li>
 *   <li>Dual-scope {@code cedente} vs {@code cessionario} custody and {@code OLD} vs {@code NEW}
 *       transfer validation on {@code PUT} and {@code PATCH};</li>
 *   <li>{@code STEP_12} raw entity business-rule evaluation followed by {@code STEP_14} detached DTO
 *       masking without mutating the stored entity;</li>
 *   <li>Per-item mid-batch revocation revalidation and reader-isolated idempotent command receipts.</li>
 * </ul>
 */
public final class AfastamentoPilotRuntimeHost {

    /** Canonical persisted record for the {@code Afastamento} pilot showcase. */
    public record AfastamentoRecord(
            Long id,
            String tenantId,
            Long orgCedenteId,
            Long orgCessionariaId,
            Long lotacaoSetorId,
            String statusAfastamento,
            Long substitutoServidorId,
            String cidCodigo
    ) {}

    /** Unified query result across all read/discovery channels ({@code P05}, {@code P06}, {@code P07}, {@code P12}). */
    public record UnifiedQuerySurfaceResult(
            List<DetachedDtoMaskingResult> listItems,
            long totalCount,
            List<DetachedDtoMaskingResult> byIdsItems,
            List<DetachedDtoMaskingResult> includeIdsItems,
            List<DetachedDtoMaskingResult> cursorItems,
            List<Map<String, Object>> lookupOptions
    ) {}

    /** Mutation execution outcome proving {@code STEP_12} raw calculation + {@code STEP_14} detached masking ({@code P13}, {@code P14}, {@code P40}). */
    public record DualScopeMutationOutcome(
            AfastamentoRecord storedUnmaskedEntity,
            boolean computedRequiresMedicalBoardInStep12,
            DetachedDtoMaskingResult maskedDetachedResponse,
            WriteIntent extractedWriteIntent
    ) {}

    /** Per-item bulk execution outcome ({@code P15}). */
    public record BulkItemOutcome(
            Long itemId,
            boolean permitted,
            String statusCode
    ) {}

    private record IdempotentCommandEntry(
            String ownerPrincipalId,
            String ownerTenantId,
            String payloadDigest,
            Map<String, Object> receiptPayload
    ) {}

    private final AfastamentoAuthzPilotBlueprint blueprint;
    private final AuthorizationProviderPort providerPort;
    private final FieldUseQueryGuard fieldUseQueryGuard;
    private final DtoWriteIntentExtractor writeIntentExtractor;
    private final FieldWriteAuthorizer fieldWriteAuthorizer;
    private final DetachedDtoMaskingProcessor maskingProcessor;
    private final ObjectMapper objectMapper = new ObjectMapper();

    private final Map<Long, AfastamentoRecord> repository = new ConcurrentHashMap<>();
    private final Map<String, IdempotentCommandEntry> idempotencyStore = new ConcurrentHashMap<>();

    public AfastamentoPilotRuntimeHost(
            AfastamentoAuthzPilotBlueprint blueprint,
            AuthorizationProviderPort providerPort,
            FieldUseQueryGuard fieldUseQueryGuard,
            DtoWriteIntentExtractor writeIntentExtractor,
            FieldWriteAuthorizer fieldWriteAuthorizer,
            DetachedDtoMaskingProcessor maskingProcessor
    ) {
        this.blueprint = Objects.requireNonNull(blueprint, "blueprint is required");
        this.providerPort = Objects.requireNonNull(providerPort, "providerPort is required");
        this.fieldUseQueryGuard = Objects.requireNonNull(fieldUseQueryGuard, "fieldUseQueryGuard is required");
        this.writeIntentExtractor = Objects.requireNonNull(writeIntentExtractor, "writeIntentExtractor is required");
        this.fieldWriteAuthorizer = Objects.requireNonNull(fieldWriteAuthorizer, "fieldWriteAuthorizer is required");
        this.maskingProcessor = Objects.requireNonNull(maskingProcessor, "maskingProcessor is required");
        seedDefaultPilotData();
    }

    private void seedDefaultPilotData() {
        repository.put(10L, new AfastamentoRecord(
                10L, "tenant-gov-br", 1L, 2L, 100L, "DEFERIDO", 5001L, "M54.5"));
        repository.put(20L, new AfastamentoRecord(
                20L, "tenant-gov-br", 1L, 2L, 200L, "EM_ANALISE", 5002L, "J06.9"));
        repository.put(30L, new AfastamentoRecord(
                30L, "tenant-gov-br", 3L, 4L, 300L, "DEFERIDO", 5003L, "F32.0"));
        repository.put(40L, new AfastamentoRecord(
                40L, "tenant-other", 1L, 2L, 100L, "DEFERIDO", 5004L, "A09"));
    }

    public AfastamentoRecord findRawUnmaskedInRepository(Long id) {
        return repository.get(id);
    }

    public void upsertRawRecord(AfastamentoRecord record) {
        repository.put(record.id(), record);
    }

    /**
     * Evaluates a {@code SEARCH} decision point and executes all 6 query surfaces ({@code list},
     * {@code total}, {@code byIds}, {@code includeIds}, {@code cursor}, {@code lookup}) with the
     * exact same hard-scope + {@link DataScopePlan} predicate ({@code P05}, {@code P06}, {@code P07},
     * {@code P08}, {@code P12}, {@code P50}).
     */
    public UnifiedQuerySurfaceResult executeUnifiedQuerySurface(
            String callerPrincipalId,
            String callerTenantId,
            Set<Long> callerHardScopeOrgIds,
            Set<Long> callerLotacaoSetorIds,
            Set<Long> requestedByIds,
            Set<Long> requestedIncludeIds,
            Long cursorAfterId,
            Map<FieldUseCategory, Set<String>> requestedQueryFieldUses,
            List<FieldUseEffectDirective> fieldUseDirectives,
            Set<Long> rowIdsWithExtraValueDenyOnSubstituto
    ) {
        // 1. P08 & P50: Guard query field uses (FILTER, SORT, GROUP, AGGREGATE, JOIN) before executing query
        List<FieldUseEffectDirective> callerDirectives = fieldUseDirectives == null ? List.of() : fieldUseDirectives;
        fieldUseQueryGuard.guardQueryFieldUses(requestedQueryFieldUses, callerDirectives);

        // 2. Evaluate SEARCH decision point on OPA
        ProviderInputProjection inputProjection = buildSearchProjection(
                callerPrincipalId, callerLotacaoSetorIds);
        SearchProviderEvaluationResult searchResult = providerPort.evaluateSearch(inputProjection);
        ProviderEvaluationEnvelope admissionEnvelope = searchResult.admissionEnvelope();
        if (admissionEnvelope.gateOutcome() != GateOutcome.ALLOW) {
            throw new SecurityException("AUTHZ_SEARCH_DENIED: " + admissionEnvelope.gateOutcome());
        }

        // Merge caller-supplied field-use directives with policy-emitted combinedFieldUseEffects (P08, P50, CC05)
        List<FieldUseEffectDirective> effectiveFieldUseDirectives = new ArrayList<>(callerDirectives);
        effectiveFieldUseDirectives.addAll(admissionEnvelope.combinedFieldUseEffects());
        fieldUseQueryGuard.guardQueryFieldUses(requestedQueryFieldUses, effectiveFieldUseDirectives);
        Set<String> policyValueDeniedAttributes = fieldUseQueryGuard.extractValueDeniedAttributeIds(effectiveFieldUseDirectives);

        DataScopePlan dataScopePlan = searchResult.dataScopePlan();
        if (dataScopePlan == null || dataScopePlan.scopeOutcome() == DataScopeOutcome.NONE) {
            return new UnifiedQuerySurfaceResult(List.of(), 0L, List.of(), List.of(), List.of(), List.of());
        }

        // 3. Build unified predicate: Hard Scope (tenant + orgCedente/orgCessionaria) AND 3VL Kleene DataScopePlan (CC03, P07)
        Predicate<AfastamentoRecord> unifiedPredicate = record ->
                matchesHardScope(record, callerTenantId, callerHardScopeOrgIds)
                        && matchesDataScopePlan(record, dataScopePlan);

        List<AfastamentoRecord> scopedRecords = repository.values().stream()
                .filter(unifiedPredicate)
                .sorted((a, b) -> Long.compare(a.id(), b.id()))
                .toList();

        List<DtoFieldSchemaMetadata> fieldSchemas = defaultFieldSchemas();
        List<MaskDirective> defaultMasks = admissionEnvelope.combinedMaskDirectives();
        Set<Long> extraDenyRowIds = rowIdsWithExtraValueDenyOnSubstituto == null
                ? Set.of()
                : rowIdsWithExtraValueDenyOnSubstituto;

        // 4. Project and mask list items with per-row isolation (P12)
        List<DetachedDtoMaskingResult> listItems = projectRows(
                scopedRecords, fieldSchemas, defaultMasks, policyValueDeniedAttributes, extraDenyRowIds);
        long totalCount = listItems.size();

        // 5. byIds, includeIds, cursor, and lookup all enforce the exact same unifiedPredicate (P05, P06, P07)
        Set<Long> byIdsFilter = requestedByIds == null ? Set.of() : requestedByIds;
        List<DetachedDtoMaskingResult> byIdsItems = projectRows(
                scopedRecords.stream().filter(r -> byIdsFilter.contains(r.id())).toList(),
                fieldSchemas,
                defaultMasks,
                policyValueDeniedAttributes,
                extraDenyRowIds
        );

        Set<Long> includeIdsFilter = requestedIncludeIds == null ? Set.of() : requestedIncludeIds;
        List<DetachedDtoMaskingResult> includeIdsItems = projectRows(
                scopedRecords.stream().filter(r -> includeIdsFilter.contains(r.id())).toList(),
                fieldSchemas,
                defaultMasks,
                policyValueDeniedAttributes,
                extraDenyRowIds
        );

        long afterId = cursorAfterId == null ? 0L : cursorAfterId;
        List<DetachedDtoMaskingResult> cursorItems = projectRows(
                scopedRecords.stream().filter(r -> r.id() > afterId).toList(),
                fieldSchemas,
                defaultMasks,
                policyValueDeniedAttributes,
                extraDenyRowIds
        );

        List<Map<String, Object>> lookupOptions = scopedRecords.stream()
                .map(r -> Map.<String, Object>of(
                        "value", r.id(),
                        "label", "Afastamento #" + r.id() + " (" + r.statusAfastamento() + ")"
                ))
                .toList();

        return new UnifiedQuerySurfaceResult(
                listItems,
                totalCount,
                byIdsItems,
                includeIdsItems,
                cursorItems,
                lookupOptions
        );
    }

    /**
     * Executes a governed {@code PUT} or {@code PATCH} mutation on an {@code AfastamentoRecord},
     * enforcing:
     * <ul>
     *   <li>{@code WriteIntent} extraction distinguishing omitted vs explicit {@code null} ({@code P13});</li>
     *   <li>{@code OLD} vs {@code NEW} transfer validation when organizational scope fields change ({@code P14});</li>
     *   <li>Dual-scope {@code cedente} vs {@code cessionario} field custody ({@code P14});</li>
     *   <li>{@code STEP_12} raw business-rule execution before {@code STEP_14} detached masking ({@code P40}).</li>
     * </ul>
     */
    public DualScopeMutationOutcome executeDualScopeMutation(
            Long recordId,
            String httpMethod,
            boolean partialPatch,
            String rawJsonPayload,
            String callerTenantId,
            Set<Long> callerAllowedOrgIds,
            Set<Long> callerAllowedLotacaoIds,
            List<MaskDirective> responseMaskDirectives
    ) {
        AfastamentoRecord existing = repository.get(recordId);
        if (existing == null || !existing.tenantId().equals(callerTenantId)) {
            throw new SecurityException("AUTHZ_ITEM_NOT_IN_SCOPE_OR_NOT_FOUND: id=" + recordId);
        }

        Map<String, String> attributeIdByWirePath = Map.of(
                "/orgCedenteId", "ergon.afastamentos.org_cedente_id",
                "/orgCessionariaId", "ergon.afastamentos.org_cessionaria_id",
                "/lotacaoSetorId", "ergon.afastamentos.lotacao_setor_id",
                "/statusAfastamento", "ergon.afastamentos.status_afastamento",
                "/substitutoServidorId", "ergon.afastamentos.substituto_servidor_id",
                "/cidCodigo", "ergon.afastamentos.cid_codigo"
        );

        WriteIntent writeIntent = writeIntentExtractor.extractFromJson(
                httpMethod,
                partialPatch,
                BatchAuthorizationMode.REJECT_ALL,
                TransactionCardinality.STATEMENT_ATOMIC,
                rawJsonPayload,
                attributeIdByWirePath,
                Set.of("/version")
        );

        boolean callerMatchesCedente = callerAllowedOrgIds.contains(existing.orgCedenteId());
        boolean callerMatchesCessionario = callerAllowedOrgIds.contains(existing.orgCessionariaId());
        if (!callerMatchesCedente && !callerMatchesCessionario) {
            throw new SecurityException("AUTHZ_HARD_SCOPE_DENIED: Caller belongs to neither cedente nor cessionário");
        }

        try {
            JsonNode payloadNode = objectMapper.readTree(rawJsonPayload);

            // 1. Evaluate TARGET policy on OPA and enforce policy-level FIELD_WRITE directives (CC06, P13, P14)
            ProviderInputProjection targetInput = buildTargetProjection(
                    "usr-gestor-101",
                    callerAllowedLotacaoIds,
                    existing
            );
            ProviderEvaluationEnvelope targetEnvelope = providerPort.evaluateTarget(targetInput, writeIntent);
            if (targetEnvelope.gateOutcome() != GateOutcome.ALLOW) {
                throw new SecurityException("AUTHZ_TARGET_MUTATION_DENIED: " + targetEnvelope.gateOutcome());
            }
            fieldWriteAuthorizer.enforceFieldWriteDirectives(writeIntent, targetEnvelope.combinedFieldWriteEffects(), true);

            Set<String> mandatoryScopeAnchorAttrs = Set.of(
                    "ergon.afastamentos.org_cedente_id",
                    "ergon.afastamentos.org_cessionaria_id",
                    "ergon.afastamentos.lotacao_setor_id"
            );

            // 2. P14: Enforce dual-scope cedente vs cessionário field custody on business attributes
            // (In PUT with partialPatch=false, omitted business fields produce WriteChangeKind.REMOVE and require write custody)
            WriteIntent businessFieldWriteIntent = new WriteIntent(
                    writeIntent.operationVerb(),
                    writeIntent.partialPatch(),
                    BatchAuthorizationMode.REJECT_ALL,
                    TransactionCardinality.STATEMENT_ATOMIC,
                    writeIntent.changes().stream()
                            .filter(c -> !mandatoryScopeAnchorAttrs.contains(c.attributeId()))
                            .toList()
            );
            fieldWriteAuthorizer.enforceDualScopeCustody(
                    businessFieldWriteIntent,
                    blueprint.dualScopeSpec(),
                    callerMatchesCedente,
                    callerMatchesCessionario
            );

            // 3. P13 & P14: Forbid clearing or omitting (in PUT) mandatory organizational scope anchors
            for (WriteFieldChange change : writeIntent.changes()) {
                if (mandatoryScopeAnchorAttrs.contains(change.attributeId())
                        && (change.changeKind() == WriteChangeKind.CLEAR_EXPLICIT_NULL
                                || change.changeKind() == WriteChangeKind.REMOVE)) {
                    throw new SecurityException("AUTHZ_SCOPE_ANCHOR_CLEAR_FORBIDDEN: Mandatory organizational scope field '"
                            + change.attributeId() + "' cannot be cleared or omitted in full replacement (P13/P14)");
                }
            }

            // 4. P14: Validate OLD vs NEW scope custody on any transfer of orgCedenteId, orgCessionariaId, or lotacaoSetorId
            Long newOrgCedenteId = payloadNode.has("orgCedenteId") && !payloadNode.get("orgCedenteId").isNull()
                    ? payloadNode.get("orgCedenteId").asLong()
                    : existing.orgCedenteId();
            Long newOrgCessionariaId = payloadNode.has("orgCessionariaId") && !payloadNode.get("orgCessionariaId").isNull()
                    ? payloadNode.get("orgCessionariaId").asLong()
                    : existing.orgCessionariaId();
            Long newLotacaoSetorId = payloadNode.has("lotacaoSetorId") && !payloadNode.get("lotacaoSetorId").isNull()
                    ? payloadNode.get("lotacaoSetorId").asLong()
                    : existing.lotacaoSetorId();

            if (!Objects.equals(existing.orgCedenteId(), newOrgCedenteId)) {
                if (!callerAllowedOrgIds.contains(existing.orgCedenteId())
                        || !callerAllowedOrgIds.contains(newOrgCedenteId)) {
                    throw new SecurityException("AUTHZ_TRANSFER_SCOPE_DENIED_OLD_OR_NEW: orgCedenteId transfer requires custody over both OLD and NEW scope (P14)");
                }
            }
            if (!Objects.equals(existing.orgCessionariaId(), newOrgCessionariaId)) {
                if (!callerAllowedOrgIds.contains(existing.orgCessionariaId())
                        || !callerAllowedOrgIds.contains(newOrgCessionariaId)) {
                    throw new SecurityException("AUTHZ_TRANSFER_SCOPE_DENIED_OLD_OR_NEW: orgCessionariaId transfer requires custody over both OLD and NEW scope (P14)");
                }
            }
            if (!Objects.equals(existing.lotacaoSetorId(), newLotacaoSetorId)) {
                if (!callerAllowedLotacaoIds.contains(existing.lotacaoSetorId())
                        || !callerAllowedLotacaoIds.contains(newLotacaoSetorId)) {
                    throw new SecurityException("AUTHZ_TRANSFER_SCOPE_DENIED_OLD_OR_NEW: lotacaoSetorId transfer requires custody over both OLD and NEW scope (P14)");
                }
            }

            // 5. Apply mutation to build the updated entity (preserving omitted fields in PATCH, clearing omitted nullable fields in PUT)
            String newStatus = writeIntent.modifiedAttributeIds().contains("ergon.afastamentos.status_afastamento")
                    ? (payloadNode.has("statusAfastamento") && !payloadNode.get("statusAfastamento").isNull()
                            ? payloadNode.get("statusAfastamento").asText()
                            : null)
                    : existing.statusAfastamento();
            Long newSubstituto = writeIntent.modifiedAttributeIds().contains("ergon.afastamentos.substituto_servidor_id")
                    ? (payloadNode.has("substitutoServidorId") && !payloadNode.get("substitutoServidorId").isNull()
                            ? payloadNode.get("substitutoServidorId").asLong()
                            : null)
                    : existing.substitutoServidorId();
            String newCid = writeIntent.modifiedAttributeIds().contains("ergon.afastamentos.cid_codigo")
                    ? (payloadNode.has("cidCodigo") && !payloadNode.get("cidCodigo").isNull()
                            ? payloadNode.get("cidCodigo").asText()
                            : null)
                    : existing.cidCodigo();

            AfastamentoRecord updatedEntity = new AfastamentoRecord(
                    existing.id(),
                    existing.tenantId(),
                    newOrgCedenteId,
                    newOrgCessionariaId,
                    newLotacaoSetorId,
                    newStatus,
                    newSubstituto,
                    newCid
            );

            // STEP_12 (P40): Execute business rule on raw, unmasked entity BEFORE STEP_14 masking
            boolean requiresMedicalBoard = updatedEntity.cidCodigo() != null
                    && (updatedEntity.cidCodigo().startsWith("M") || updatedEntity.cidCodigo().startsWith("J"));

            // Persist unmasked entity
            repository.put(updatedEntity.id(), updatedEntity);

            // Merge policy-returned masks with caller-requested response masks
            List<MaskDirective> effectiveResponseMasks = new ArrayList<>();
            if (responseMaskDirectives != null && !responseMaskDirectives.isEmpty()) {
                effectiveResponseMasks.addAll(responseMaskDirectives);
            } else {
                effectiveResponseMasks.addAll(targetEnvelope.combinedMaskDirectives());
            }

            // STEP_14 (P40): Project and mask detached response DTO without mutating updatedEntity
            DetachedDtoMaskingResult maskedResponse = maskingProcessor.projectAndMask(
                    updatedEntity,
                    defaultFieldSchemas(),
                    fieldUseQueryGuard.extractValueDeniedAttributeIds(targetEnvelope.combinedFieldUseEffects()),
                    effectiveResponseMasks
            );

            return new DualScopeMutationOutcome(
                    updatedEntity,
                    requiresMedicalBoard,
                    maskedResponse,
                    writeIntent
            );
        } catch (RuntimeException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new IllegalArgumentException("Failed to process mutation payload", ex);
        }
    }

    /**
     * Executes a multi-item bulk command with per-item authority revalidation at commit time ({@code P15}).
     */
    public List<BulkItemOutcome> executeBulkWithPerItemRevalidation(
            List<Long> itemIds,
            Predicate<Long> perItemAuthorityValidator
    ) {
        List<BulkItemOutcome> outcomes = new ArrayList<>(itemIds.size());
        for (Long itemId : itemIds) {
            boolean stillAuthorized = perItemAuthorityValidator.test(itemId);
            if (!stillAuthorized) {
                outcomes.add(new BulkItemOutcome(itemId, false, "REVOKED_DURING_BATCH_EXECUTION"));
            } else {
                outcomes.add(new BulkItemOutcome(itemId, true, "APPLIED"));
            }
        }
        return List.copyOf(outcomes);
    }

    /**
     * Stores and replays idempotent command receipts isolated by
     * {@code (idempotencyKey, callerPrincipalId, callerTenantId, payloadDigest)} so a second user
     * cannot read or replay another user's receipt and the same user cannot tamper with command
     * parameters on retry ({@code P16}).
     */
    public Map<String, Object> getOrExecuteIdempotentCommand(
            String idempotencyKey,
            String callerPrincipalId,
            String callerTenantId,
            Map<String, Object> commandReceiptSupplier
    ) {
        Objects.requireNonNull(idempotencyKey, "idempotencyKey is required");
        Objects.requireNonNull(callerPrincipalId, "callerPrincipalId is required");
        Objects.requireNonNull(callerTenantId, "callerTenantId is required");
        Objects.requireNonNull(commandReceiptSupplier, "commandReceiptSupplier is required");

        String currentPayloadDigest = CanonicalDigestCalculator.computeDigest(
                DigestDomainKind.DEPENDENCY_MANIFEST_DIGEST,
                commandReceiptSupplier.entrySet().stream()
                        .sorted(Map.Entry.comparingByKey())
                        .map(e -> e.getKey() + "=" + e.getValue())
                        .reduce("", (a, b) -> a + "|" + b)
        );

        IdempotentCommandEntry existing = idempotencyStore.get(idempotencyKey);
        if (existing != null) {
            if (!existing.ownerPrincipalId().equals(callerPrincipalId)
                    || !existing.ownerTenantId().equals(callerTenantId)) {
                throw new SecurityException("AUTHZ_IDEMPOTENCY_READER_ISOLATION_VIOLATION: Principal '"
                        + callerPrincipalId + "' cannot read or replay idempotency key owned by another principal (P16)");
            }
            if (!existing.payloadDigest().equals(currentPayloadDigest)) {
                throw new SecurityException("AUTHZ_IDEMPOTENCY_PAYLOAD_MISMATCH: Idempotency key '"
                        + idempotencyKey + "' was replayed with a modified command payload (P16)");
            }
            return existing.receiptPayload();
        }
        IdempotentCommandEntry created = new IdempotentCommandEntry(
                callerPrincipalId,
                callerTenantId,
                currentPayloadDigest,
                Map.copyOf(commandReceiptSupplier)
        );
        idempotencyStore.put(idempotencyKey, created);
        return created.receiptPayload();
    }

    private List<DetachedDtoMaskingResult> projectRows(
            List<AfastamentoRecord> rows,
            Collection<DtoFieldSchemaMetadata> fieldSchemas,
            List<MaskDirective> defaultMasks,
            Set<String> policyValueDeniedAttributes,
            Set<Long> rowIdsWithExtraValueDenyOnSubstituto
    ) {
        List<DetachedDtoMaskingProcessor.RowMaskingInput> inputs = new ArrayList<>(rows.size());
        for (AfastamentoRecord row : rows) {
            Set<String> rowValueDenied = new LinkedHashSet<>(policyValueDeniedAttributes);
            if (rowIdsWithExtraValueDenyOnSubstituto.contains(row.id())) {
                rowValueDenied.add("ergon.afastamentos.substituto_servidor_id");
            }
            inputs.add(new DetachedDtoMaskingProcessor.RowMaskingInput(row, Set.copyOf(rowValueDenied), defaultMasks));
        }
        return maskingProcessor.projectAndMaskPage(inputs, fieldSchemas);
    }

    private boolean matchesHardScope(
            AfastamentoRecord record,
            String callerTenantId,
            Set<Long> callerHardScopeOrgIds
    ) {
        if (!record.tenantId().equals(callerTenantId)) {
            return false;
        }
        return callerHardScopeOrgIds.contains(record.orgCedenteId())
                || callerHardScopeOrgIds.contains(record.orgCessionariaId());
    }

    private boolean matchesDataScopePlan(AfastamentoRecord record, DataScopePlan plan) {
        if (plan.scopeOutcome() == DataScopeOutcome.ALL) {
            return true;
        }
        if (plan.scopeOutcome() == DataScopeOutcome.NONE) {
            return false;
        }
        return evaluateKleenePredicateOnRecord(record, plan.predicateIr()).isRowSelected();
    }

    /**
     * Evaluates a {@link SearchPredicateIr} against an {@link AfastamentoRecord} using the canonical
     * 3-valued Kleene logic evaluator ({@code CC03}, {@code P07}), ensuring {@code UNKNOWN} on absent/null
     * attributes is never inverted to {@code TRUE} by {@code NOT} and never selects the row.
     */
    public KleeneTruthValue evaluateKleenePredicateOnRecord(AfastamentoRecord record, SearchPredicateIr predicate) {
        return KleeneSearchPredicateEvaluator.evaluate(predicate, toResolvedResourceFacts(record));
    }

    private Map<String, ResolvedFactValue> toResolvedResourceFacts(AfastamentoRecord record) {
        Map<String, ResolvedFactValue> facts = new LinkedHashMap<>();
        facts.put("resource.id", ResolvedFactValue.present("resource.id", record.id()));
        facts.put("resource.tenantId", ResolvedFactValue.present("resource.tenantId", record.tenantId()));
        facts.put("resource.orgCedenteId", ResolvedFactValue.present("resource.orgCedenteId", record.orgCedenteId()));
        facts.put("resource.orgCessionariaId", ResolvedFactValue.present("resource.orgCessionariaId", record.orgCessionariaId()));
        facts.put("resource.lotacaoSetorId", ResolvedFactValue.present("resource.lotacaoSetorId", record.lotacaoSetorId()));
        facts.put("resource.statusAfastamento", record.statusAfastamento() != null
                ? ResolvedFactValue.present("resource.statusAfastamento", record.statusAfastamento())
                : ResolvedFactValue.absent("resource.statusAfastamento"));
        facts.put("resource.substitutoServidorId", record.substitutoServidorId() != null
                ? ResolvedFactValue.present("resource.substitutoServidorId", record.substitutoServidorId())
                : ResolvedFactValue.absent("resource.substitutoServidorId"));
        facts.put("resource.cidCodigo", record.cidCodigo() != null
                ? ResolvedFactValue.present("resource.cidCodigo", record.cidCodigo())
                : ResolvedFactValue.absent("resource.cidCodigo"));
        return Map.copyOf(facts);
    }

    private ProviderInputProjection buildSearchProjection(
            String callerPrincipalId,
            Set<Long> callerLotacaoSetorIds
    ) {
        return new ProviderInputProjection(
                ProviderInputProjection.SCHEMA_VERSION_V1,
                blueprint.decisionPoint().identity().pointKey(),
                "SEARCH",
                blueprint.factContract().factContractDigest(),
                new TemporalContext(Instant.now(), ZoneOffset.UTC),
                Map.of(
                        "subject.principalId", callerPrincipalId,
                        "subject.organizationUnitIds", List.copyOf(callerLotacaoSetorIds)
                ),
                Map.of(
                        "subject.principalId", FactResolutionStatus.PRESENT,
                        "subject.organizationUnitIds", FactResolutionStatus.PRESENT
                ),
                Set.of("resource.cidCodigo")
        );
    }

    private ProviderInputProjection buildTargetProjection(
            String callerPrincipalId,
            Set<Long> callerLotacaoSetorIds,
            AfastamentoRecord existing
    ) {
        return new ProviderInputProjection(
                ProviderInputProjection.SCHEMA_VERSION_V1,
                blueprint.decisionPoint().identity().pointKey(),
                "TARGET",
                blueprint.factContract().factContractDigest(),
                new TemporalContext(Instant.now(), ZoneOffset.UTC),
                Map.of(
                        "subject.principalId", callerPrincipalId,
                        "subject.organizationUnitIds", List.copyOf(callerLotacaoSetorIds),
                        "resource.lotacaoSetorId", existing.lotacaoSetorId()
                ),
                Map.of(
                        "subject.principalId", FactResolutionStatus.PRESENT,
                        "subject.organizationUnitIds", FactResolutionStatus.PRESENT,
                        "resource.lotacaoSetorId", FactResolutionStatus.PRESENT
                ),
                Set.of("resource.cidCodigo")
        );
    }

    public static List<DtoFieldSchemaMetadata> defaultFieldSchemas() {
        return List.of(
                new DtoFieldSchemaMetadata("id", "ergon.afastamentos.id", FactValueType.INT64, false),
                new DtoFieldSchemaMetadata("orgCedenteId", "ergon.afastamentos.org_cedente_id", FactValueType.INT64, false),
                new DtoFieldSchemaMetadata("orgCessionariaId", "ergon.afastamentos.org_cessionaria_id", FactValueType.INT64, false),
                new DtoFieldSchemaMetadata("lotacaoSetorId", "ergon.afastamentos.lotacao_setor_id", FactValueType.INT64, false),
                new DtoFieldSchemaMetadata("statusAfastamento", "ergon.afastamentos.status_afastamento", FactValueType.STRING, false),
                new DtoFieldSchemaMetadata("substitutoServidorId", "ergon.afastamentos.substituto_servidor_id", FactValueType.INT64, true),
                new DtoFieldSchemaMetadata("cidCodigo", "ergon.afastamentos.cid_codigo", FactValueType.STRING, true)
        );
    }
}
