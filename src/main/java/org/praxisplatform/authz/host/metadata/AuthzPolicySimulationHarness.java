package org.praxisplatform.authz.host.metadata;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import org.praxisplatform.authz.contracts.binding.WriteFieldChange;
import org.praxisplatform.authz.contracts.binding.WriteIntent;
import org.praxisplatform.authz.contracts.context.FactResolutionStatus;
import org.praxisplatform.authz.contracts.decisionpoint.DecisionPointDescriptor;
import org.praxisplatform.authz.contracts.decisionpoint.FieldUseCategory;
import org.praxisplatform.authz.contracts.envelope.FieldUseEffectDirective;
import org.praxisplatform.authz.contracts.envelope.MaskDirective;
import org.praxisplatform.authz.contracts.policy.DualScopeDelegationSpec;
import org.praxisplatform.authz.contracts.obligation.DefaultObligationHandlerRegistry;
import org.praxisplatform.authz.enforcement.context.UntrustedRequestHeaderGuard;
import org.praxisplatform.authz.enforcement.fielduse.FieldUseQueryGuard;
import org.praxisplatform.authz.enforcement.fielduse.FieldUseViolationException;
import org.praxisplatform.authz.enforcement.masking.DetachedDtoMaskingProcessor;
import org.praxisplatform.authz.enforcement.masking.DetachedDtoMaskingProcessor.RowMaskingInput;
import org.praxisplatform.authz.enforcement.masking.DetachedDtoMaskingResult;
import org.praxisplatform.authz.enforcement.obligation.InMemoryTransactionalAuditOutbox;
import org.praxisplatform.authz.enforcement.obligation.ObligationBarrierCoordinator;
import org.praxisplatform.authz.enforcement.pipeline.AuthorizationProviderPort;
import org.praxisplatform.authz.enforcement.writeintent.DtoWriteIntentExtractor;
import org.praxisplatform.authz.enforcement.writeintent.FieldWriteAuthorizer;
import org.praxisplatform.authz.enforcement.writeintent.FieldWriteViolationException;
import org.praxisplatform.authz.host.metadata.AuthzHostPolicyBootstrapBuilder.AuthzHostPolicyBootstrapBundle;
import org.praxisplatform.authz.host.metadata.AuthzResourceOperationAvailabilityProvider.CallerAvailabilityFactContext;
import org.praxisplatform.authz.host.metadata.AuthzResourceOperationAvailabilityProvider.ResourceAvailabilityPolicyBinding;
import org.praxisplatform.authz.host.metadata.MetadataDtoGovernanceIntrospector.IntrospectedDtoGovernanceContract;
import org.praxisplatform.authz.opa.client.OpaAuthorizationProviderAdapter;
import org.praxisplatform.authz.opa.revision.SameInstanceSearchRevisionGuard;
import org.praxisplatform.authz.seams.GovernedExportAndAiToolAuthorizationSeam.SanitizedAiToolProjection;
import org.praxisplatform.authz.seams.MetadataResourceAuthorizationSeam;
import org.praxisplatform.authz.seams.MetadataResourceAuthorizationSeam.AuthorizedPreMutationContext;
import org.praxisplatform.authz.seams.MetadataResourceAuthorizationSeam.TargetReadProjectionEvaluation;
import org.praxisplatform.uischema.capability.AvailabilityDecision;
import org.praxisplatform.uischema.capability.ResourceOperationAvailabilityContext;
import org.praxisplatform.uischema.capability.ResourceStateSnapshot;
import org.praxisplatform.uischema.dto.OptionDTO;
import org.praxisplatform.uischema.options.OptionSourceDescriptor;
import org.praxisplatform.uischema.options.service.OptionSourceOperation;
import org.praxisplatform.uischema.stats.StatsFieldDescriptor;
import org.praxisplatform.uischema.stats.StatsFieldRegistry;
import org.springframework.data.domain.Sort;

/**
 * Declarative in-memory policy simulation and matrix verification harness for governed resources
 * ({@code Fase P10.16-C}).
 *
 * <p>Enables enterprise hosts and security auditors to verify {@link AuthzCallerContext} &times;
 * operation/action/surface &times; entity state combinations against an
 * {@link AuthzResourceGovernanceSpec} and {@link AuthzHostPolicyBootstrapBundle} without requiring
 * a live database or HTTP container.</p>
 *
 * @param <E> entity type
 * @param <ResponseDTO> response DTO type
 */
public final class AuthzPolicySimulationHarness<E, ResponseDTO> {

    /**
     * Structured outcome of an item or collection availability simulation ({@code Fase P10.16-C}).
     *
     * @param allowed whether the operation is permitted in discovery
     * @param reason machine-readable denial reason when {@code !allowed}
     * @param denialCategory structured denial category when {@code !allowed}
     * @param dualScopeCustodyRole value-free custody partition role ({@code CEDENTE_ONLY}, {@code CESSIONARIO_ONLY}, etc.)
     * @param forbiddenWriteAttributeIds canonical {@code attributeId}s denied write access
     * @param policyReasonCodes matched OPA policy unit reason codes
     * @param metadata full sanitized availability decision metadata
     */
    public record AvailabilitySimulationOutcome(
            boolean allowed,
            String reason,
            String denialCategory,
            String dualScopeCustodyRole,
            List<String> forbiddenWriteAttributeIds,
            List<String> policyReasonCodes,
            Map<String, Object> metadata
    ) {
        /** Asserts that the simulated operation was allowed. */
        public AvailabilitySimulationOutcome assertAllowed() {
            if (!allowed) {
                throw new IllegalStateException(
                        "Expected availability ALLOWED, but was DENIED with reason='" + reason
                                + "', category='" + denialCategory + "', metadata=" + metadata
                );
            }
            return this;
        }

        /** Asserts that the simulated operation was denied with {@code expectedReason}. */
        public AvailabilitySimulationOutcome assertDenied(String expectedReason) {
            if (allowed) {
                throw new IllegalStateException(
                        "Expected availability DENIED with reason='" + expectedReason
                                + "', but was ALLOWED (metadata=" + metadata + ")"
                );
            }
            if (expectedReason != null && !Objects.equals(expectedReason, reason)) {
                throw new IllegalStateException(
                        "Expected availability denial reason='" + expectedReason + "', but was '"
                                + reason + "' (metadata=" + metadata + ")"
                );
            }
            return this;
        }

        /** Asserts that the simulated operation was denied with {@code expectedCategory}. */
        public AvailabilitySimulationOutcome assertDeniedCategory(String expectedCategory) {
            if (allowed) {
                throw new IllegalStateException(
                        "Expected availability DENIED with category='" + expectedCategory
                                + "', but was ALLOWED (metadata=" + metadata + ")"
                );
            }
            if (expectedCategory != null && !Objects.equals(expectedCategory, denialCategory)) {
                throw new IllegalStateException(
                        "Expected availability denialCategory='" + expectedCategory + "', but was '"
                                + denialCategory + "' (metadata=" + metadata + ")"
                );
            }
            return this;
        }
    }

    /**
     * Structured outcome of a live {@code TARGET} read or surface projection simulation
     * ({@code Fase P10.16-C}).
     *
     * @param allowed whether the target read projection was permitted
     * @param denialReason machine-readable denial reason when {@code !allowed}
     * @param maskedResponse detached masked DTO when {@code allowed && rawResponseDto != null}
     * @param maskedAttributeIds canonical {@code attributeId}s targeted by active {@link MaskDirective}s
     * @param valueDeniedAttributeIds canonical {@code attributeId}s denied by {@code VALUE+DENY}
     * @param <DTO> response DTO type
     */
    public record ReadSimulationOutcome<DTO>(
            boolean allowed,
            String denialReason,
            DTO maskedResponse,
            Set<String> maskedAttributeIds,
            Set<String> valueDeniedAttributeIds
    ) {
        /** Asserts that the simulated read projection was allowed. */
        public ReadSimulationOutcome<DTO> assertAllowed() {
            if (!allowed) {
                throw new IllegalStateException(
                        "Expected target read ALLOWED, but was DENIED with reason='" + denialReason + "'"
                );
            }
            return this;
        }

        /** Asserts that the simulated read projection was denied. */
        public ReadSimulationOutcome<DTO> assertDenied() {
            if (allowed) {
                throw new IllegalStateException("Expected target read DENIED, but was ALLOWED");
            }
            return this;
        }

        /** Asserts that {@code attributeId} received an active mask directive. */
        public ReadSimulationOutcome<DTO> assertAttributeMasked(String attributeId) {
            assertAllowed();
            if (!maskedAttributeIds.contains(attributeId)) {
                throw new IllegalStateException(
                        "Expected attribute '" + attributeId + "' to be masked, but active maskedAttributeIds="
                                + maskedAttributeIds
                );
            }
            return this;
        }
    }

    /**
     * Structured outcome of an assisted {@code DuplicateDraft} simulation ({@code Fase P10.17-B}).
     *
     * @param allowed whether the source entity was accessible and custody-permitted for cloning
     * @param denialReason machine-readable denial reason when {@code !allowed}
     * @param sanitizedDraft sanitized detached draft DTO when {@code allowed}
     * @param strippedAttributes wire field names and canonical {@code attributeId}s stripped to {@code null}
     * @param <DraftDTO> draft DTO type
     */
    public record DuplicateDraftSimulationOutcome<DraftDTO>(
            boolean allowed,
            String denialReason,
            DraftDTO sanitizedDraft,
            Set<String> strippedAttributes
    ) {
        public DuplicateDraftSimulationOutcome {
            strippedAttributes = strippedAttributes == null ? Set.of() : Set.copyOf(strippedAttributes);
        }

        /** Asserts that the duplicate-draft simulation was allowed. */
        public DuplicateDraftSimulationOutcome<DraftDTO> assertAllowed() {
            if (!allowed) {
                throw new IllegalStateException(
                        "Expected duplicate-draft ALLOWED, but was DENIED with reason='" + denialReason + "'"
                );
            }
            return this;
        }

        /** Asserts that the duplicate-draft simulation was denied. */
        public DuplicateDraftSimulationOutcome<DraftDTO> assertDenied() {
            if (allowed) {
                throw new IllegalStateException("Expected duplicate-draft DENIED, but was ALLOWED");
            }
            return this;
        }

        /** Asserts that the duplicate-draft simulation was denied with {@code expectedReason}. */
        public DuplicateDraftSimulationOutcome<DraftDTO> assertDenied(String expectedReason) {
            assertDenied();
            if (expectedReason != null && !Objects.equals(expectedReason, denialReason)) {
                throw new IllegalStateException(
                        "Expected duplicate-draft denialReason='" + expectedReason + "', but was '" + denialReason + "'"
                );
            }
            return this;
        }

        /** Asserts that {@code wireOrAttributeId} was stripped to {@code null} in the sanitized draft. */
        public DuplicateDraftSimulationOutcome<DraftDTO> assertAttributeStripped(String wireOrAttributeId) {
            assertAllowed();
            if (!strippedAttributes.contains(wireOrAttributeId)) {
                throw new IllegalStateException(
                        "Expected attribute '" + wireOrAttributeId + "' to be stripped in duplicate-draft, but strippedAttributes="
                                + strippedAttributes
                );
            }
            return this;
        }

        /** Asserts that {@code wireOrAttributeId} was preserved (not stripped) in the sanitized draft. */
        public DuplicateDraftSimulationOutcome<DraftDTO> assertAttributePreserved(String wireOrAttributeId) {
            assertAllowed();
            if (strippedAttributes.contains(wireOrAttributeId)) {
                throw new IllegalStateException(
                        "Expected attribute '" + wireOrAttributeId + "' to be preserved in duplicate-draft, but it was stripped ("
                                + strippedAttributes + ")"
                );
            }
            return this;
        }
    }

    /**
     * Structured outcome of a governed collection export simulation ({@code Fase P10.17-B}).
     *
     * @param allowed whether collection export was permitted for the caller
     * @param denialReason machine-readable denial reason when {@code !allowed}
     * @param exportedRows sanitized and masked row projections admitted into the export
     * @param excludedFields wire field names and canonical {@code attributeId}s excluded from export
     * @param maskedAttributeIds canonical {@code attributeId}s masked in exported rows
     */
    public record CollectionExportSimulationOutcome(
            boolean allowed,
            String denialReason,
            List<Map<String, Object>> exportedRows,
            Set<String> excludedFields,
            Set<String> maskedAttributeIds
    ) {
        public CollectionExportSimulationOutcome {
            exportedRows = exportedRows == null ? List.of() : List.copyOf(exportedRows);
            excludedFields = excludedFields == null ? Set.of() : Set.copyOf(excludedFields);
            maskedAttributeIds = maskedAttributeIds == null ? Set.of() : Set.copyOf(maskedAttributeIds);
        }

        /** Asserts that the collection export simulation was allowed. */
        public CollectionExportSimulationOutcome assertAllowed() {
            if (!allowed) {
                throw new IllegalStateException(
                        "Expected collection export ALLOWED, but was DENIED with reason='" + denialReason + "'"
                );
            }
            return this;
        }

        /** Asserts that the collection export simulation was denied. */
        public CollectionExportSimulationOutcome assertDenied() {
            if (allowed) {
                throw new IllegalStateException("Expected collection export DENIED, but was ALLOWED");
            }
            return this;
        }

        /** Asserts that the exported row count equals {@code expectedCount}. */
        public CollectionExportSimulationOutcome assertRowCount(int expectedCount) {
            assertAllowed();
            if (exportedRows.size() != expectedCount) {
                throw new IllegalStateException(
                        "Expected " + expectedCount + " exported row(s), but actual was " + exportedRows.size()
                );
            }
            return this;
        }

        /** Asserts that {@code wireOrAttributeId} was excluded from exported columns/rows. */
        public CollectionExportSimulationOutcome assertFieldExcluded(String wireOrAttributeId) {
            assertAllowed();
            if (!excludedFields.contains(wireOrAttributeId)) {
                throw new IllegalStateException(
                        "Expected field '" + wireOrAttributeId + "' to be excluded from export, but excludedFields="
                                + excludedFields
                );
            }
            return this;
        }

        /** Asserts that {@code attributeId} was masked in exported rows. */
        public CollectionExportSimulationOutcome assertAttributeMasked(String attributeId) {
            assertAllowed();
            if (!maskedAttributeIds.contains(attributeId)) {
                throw new IllegalStateException(
                        "Expected attribute '" + attributeId + "' to be masked in export, but maskedAttributeIds="
                                + maskedAttributeIds
                );
            }
            return this;
        }
    }

    /**
     * Structured outcome of a governed non-persistent reactive determination simulation
     * ({@code Fase P10.18-A}, {@code P05}, {@code P12}, {@code P13}, {@code P14}, {@code P50}).
     *
     * @param allowed whether the target entity passed tenant hard-scope, row access, and {@code TARGET} gates
     * @param denialReason machine-readable denial reason when {@code !allowed}
     * @param maskedDeterminationPayload detached and masked determination payload map when {@code allowed}
     * @param maskedAttributeIds canonical {@code attributeId}s masked in the determination payload
     * @param valueDeniedAttributeIds canonical {@code attributeId}s omitted from the determination payload
     */
    public record ReactiveDeterminationSimulationOutcome(
            boolean allowed,
            String denialReason,
            Map<String, Object> maskedDeterminationPayload,
            Set<String> maskedAttributeIds,
            Set<String> valueDeniedAttributeIds
    ) {
        public ReactiveDeterminationSimulationOutcome {
            maskedDeterminationPayload = maskedDeterminationPayload == null
                    ? Map.of()
                    : java.util.Collections.unmodifiableMap(new LinkedHashMap<>(maskedDeterminationPayload));
            maskedAttributeIds = maskedAttributeIds == null ? Set.of() : Set.copyOf(maskedAttributeIds);
            valueDeniedAttributeIds = valueDeniedAttributeIds == null ? Set.of() : Set.copyOf(valueDeniedAttributeIds);
        }

        /** Asserts that the reactive determination simulation was allowed. */
        public ReactiveDeterminationSimulationOutcome assertAllowed() {
            if (!allowed) {
                throw new IllegalStateException(
                        "Expected reactive determination ALLOWED, but was DENIED with reason='" + denialReason + "'"
                );
            }
            return this;
        }

        /** Asserts that the reactive determination simulation was denied. */
        public ReactiveDeterminationSimulationOutcome assertDenied() {
            if (allowed) {
                throw new IllegalStateException("Expected reactive determination DENIED, but was ALLOWED");
            }
            return this;
        }

        /** Asserts that the reactive determination simulation was denied with {@code expectedReason}. */
        public ReactiveDeterminationSimulationOutcome assertDenied(String expectedReason) {
            assertDenied();
            if (expectedReason != null && !Objects.equals(expectedReason, denialReason)) {
                throw new IllegalStateException(
                        "Expected reactive determination denialReason='" + expectedReason
                                + "', but was '" + denialReason + "'"
                );
            }
            return this;
        }

        /** Asserts that {@code wireKey} is present in {@code maskedDeterminationPayload} with {@code expectedValue}. */
        public ReactiveDeterminationSimulationOutcome assertKeyPresentWithValue(String wireKey, Object expectedValue) {
            assertAllowed();
            if (!maskedDeterminationPayload.containsKey(wireKey)) {
                throw new IllegalStateException(
                        "Expected key '" + wireKey + "' in maskedDeterminationPayload, but keys were "
                                + maskedDeterminationPayload.keySet()
                );
            }
            Object actual = maskedDeterminationPayload.get(wireKey);
            if (!Objects.equals(expectedValue, actual)) {
                throw new IllegalStateException(
                        "Expected maskedDeterminationPayload['" + wireKey + "']='" + expectedValue
                                + "', but was '" + actual + "'"
                );
            }
            return this;
        }

        /** Asserts that {@code wireKey} was suppressed/omitted from {@code maskedDeterminationPayload}. */
        public ReactiveDeterminationSimulationOutcome assertKeySuppressed(String wireKey) {
            assertAllowed();
            if (maskedDeterminationPayload.containsKey(wireKey)) {
                throw new IllegalStateException(
                        "Expected key '" + wireKey + "' to be suppressed from maskedDeterminationPayload, but was present with value='"
                                + maskedDeterminationPayload.get(wireKey) + "'"
                );
            }
            return this;
        }

        /** Asserts that {@code attributeId} was masked in the determination evaluation. */
        public ReactiveDeterminationSimulationOutcome assertAttributeMasked(String attributeId) {
            assertAllowed();
            if (!maskedAttributeIds.contains(attributeId)) {
                throw new IllegalStateException(
                        "Expected attribute '" + attributeId + "' to be masked in reactive determination, but maskedAttributeIds="
                                + maskedAttributeIds
                );
            }
            return this;
        }
    }

    /**
     * Structured outcome of an AI Context / Tool Grounding projection simulation
     * ({@code Fase P10.18-A}, {@code P47}, {@code P57}, {@code P62}).
     *
     * @param allowed whether the target entity passed tenant hard-scope, row access, and {@code TARGET} gates
     * @param denialReason machine-readable denial reason when {@code !allowed}
     * @param projection canonical {@link SanitizedAiToolProjection} when {@code allowed}
     * @param allowedWireColumns wire column names admitted into the AI projection
     * @param suppressedAttributeIds wire field names and canonical {@code attributeId}s suppressed from AI context
     * @param detachedPayload sanitized detached payload map for AI consumption
     */
    public record AiContextSimulationOutcome(
            boolean allowed,
            String denialReason,
            SanitizedAiToolProjection projection,
            List<String> allowedWireColumns,
            Set<String> suppressedAttributeIds,
            Map<String, Object> detachedPayload
    ) {
        public AiContextSimulationOutcome {
            allowedWireColumns = allowedWireColumns == null ? List.of() : List.copyOf(allowedWireColumns);
            suppressedAttributeIds = suppressedAttributeIds == null ? Set.of() : Set.copyOf(suppressedAttributeIds);
            detachedPayload = detachedPayload == null
                    ? Map.of()
                    : java.util.Collections.unmodifiableMap(new LinkedHashMap<>(detachedPayload));
        }

        /** Asserts that the AI context projection simulation was allowed. */
        public AiContextSimulationOutcome assertAllowed() {
            if (!allowed) {
                throw new IllegalStateException(
                        "Expected AI context projection ALLOWED, but was DENIED with reason='" + denialReason + "'"
                );
            }
            return this;
        }

        /** Asserts that the AI context projection simulation was denied. */
        public AiContextSimulationOutcome assertDenied() {
            if (allowed) {
                throw new IllegalStateException("Expected AI context projection DENIED, but was ALLOWED");
            }
            return this;
        }

        /** Asserts that the AI context projection simulation was denied with {@code expectedReason}. */
        public AiContextSimulationOutcome assertDenied(String expectedReason) {
            assertDenied();
            if (expectedReason != null && !Objects.equals(expectedReason, denialReason)) {
                throw new IllegalStateException(
                        "Expected AI context projection denialReason='" + expectedReason
                                + "', but was '" + denialReason + "'"
                );
            }
            return this;
        }

        /** Asserts that {@code wireFieldName} is admitted in {@code allowedWireColumns} and {@code detachedPayload}. */
        public AiContextSimulationOutcome assertColumnAllowed(String wireFieldName) {
            assertAllowed();
            if (!allowedWireColumns.contains(wireFieldName) || !detachedPayload.containsKey(wireFieldName)) {
                throw new IllegalStateException(
                        "Expected wire column '" + wireFieldName + "' to be allowed in AI context, but allowedWireColumns="
                                + allowedWireColumns
                );
            }
            return this;
        }

        /** Asserts that {@code wireOrAttributeId} was suppressed from the AI context projection. */
        public AiContextSimulationOutcome assertAttributeSuppressed(String wireOrAttributeId) {
            assertAllowed();
            if (!suppressedAttributeIds.contains(wireOrAttributeId) || detachedPayload.containsKey(wireOrAttributeId)) {
                throw new IllegalStateException(
                        "Expected '" + wireOrAttributeId + "' to be suppressed from AI context, but suppressedAttributeIds="
                                + suppressedAttributeIds + ", detachedPayloadKeys=" + detachedPayload.keySet()
                );
            }
            return this;
        }
    }

    /**
     * Structured outcome of a query {@link FieldUseCategory} ({@code FILTER}, {@code SORT},
     * {@code GROUP}, {@code AGGREGATE}, {@code JOIN}) eligibility simulation
     * ({@code Fase P10.18-B}, {@code P13}, {@code P14}, {@code P50}).
     *
     * @param allowed whether all requested query field uses were permitted
     * @param denialReason machine-readable denial reason when {@code !allowed}
     * @param violatedCategory first violated {@link FieldUseCategory} when denied due to field-use violation
     * @param violatedAttributeIds canonical {@code attributeId}s that violated {@code violatedCategory}
     * @param effectiveDirectives combined static and dynamic {@link FieldUseEffectDirective}s
     */
    public record QueryFieldUseSimulationOutcome(
            boolean allowed,
            String denialReason,
            FieldUseCategory violatedCategory,
            Set<String> violatedAttributeIds,
            List<FieldUseEffectDirective> effectiveDirectives
    ) {
        public QueryFieldUseSimulationOutcome {
            violatedAttributeIds = violatedAttributeIds == null ? Set.of() : Set.copyOf(violatedAttributeIds);
            effectiveDirectives = effectiveDirectives == null ? List.of() : List.copyOf(effectiveDirectives);
        }

        /** Asserts that all requested query field uses were allowed. */
        public QueryFieldUseSimulationOutcome assertAllowed() {
            if (!allowed) {
                throw new IllegalStateException(
                        "Expected query field-use ALLOWED, but was DENIED with reason='" + denialReason
                                + "', category=" + violatedCategory + ", attributes=" + violatedAttributeIds
                );
            }
            return this;
        }

        /** Asserts that the query field-use simulation was denied. */
        public QueryFieldUseSimulationOutcome assertDenied() {
            if (allowed) {
                throw new IllegalStateException("Expected query field-use DENIED, but was ALLOWED");
            }
            return this;
        }

        /** Asserts that the query field-use simulation was denied with {@code expectedReason}. */
        public QueryFieldUseSimulationOutcome assertDenied(String expectedReason) {
            assertDenied();
            if (expectedReason != null && !Objects.equals(expectedReason, denialReason)) {
                throw new IllegalStateException(
                        "Expected query field-use denialReason='" + expectedReason + "', but was '" + denialReason + "'"
                );
            }
            return this;
        }

        /** Asserts that the query field-use simulation was denied for {@code expectedCategory} on {@code expectedAttributeId}. */
        public QueryFieldUseSimulationOutcome assertViolated(
                FieldUseCategory expectedCategory,
                String expectedAttributeId
        ) {
            assertDenied();
            if (expectedCategory != null && violatedCategory != expectedCategory) {
                throw new IllegalStateException(
                        "Expected violated FieldUseCategory=" + expectedCategory + ", but was " + violatedCategory
                );
            }
            if (expectedAttributeId != null && !violatedAttributeIds.contains(expectedAttributeId)) {
                throw new IllegalStateException(
                        "Expected violatedAttributeIds to contain '" + expectedAttributeId
                                + "', but was " + violatedAttributeIds
                );
            }
            return this;
        }
    }

    /**
     * Structured outcome of an analytical {@code GROUP BY} / {@code AGGREGATE} eligibility
     * simulation ({@code Fase P10.19-A}, {@code P05}, {@code P08}, {@code P10}, {@code P14}, {@code P46}, {@code P50}).
     *
     * @param allowed whether all requested dimensions and metric fields were permitted
     * @param denialReason machine-readable denial reason when {@code !allowed}
     * @param violatedCategory violated {@link FieldUseCategory} ({@code GROUP} or {@code AGGREGATE}) when denied
     * @param violatedAttributeIds canonical {@code attributeId}s denied for {@code violatedCategory}
     */
    public record StatsSimulationOutcome(
            boolean allowed,
            String denialReason,
            FieldUseCategory violatedCategory,
            Set<String> violatedAttributeIds
    ) {
        public StatsSimulationOutcome {
            violatedAttributeIds = violatedAttributeIds == null ? Set.of() : Set.copyOf(violatedAttributeIds);
        }

        /** Asserts that the analytical stats simulation was allowed. */
        public StatsSimulationOutcome assertAllowed() {
            if (!allowed) {
                throw new IllegalStateException(
                        "Expected stats query ALLOWED, but was DENIED with reason='" + denialReason
                                + "', category=" + violatedCategory + ", attributes=" + violatedAttributeIds
                );
            }
            return this;
        }

        /** Asserts that the analytical stats simulation was denied. */
        public StatsSimulationOutcome assertDenied() {
            if (allowed) {
                throw new IllegalStateException("Expected stats query DENIED, but was ALLOWED");
            }
            return this;
        }

        /** Asserts that the stats simulation was denied for {@code expectedCategory} on {@code expectedAttributeId}. */
        public StatsSimulationOutcome assertViolated(
                FieldUseCategory expectedCategory,
                String expectedAttributeId
        ) {
            assertDenied();
            if (expectedCategory != null && violatedCategory != expectedCategory) {
                throw new IllegalStateException(
                        "Expected stats violated FieldUseCategory=" + expectedCategory + ", but was " + violatedCategory
                );
            }
            if (expectedAttributeId != null && !violatedAttributeIds.contains(expectedAttributeId)) {
                throw new IllegalStateException(
                        "Expected stats violatedAttributeIds to contain '" + expectedAttributeId
                                + "', but was " + violatedAttributeIds
                );
            }
            return this;
        }
    }

    /**
     * Structured outcome of a governed {@code OptionSource} simulation ({@code Fase P10.19-A},
     * {@code P05}, {@code P06}, {@code P07}, {@code P09}, {@code P12}, {@code P50}).
     *
     * @param allowed whether collection-level option-source access was permitted
     * @param denialReason machine-readable denial reason when {@code !allowed}
     * @param options sanitized {@link OptionDTO} list for in-scope entities
     * @param admittedIds IDs of in-scope options retained after row-level scope filtering
     * @param maskedAttributeIds canonical {@code attributeId}s masked across admitted options
     * @param valueDeniedAttributeIds canonical {@code attributeId}s redacted across admitted options
     */
    public record OptionSourceSimulationOutcome(
            boolean allowed,
            String denialReason,
            FieldUseCategory violatedCategory,
            Set<String> violatedAttributeIds,
            List<OptionDTO<Object>> options,
            Set<Object> admittedIds,
            Set<String> maskedAttributeIds,
            Set<String> valueDeniedAttributeIds
    ) {
        public OptionSourceSimulationOutcome(
                boolean allowed,
                String denialReason,
                List<OptionDTO<Object>> options,
                Set<Object> admittedIds,
                Set<String> maskedAttributeIds,
                Set<String> valueDeniedAttributeIds
        ) {
            this(
                    allowed,
                    denialReason,
                    null,
                    Set.of(),
                    options,
                    admittedIds,
                    maskedAttributeIds,
                    valueDeniedAttributeIds
            );
        }

        public OptionSourceSimulationOutcome {
            violatedAttributeIds = violatedAttributeIds == null ? Set.of() : Set.copyOf(violatedAttributeIds);
            options = options == null ? List.of() : List.copyOf(options);
            admittedIds = admittedIds == null ? Set.of() : Set.copyOf(admittedIds);
            maskedAttributeIds = maskedAttributeIds == null ? Set.of() : Set.copyOf(maskedAttributeIds);
            valueDeniedAttributeIds = valueDeniedAttributeIds == null ? Set.of() : Set.copyOf(valueDeniedAttributeIds);
        }

        /** Asserts that the option-source simulation was allowed. */
        public OptionSourceSimulationOutcome assertAllowed() {
            if (!allowed) {
                throw new IllegalStateException(
                        "Expected option-source ALLOWED, but was DENIED with reason='" + denialReason
                                + "', category=" + violatedCategory
                                + ", violatedAttributeIds=" + violatedAttributeIds
                );
            }
            return this;
        }

        /** Asserts that the option-source simulation was denied. */
        public OptionSourceSimulationOutcome assertDenied() {
            if (allowed) {
                throw new IllegalStateException("Expected option-source DENIED, but was ALLOWED");
            }
            return this;
        }

        /** Asserts that the option-source simulation was denied for {@code expectedCategory} on {@code expectedAttributeId}. */
        public OptionSourceSimulationOutcome assertDenied(
                FieldUseCategory expectedCategory,
                String expectedAttributeId
        ) {
            assertDenied();
            if (expectedCategory != null && violatedCategory != expectedCategory) {
                throw new IllegalStateException(
                        "Expected option-source violatedCategory=" + expectedCategory + ", but got " + violatedCategory
                );
            }
            if (expectedAttributeId != null && !violatedAttributeIds.contains(expectedAttributeId)) {
                throw new IllegalStateException(
                        "Expected option-source violatedAttributeIds to contain '" + expectedAttributeId
                                + "', but got " + violatedAttributeIds
                );
            }
            return this;
        }

        /** Asserts that the option-source simulation was denied with {@code expectedReason}. */
        public OptionSourceSimulationOutcome assertDeniedReason(String expectedReason) {
            assertDenied();
            if (expectedReason != null && !expectedReason.equals(denialReason)) {
                throw new IllegalStateException(
                        "Expected option-source denialReason='" + expectedReason + "', but got '" + denialReason + "'"
                );
            }
            return this;
        }

        /** Asserts that the number of admitted options equals {@code expectedCount}. */
        public OptionSourceSimulationOutcome assertOptionCount(int expectedCount) {
            assertAllowed();
            if (options.size() != expectedCount) {
                throw new IllegalStateException(
                        "Expected " + expectedCount + " option(s), but actual was " + options.size()
                                + " (admittedIds=" + admittedIds + ")"
                );
            }
            return this;
        }

        /** Asserts that option {@code id} was admitted. */
        public OptionSourceSimulationOutcome assertOptionAdmitted(Object id) {
            assertAllowed();
            if (!admittedIds.contains(id)) {
                throw new IllegalStateException(
                        "Expected option id='" + id + "' to be admitted, but admittedIds=" + admittedIds
                );
            }
            return this;
        }

        /** Asserts that out-of-scope option {@code id} was omitted without leaking existence. */
        public OptionSourceSimulationOutcome assertOptionOmitted(Object id) {
            assertAllowed();
            if (admittedIds.contains(id)) {
                throw new IllegalStateException(
                        "Expected out-of-scope option id='" + id + "' to be omitted, but it was admitted"
                );
            }
            return this;
        }

        /** Asserts that admitted option {@code id} has {@code expectedLabel}. */
        public OptionSourceSimulationOutcome assertOptionLabel(Object id, String expectedLabel) {
            assertAllowed();
            for (OptionDTO<Object> opt : options) {
                if (Objects.equals(opt.id(), id)) {
                    if (!Objects.equals(expectedLabel, opt.label())) {
                        throw new IllegalStateException(
                                "Expected option id='" + id + "' label='" + expectedLabel
                                        + "', but was '" + opt.label() + "'"
                        );
                    }
                    return this;
                }
            }
            throw new IllegalStateException("Option id='" + id + "' not found in admittedIds=" + admittedIds);
        }

        /** Asserts that admitted option {@code id} has {@code extra.selectable == expectedSelectable}. */
        public OptionSourceSimulationOutcome assertOptionSelectable(Object id, boolean expectedSelectable) {
            assertAllowed();
            for (OptionDTO<Object> opt : options) {
                if (Objects.equals(opt.id(), id)) {
                    boolean actualSelectable = opt.extra() == null
                            || !Boolean.FALSE.equals(opt.extra().get("selectable"));
                    if (actualSelectable != expectedSelectable) {
                        throw new IllegalStateException(
                                "Expected option id='" + id + "' selectable=" + expectedSelectable
                                        + ", but was " + actualSelectable + " (extra=" + opt.extra() + ")"
                        );
                    }
                    return this;
                }
            }
            throw new IllegalStateException("Option id='" + id + "' not found in admittedIds=" + admittedIds);
        }
    }

    /**
     * Structured outcome of a pre-hydration write mutation simulation at {@code STEP_11}
     * ({@code CREATE}, {@code UPDATE}, {@code DELETE}, or item {@code @WorkflowAction})
     * ({@code Fase P10.19-B}, {@code R-07}, {@code R-11}, {@code P13}, {@code P14}, {@code P17}).
     *
     * @param allowed whether the write mutation was admitted at {@code STEP_11}
     * @param denialReason canonical denial category ({@code "hard-scope-tenant-mismatch"},
     *                     {@code "policy-gate-denied"}, {@code "scope-anchor-clear-forbidden"},
     *                     {@code "dual-scope-custody-denied"}, or {@code "field-write-denied"})
     * @param reasonCode machine-readable reason code when {@code !allowed}
     * @param modifiedAttributeIds canonical {@code attributeId}s in the extracted {@link WriteIntent}
     * @param forbiddenWriteAttributeIds canonical {@code attributeId}s rejected by {@link FieldWriteAuthorizer}
     * @param writeIntent extracted {@link WriteIntent} when evaluated
     */
    public record WriteMutationSimulationOutcome(
            boolean allowed,
            String denialReason,
            String reasonCode,
            Set<String> modifiedAttributeIds,
            Set<String> forbiddenWriteAttributeIds,
            WriteIntent writeIntent
    ) {
        public WriteMutationSimulationOutcome {
            modifiedAttributeIds = modifiedAttributeIds == null ? Set.of() : Set.copyOf(modifiedAttributeIds);
            forbiddenWriteAttributeIds = forbiddenWriteAttributeIds == null
                    ? Set.of()
                    : Set.copyOf(forbiddenWriteAttributeIds);
        }

        /** Asserts that the write mutation simulation was allowed at {@code STEP_11}. */
        public WriteMutationSimulationOutcome assertAllowed() {
            if (!allowed) {
                throw new IllegalStateException(
                        "Expected write mutation ALLOWED, but was DENIED with reason='" + denialReason
                                + "', reasonCode='" + reasonCode
                                + "', forbiddenWriteAttributeIds=" + forbiddenWriteAttributeIds
                );
            }
            return this;
        }

        /** Asserts that the write mutation simulation was denied. */
        public WriteMutationSimulationOutcome assertDenied() {
            if (allowed) {
                throw new IllegalStateException("Expected write mutation DENIED, but was ALLOWED");
            }
            return this;
        }

        /** Asserts that the write mutation simulation was denied with {@code expectedDenialReason}. */
        public WriteMutationSimulationOutcome assertDenied(String expectedDenialReason) {
            assertDenied();
            if (expectedDenialReason != null && !Objects.equals(expectedDenialReason, denialReason)) {
                throw new IllegalStateException(
                        "Expected write mutation denialReason='" + expectedDenialReason
                                + "', but was '" + denialReason + "' (reasonCode=" + reasonCode + ")"
                );
            }
            return this;
        }

        /** Asserts that {@code attributeId} was included in the extracted {@link WriteIntent}. */
        public WriteMutationSimulationOutcome assertAttributeModified(String attributeId) {
            assertAllowed();
            if (!modifiedAttributeIds.contains(attributeId)) {
                throw new IllegalStateException(
                        "Expected attribute '" + attributeId + "' in modifiedAttributeIds, but was "
                                + modifiedAttributeIds
                );
            }
            return this;
        }

        /** Asserts that {@code attributeId} was rejected as a forbidden write attribute. */
        public WriteMutationSimulationOutcome assertForbiddenWriteAttribute(String attributeId) {
            assertDenied();
            if (!forbiddenWriteAttributeIds.contains(attributeId)) {
                throw new IllegalStateException(
                        "Expected attribute '" + attributeId + "' in forbiddenWriteAttributeIds, but was "
                                + forbiddenWriteAttributeIds
                );
            }
            return this;
        }
    }

    /**
     * Structured outcome of a cohort-scoped bulk mutation simulation ({@code BulkMode.UNIFORM_UPDATE},
     * {@code BulkMode.PER_ITEM_UPDATE}, {@code BulkMode.DOMAIN_COMMAND}, or bulk {@code DELETE})
     * under {@link org.praxisplatform.authz.contracts.binding.BatchAuthorizationMode#REJECT_ALL} or
     * {@link org.praxisplatform.authz.contracts.binding.BatchAuthorizationMode#PER_ITEM}
     * ({@code Fase P10.20-B}, {@code P13}, {@code P14}, {@code P15}, {@code P18}, {@code P34}).
     *
     * @param batchMode governed batch authorization mode ({@code REJECT_ALL} or {@code PER_ITEM})
     * @param batchAborted {@code true} when {@code REJECT_ALL} aborted the entire cohort due to a denied item or collection gate
     * @param abortReason machine-readable abort reason when {@code batchAborted == true}
     * @param itemOutcomes per-item execution outcomes
     * @param committedIds IDs of items admitted and committed
     * @param rejectedIds IDs of items rejected
     * @param reasonCodeById map of item IDs to their outcome {@code reasonCode} ({@code "COMMITTED"}, {@code "FIELD_WRITE_DENIED"}, {@code "ACCESS_OR_SCOPE_DENIED"}, {@code "ENTITY_NOT_FOUND"}, or {@code "BATCH_ABORTED"})
     * @param <ID> entity identifier type
     */
    public record BulkMutationSimulationOutcome<ID>(
            org.praxisplatform.authz.contracts.binding.BatchAuthorizationMode batchMode,
            boolean batchAborted,
            String abortReason,
            List<AuthzGovernedBulkDomainResourceAdapter.BulkCohortItemOutcome<ID>> itemOutcomes,
            Set<ID> committedIds,
            Set<ID> rejectedIds,
            Map<ID, String> reasonCodeById
    ) {
        public BulkMutationSimulationOutcome {
            Objects.requireNonNull(batchMode, "batchMode is required");
            itemOutcomes = itemOutcomes == null ? List.of() : List.copyOf(itemOutcomes);
            committedIds = committedIds == null ? Set.of() : Set.copyOf(committedIds);
            rejectedIds = rejectedIds == null ? Set.of() : Set.copyOf(rejectedIds);
            reasonCodeById = reasonCodeById == null ? Map.of() : Map.copyOf(reasonCodeById);
        }

        /** Asserts that no item caused a batch abort and every item in the cohort was committed. */
        public BulkMutationSimulationOutcome<ID> assertAllCommitted() {
            if (batchAborted || !rejectedIds.isEmpty()) {
                throw new IllegalStateException(
                        "Expected all cohort items COMMITTED, but batchAborted=" + batchAborted
                                + " (abortReason=" + abortReason + "), rejectedIds=" + rejectedIds
                                + ", reasonCodeById=" + reasonCodeById
                );
            }
            return this;
        }

        /** Asserts that a {@code REJECT_ALL} cohort was aborted and zero items were committed. */
        public BulkMutationSimulationOutcome<ID> assertBatchAborted() {
            if (!batchAborted || !committedIds.isEmpty()) {
                throw new IllegalStateException(
                        "Expected REJECT_ALL cohort to be aborted with 0 committed items, but batchAborted="
                                + batchAborted + ", committedIds=" + committedIds
                );
            }
            return this;
        }

        /** Asserts that a {@code REJECT_ALL} cohort was aborted with {@code expectedAbortReason}. */
        public BulkMutationSimulationOutcome<ID> assertBatchAborted(String expectedAbortReason) {
            assertBatchAborted();
            if (expectedAbortReason != null && !Objects.equals(expectedAbortReason, abortReason)) {
                throw new IllegalStateException(
                        "Expected bulk cohort abortReason='" + expectedAbortReason
                                + "', but was '" + abortReason + "'"
                );
            }
            return this;
        }

        /** Asserts that the number of committed items equals {@code expectedCount}. */
        public BulkMutationSimulationOutcome<ID> assertCommittedCount(int expectedCount) {
            if (committedIds.size() != expectedCount) {
                throw new IllegalStateException(
                        "Expected " + expectedCount + " committed item(s), but actual was "
                                + committedIds.size() + " (committedIds=" + committedIds
                                + ", reasonCodeById=" + reasonCodeById + ")"
                );
            }
            return this;
        }

        /** Asserts that item {@code id} was committed. */
        public BulkMutationSimulationOutcome<ID> assertItemCommitted(ID id) {
            if (!committedIds.contains(id)) {
                throw new IllegalStateException(
                        "Expected item id='" + id + "' to be COMMITTED, but reasonCode='"
                                + reasonCodeById.get(id) + "' (committedIds=" + committedIds + ")"
                );
            }
            return this;
        }

        /** Asserts that item {@code id} was rejected with {@code expectedReasonCode}. */
        public BulkMutationSimulationOutcome<ID> assertItemRejected(ID id, String expectedReasonCode) {
            if (!rejectedIds.contains(id)) {
                throw new IllegalStateException(
                        "Expected item id='" + id + "' to be REJECTED, but it was not in rejectedIds="
                                + rejectedIds + " (reasonCodeById=" + reasonCodeById + ")"
                );
            }
            String actualReason = reasonCodeById.get(id);
            if (expectedReasonCode != null && !Objects.equals(expectedReasonCode, actualReason)) {
                throw new IllegalStateException(
                        "Expected item id='" + id + "' rejection reasonCode='" + expectedReasonCode
                                + "', but was '" + actualReason + "'"
                );
            }
            return this;
        }
    }

    /**
     * Structured outcome of a 2-phase bulk proposal &amp; confirmation simulation
     * ({@code GovernedBulkProposalGrant}, {@code Fase P10.21-B}, {@code P15}, {@code P18}, {@code P34}).
     *
     * @param proposalAllowed {@code true} when at least one item in the proposal cohort was admitted
     * @param confirmAllowed {@code true} when confirmation passed anti-confused-deputy, policy digest continuity, and cohort execution
     * @param confirmDenialReason machine-readable denial reason when {@code !confirmAllowed} ({@code "PROPOSAL_REJECTED"}, {@code "AUTHZ_BULK_CONFUSED_DEPUTY_DENIED"}, {@code "AUTHZ_BULK_POLICY_REVOKED_OR_ROTATED"}, or cohort abort reason)
     * @param proposalPreviewsById masked/sanitized candidate preview outcomes per admitted item ID
     * @param confirmOutcome cohort execution outcome when confirmation reached {@code STEP_11}
     * @param <ID> entity identifier type
     * @param <ResponseDTO> response DTO type
     */
    public record BulkTwoPhaseSimulationOutcome<ID, ResponseDTO>(
            boolean proposalAllowed,
            boolean confirmAllowed,
            String confirmDenialReason,
            Map<ID, ReadSimulationOutcome<ResponseDTO>> proposalPreviewsById,
            BulkMutationSimulationOutcome<ID> confirmOutcome
    ) {
        public BulkTwoPhaseSimulationOutcome {
            proposalPreviewsById = proposalPreviewsById == null ? Map.of() : Map.copyOf(proposalPreviewsById);
        }

        /** Asserts that both the proposal phase and confirmation phase succeeded. */
        public BulkTwoPhaseSimulationOutcome<ID, ResponseDTO> assertProposalAndConfirmAllowed() {
            if (!proposalAllowed || !confirmAllowed) {
                throw new IllegalStateException(
                        "Expected 2-phase bulk proposal and confirmation ALLOWED, but proposalAllowed="
                                + proposalAllowed + ", confirmAllowed=" + confirmAllowed
                                + ", confirmDenialReason=" + confirmDenialReason
                );
            }
            return this;
        }

        /** Asserts that confirmation succeeded and committed {@code expectedCommittedIds}. */
        public BulkTwoPhaseSimulationOutcome<ID, ResponseDTO> assertConfirmAllowed(Set<ID> expectedCommittedIds) {
            assertProposalAndConfirmAllowed();
            if (confirmOutcome != null && expectedCommittedIds != null
                    && !Objects.equals(expectedCommittedIds, confirmOutcome.committedIds())) {
                throw new IllegalStateException(
                        "Expected 2-phase bulk confirmation committedIds=" + expectedCommittedIds
                                + ", but was " + confirmOutcome.committedIds()
                );
            }
            return this;
        }

        /** Asserts that confirmation was denied with {@code expectedConfirmDenialReason}. */
        public BulkTwoPhaseSimulationOutcome<ID, ResponseDTO> assertConfirmDenied(String expectedConfirmDenialReason) {
            if (confirmAllowed) {
                throw new IllegalStateException(
                        "Expected 2-phase bulk confirmation DENIED with reason='" + expectedConfirmDenialReason
                                + "', but confirmAllowed=true"
                );
            }
            if (expectedConfirmDenialReason != null && !Objects.equals(expectedConfirmDenialReason, confirmDenialReason)) {
                throw new IllegalStateException(
                        "Expected 2-phase bulk confirmation denial reason='" + expectedConfirmDenialReason
                                + "', but was '" + confirmDenialReason + "'"
                );
            }
            return this;
        }

        /** Asserts that the masked/sanitized proposal preview for {@code id} satisfies {@code predicate}. */
        public BulkTwoPhaseSimulationOutcome<ID, ResponseDTO> assertProposalPreview(
                ID id,
                java.util.function.Predicate<ReadSimulationOutcome<ResponseDTO>> predicate
        ) {
            ReadSimulationOutcome<ResponseDTO> preview = proposalPreviewsById.get(id);
            if (preview == null) {
                throw new IllegalStateException(
                        "Expected proposal preview for id='" + id + "', but present IDs were "
                                + proposalPreviewsById.keySet()
                );
            }
            if (!predicate.test(preview)) {
                throw new IllegalStateException(
                        "Proposal preview predicate failed for id='" + id + "' (preview=" + preview + ")"
                );
            }
            return this;
        }
    }

    /**
     * Structured outcome of an untrusted request header anti-spoofing simulation
     * ({@link UntrustedRequestHeaderGuard}, {@code Fase P10.21-B}, {@code P02}, {@code P53}).
     *
     * @param allowed {@code true} when no incoming header violated {@link UntrustedRequestHeaderGuard}
     * @param rejectedHeaderNames list of spoofed authority header names rejected by the guard
     * @param reasonCode machine-readable rejection reason ({@code "UNTRUSTED_AUTHORITY_HEADER_SPOOFING"}) when {@code !allowed}
     */
    public record HeaderSpoofingSimulationOutcome(
            boolean allowed,
            List<String> rejectedHeaderNames,
            String reasonCode
    ) {
        public HeaderSpoofingSimulationOutcome {
            rejectedHeaderNames = rejectedHeaderNames == null ? List.of() : List.copyOf(rejectedHeaderNames);
        }

        /** Asserts that all incoming headers passed the anti-spoofing guard. */
        public HeaderSpoofingSimulationOutcome assertAllowed() {
            if (!allowed) {
                throw new IllegalStateException(
                        "Expected incoming headers ALLOWED, but rejectedHeaderNames=" + rejectedHeaderNames
                                + " (reasonCode=" + reasonCode + ")"
                );
            }
            return this;
        }

        /** Asserts that at least one incoming header was rejected by the anti-spoofing guard. */
        public HeaderSpoofingSimulationOutcome assertSpoofingRejected() {
            if (allowed || rejectedHeaderNames.isEmpty()) {
                throw new IllegalStateException(
                        "Expected incoming headers to be REJECTED for authority spoofing, but allowed=" + allowed
                );
            }
            return this;
        }

        /** Asserts that {@code expectedHeaderName} was rejected by the anti-spoofing guard. */
        public HeaderSpoofingSimulationOutcome assertSpoofingRejected(String expectedHeaderName) {
            assertSpoofingRejected();
            if (expectedHeaderName != null && rejectedHeaderNames.stream().noneMatch(h -> h.equalsIgnoreCase(expectedHeaderName))) {
                throw new IllegalStateException(
                        "Expected rejectedHeaderNames to contain '" + expectedHeaderName
                                + "', but was " + rejectedHeaderNames
                );
            }
            return this;
        }
    }

    /**
     * Summary report returned by {@link MatrixRunner#verifyAll()} ({@code Fase P10.16-C}).
     *
     * @param totalScenarios number of evaluated matrix rows
     * @param failures diagnostic failure messages (empty when all rows passed)
     */
    public record MatrixVerificationReport(
            int totalScenarios,
            List<String> failures
    ) {
        public MatrixVerificationReport {
            failures = failures == null ? List.of() : List.copyOf(failures);
        }

        /** Returns {@code true} when all matrix scenarios passed with zero failures. */
        public boolean allPassed() {
            return failures.isEmpty();
        }

        /** Throws {@link IllegalStateException} if any scenario in the matrix failed. */
        public MatrixVerificationReport assertAllPassed() {
            if (!failures.isEmpty()) {
                throw new IllegalStateException(
                        "AuthzPolicySimulationHarness matrix failed (" + failures.size() + "/"
                                + totalScenarios + " scenarios failed):\n - "
                                + String.join("\n - ", failures)
                );
            }
            return this;
        }
    }

    private final AuthzResourceGovernanceSpec<E> spec;
    private final MetadataResourceAuthorizationSeam authorizationSeam;
    private final MetadataDtoGovernanceIntrospector dtoIntrospector;
    private final DetachedDtoMaskingProcessor maskingProcessor;
    private final Class<ResponseDTO> responseDtoClass;
    private final IntrospectedDtoGovernanceContract responseGovernanceContract;
    private final ObjectMapper objectMapper = new ObjectMapper().findAndRegisterModules();

    private AuthzPolicySimulationHarness(
            AuthzResourceGovernanceSpec<E> spec,
            MetadataResourceAuthorizationSeam authorizationSeam,
            MetadataDtoGovernanceIntrospector dtoIntrospector,
            DetachedDtoMaskingProcessor maskingProcessor,
            Class<ResponseDTO> responseDtoClass
    ) {
        this.spec = Objects.requireNonNull(spec, "spec is required");
        this.authorizationSeam = Objects.requireNonNull(authorizationSeam, "authorizationSeam is required");
        this.dtoIntrospector = Objects.requireNonNull(dtoIntrospector, "dtoIntrospector is required");
        this.maskingProcessor = Objects.requireNonNull(maskingProcessor, "maskingProcessor is required");
        this.responseDtoClass = Objects.requireNonNull(responseDtoClass, "responseDtoClass is required");
        this.responseGovernanceContract = dtoIntrospector.introspect(responseDtoClass, spec.resourceKey());
    }

    /**
     * Creates a simulation harness directly from a declarative {@link AuthzResourceGovernanceSpec},
     * compiled {@link AuthzHostPolicyBootstrapBundle}, and {@code ResponseDTO} class.
     */
    public static <E, ResponseDTO> AuthzPolicySimulationHarness<E, ResponseDTO> forResource(
            AuthzResourceGovernanceSpec<E> spec,
            AuthzHostPolicyBootstrapBundle bundle,
            Class<ResponseDTO> responseDtoClass
    ) {
        Objects.requireNonNull(bundle, "bundle is required");
        AuthorizationProviderPort providerPort = new OpaAuthorizationProviderAdapter(
                bundle.localOpaTransport(),
                new SameInstanceSearchRevisionGuard(2)
        );
        DetachedDtoMaskingProcessor maskingProcessor = new DetachedDtoMaskingProcessor();
        ObligationBarrierCoordinator obligationCoordinator = new ObligationBarrierCoordinator(
                new DefaultObligationHandlerRegistry(),
                new InMemoryTransactionalAuditOutbox()
        );
        MetadataResourceAuthorizationSeam seam = new MetadataResourceAuthorizationSeam(
                providerPort,
                new FieldUseQueryGuard(),
                new DtoWriteIntentExtractor(),
                new FieldWriteAuthorizer(),
                maskingProcessor,
                obligationCoordinator
        );
        return new AuthzPolicySimulationHarness<>(
                spec,
                seam,
                new MetadataDtoGovernanceIntrospector(),
                maskingProcessor,
                responseDtoClass
        );
    }

    /**
     * Creates a simulation harness using an existing {@link MetadataResourceAuthorizationSeam} and
     * {@link MetadataDtoGovernanceIntrospector}.
     */
    public static <E, ResponseDTO> AuthzPolicySimulationHarness<E, ResponseDTO> forResource(
            AuthzResourceGovernanceSpec<E> spec,
            MetadataResourceAuthorizationSeam authorizationSeam,
            MetadataDtoGovernanceIntrospector dtoIntrospector,
            Class<ResponseDTO> responseDtoClass
    ) {
        return new AuthzPolicySimulationHarness<>(
                spec,
                authorizationSeam,
                dtoIntrospector,
                new DetachedDtoMaskingProcessor(),
                responseDtoClass
        );
    }

    /**
     * Simulates contextual availability of an {@code ITEM}-scoped operation, workflow action, or UI
     * surface against {@code entity} (or {@code null} to simulate a missing entity).
     */
    public AvailabilitySimulationOutcome simulateItemAvailability(
            AuthzCallerContext caller,
            String operationId,
            E entity
    ) {
        Objects.requireNonNull(caller, "caller is required");
        Objects.requireNonNull(operationId, "operationId is required");
        AuthzResourceOperationAvailabilityProvider provider = buildProviderForCaller(caller, entity);
        ResourceStateSnapshot snapshot = entity == null ? null : spec.toResourceStateSnapshot(entity);
        ResourceOperationAvailabilityContext ctx = ResourceOperationAvailabilityContext.item(
                spec.resourceKey(),
                "/api/" + spec.resourceKey().replace('.', '/'),
                operationId,
                "sim-id",
                snapshot
        );
        return toAvailabilityOutcome(provider.evaluate(ctx));
    }

    /**
     * Simulates contextual availability of a {@code COLLECTION}-scoped operation or bulk workflow
     * action ({@code ActionScope.COLLECTION}).
     */
    public AvailabilitySimulationOutcome simulateCollectionAvailability(
            AuthzCallerContext caller,
            String operationId
    ) {
        Objects.requireNonNull(caller, "caller is required");
        Objects.requireNonNull(operationId, "operationId is required");
        AuthzResourceOperationAvailabilityProvider provider = buildProviderForCaller(caller, null);
        ResourceOperationAvailabilityContext ctx = ResourceOperationAvailabilityContext.collection(
                spec.resourceKey(),
                "/api/" + spec.resourceKey().replace('.', '/'),
                operationId
        );
        return toAvailabilityOutcome(provider.evaluate(ctx));
    }

    /**
     * Simulates a live {@code TARGET} read projection on {@code entity} using the resource's primary
     * decision point and masks {@code rawResponseDto} when permitted.
     */
    public ReadSimulationOutcome<ResponseDTO> simulateTargetRead(
            AuthzCallerContext caller,
            E entity,
            ResponseDTO rawResponseDto
    ) {
        return simulateProjectionReadInternal(
                caller,
                spec.decisionPoint(),
                entity,
                rawResponseDto
        );
    }

    /**
     * Simulates a live {@code TARGET} read projection on {@code entity} for a specific
     * {@code @UiSurface} decision point ({@code surfaceKey}) and masks {@code rawResponseDto} when permitted.
     */
    public ReadSimulationOutcome<ResponseDTO> simulateSurfaceRead(
            AuthzCallerContext caller,
            String surfaceKey,
            E entity,
            ResponseDTO rawResponseDto
    ) {
        Objects.requireNonNull(surfaceKey, "surfaceKey is required");
        DecisionPointDescriptor surfaceDp = spec.surfaceDecisionPoints().getOrDefault(surfaceKey, spec.decisionPoint());
        return simulateProjectionReadInternal(caller, surfaceDp, entity, rawResponseDto);
    }

    /**
     * Simulates a collection-scoped bulk workflow command ({@code BulkMode.DOMAIN_COMMAND} /
     * {@code ActionScope.COLLECTION}) across {@code candidateEntities} in memory under
     * {@link org.praxisplatform.authz.contracts.binding.BatchAuthorizationMode#PER_ITEM} or
     * {@link org.praxisplatform.authz.contracts.binding.BatchAuthorizationMode#REJECT_ALL}
     * ({@code Fase P10.16-C}, {@code P10.16-R05}).
     */
    public <ID> List<AuthzGovernedBulkDomainResourceAdapter.BulkCohortItemOutcome<ID>> simulateBulkCommand(
            AuthzCallerContext caller,
            String actionKey,
            List<E> candidateEntities,
            java.util.function.Function<E, ID> idExtractor,
            org.praxisplatform.authz.contracts.binding.BatchAuthorizationMode batchMode
    ) {
        Objects.requireNonNull(caller, "caller is required");
        Objects.requireNonNull(actionKey, "actionKey is required");
        Objects.requireNonNull(idExtractor, "idExtractor is required");
        Objects.requireNonNull(batchMode, "batchMode is required");
        if (candidateEntities == null || candidateEntities.isEmpty()) {
            return List.of();
        }
        AvailabilitySimulationOutcome collectionAvail = simulateCollectionAvailability(caller, actionKey);
        if (!collectionAvail.allowed()) {
            if (batchMode == org.praxisplatform.authz.contracts.binding.BatchAuthorizationMode.REJECT_ALL) {
                throw new SecurityException("AUTHZ_BULK_COMMAND_COLLECTION_DENIED: Bulk action '" + actionKey
                        + "' denied at collection SEARCH gate (" + collectionAvail.reason() + ")");
            }
            List<AuthzGovernedBulkDomainResourceAdapter.BulkCohortItemOutcome<ID>> deniedAll =
                    new ArrayList<>(candidateEntities.size());
            for (E entity : candidateEntities) {
                ID id = entity == null ? null : idExtractor.apply(entity);
                deniedAll.add(new AuthzGovernedBulkDomainResourceAdapter.BulkCohortItemOutcome<>(
                        id, false, null, "ACCESS_OR_SCOPE_DENIED"
                ));
            }
            return List.copyOf(deniedAll);
        }

        List<AuthzGovernedBulkDomainResourceAdapter.BulkCohortItemOutcome<ID>> outcomes =
                new ArrayList<>(candidateEntities.size());
        for (E entity : candidateEntities) {
            ID id = entity == null ? null : idExtractor.apply(entity);
            if (entity == null) {
                if (batchMode == org.praxisplatform.authz.contracts.binding.BatchAuthorizationMode.REJECT_ALL) {
                    throw new jakarta.persistence.EntityNotFoundException("Missing target entity in REJECT_ALL cohort");
                }
                outcomes.add(new AuthzGovernedBulkDomainResourceAdapter.BulkCohortItemOutcome<>(
                        id, false, null, "ENTITY_NOT_FOUND"
                ));
                continue;
            }
            AvailabilitySimulationOutcome itemAvail = simulateItemAvailability(caller, actionKey, entity);
            if (!itemAvail.allowed()) {
                if (batchMode == org.praxisplatform.authz.contracts.binding.BatchAuthorizationMode.REJECT_ALL) {
                    throw new SecurityException("AUTHZ_BULK_COMMAND_ITEM_DENIED: Item '" + id
                            + "' denied for bulk action '" + actionKey + "' (" + itemAvail.reason() + ")");
                }
                String reasonCode = ("dual-scope-custody-denied".equals(itemAvail.reason())
                                || "field-write-denied".equals(itemAvail.reason()))
                        ? "FIELD_WRITE_DENIED"
                        : "ACCESS_OR_SCOPE_DENIED";
                outcomes.add(new AuthzGovernedBulkDomainResourceAdapter.BulkCohortItemOutcome<>(
                        id, false, null, reasonCode
                ));
            } else {
                outcomes.add(new AuthzGovernedBulkDomainResourceAdapter.BulkCohortItemOutcome<>(
                        id, true, null, "COMMITTED"
                ));
            }
        }
        return List.copyOf(outcomes);
    }

    /**
     * Simulates an assisted non-persistent {@code DuplicateDraft} operation against {@code sourceEntity}
     * and returns the sanitized {@code DraftDTO} along with the set of stripped attributes
     * ({@code Fase P10.17-B}).
     */
    public <DraftDTO> DuplicateDraftSimulationOutcome<DraftDTO> simulateDuplicateDraft(
            AuthzCallerContext caller,
            E sourceEntity,
            DraftDTO rawDraft
    ) {
        return simulateDuplicateDraft(caller, "duplicate-draft", sourceEntity, rawDraft);
    }

    /**
     * Simulates an assisted non-persistent {@code DuplicateDraft} operation using {@code operationId}
     * ({@code Fase P10.17-B}).
     */
    public <DraftDTO> DuplicateDraftSimulationOutcome<DraftDTO> simulateDuplicateDraft(
            AuthzCallerContext caller,
            String operationId,
            E sourceEntity,
            DraftDTO rawDraft
    ) {
        Objects.requireNonNull(caller, "caller is required");
        Objects.requireNonNull(sourceEntity, "sourceEntity is required");
        if (caller.tenantId() != null) {
            String entityTenant = spec.extractTenantFromEntity(sourceEntity);
            if (entityTenant != null && !Objects.equals(caller.tenantId(), entityTenant)) {
                return new DuplicateDraftSimulationOutcome<>(
                        false,
                        "hard-scope-tenant-mismatch",
                        null,
                        Set.of()
                );
            }
        }
        try {
            spec.verifyEntityAccessAllowed(sourceEntity, caller, null);
        } catch (SecurityException ex) {
            return new DuplicateDraftSimulationOutcome<>(
                    false,
                    "policy-gate-denied",
                    null,
                    Set.of()
            );
        }
        Map<String, Object> mergedFacts = new LinkedHashMap<>(caller.subjectAndEnvironmentFacts());
        if (caller.tenantId() != null) {
            mergedFacts.putIfAbsent("subject.tenantId", caller.tenantId());
        }
        Map<String, Object> targetFacts = spec.extractEntityTargetFacts(sourceEntity);
        if (targetFacts != null) {
            mergedFacts.putAll(targetFacts);
        }
        Map<String, FactResolutionStatus> statuses = new LinkedHashMap<>();
        for (String key : mergedFacts.keySet()) {
            statuses.put(key, FactResolutionStatus.PRESENT);
        }
        String effectiveOpId = (operationId == null || operationId.isBlank()) ? "duplicate-draft" : operationId;
        DecisionPointDescriptor effectiveDp = spec.actionDecisionPoints()
                .getOrDefault(effectiveOpId, spec.decisionPoint());
        String factDigest = (effectiveDp.factContractRef() != null
                        && effectiveDp.factContractRef().factContractDigest() != null)
                ? effectiveDp.factContractRef().factContractDigest()
                : spec.factContractDigest();
        TargetReadProjectionEvaluation targetEval;
        try {
            if (spec.decisionPoint() != null
                    && !Objects.equals(
                            effectiveDp.identity().pointKey(),
                            spec.decisionPoint().identity().pointKey()
                    )) {
                TargetReadProjectionEvaluation primaryEval = authorizationSeam.evaluateTargetReadProjection(
                        spec.decisionPoint(),
                        spec.factContractDigest(),
                        mergedFacts,
                        statuses
                );
                TargetReadProjectionEvaluation secondaryEval = authorizationSeam.evaluateTargetReadProjection(
                        effectiveDp,
                        factDigest,
                        mergedFacts,
                        statuses
                );
                targetEval = primaryEval.mergeWith(secondaryEval);
            } else {
                targetEval = authorizationSeam.evaluateTargetReadProjection(
                        effectiveDp,
                        factDigest,
                        mergedFacts,
                        statuses
                );
            }
        } catch (SecurityException ex) {
            return new DuplicateDraftSimulationOutcome<>(
                    false,
                    "policy-gate-denied",
                    null,
                    Set.of()
            );
        }
        DualScopeDelegationSpec dualScope = spec.dualScopeDelegationSpec();
        boolean callerCedente = spec.isCallerCedente(sourceEntity, caller);
        boolean callerCessionario = spec.isCallerCessionario(sourceEntity, caller);
        if (dualScope != null && !callerCedente && !callerCessionario) {
            return new DuplicateDraftSimulationOutcome<>(
                    false,
                    "dual-scope-custody-denied",
                    null,
                    Set.of()
            );
        }
        if (rawDraft == null) {
            return new DuplicateDraftSimulationOutcome<>(true, null, null, Set.of());
        }
        IntrospectedDtoGovernanceContract draftContract = (rawDraft instanceof Map<?, ?> || rawDraft instanceof String)
                ? responseGovernanceContract
                : dtoIntrospector.introspectWriteDto(rawDraft.getClass(), responseDtoClass, spec.resourceKey());
        Set<String> stripped = new LinkedHashSet<>();
        DraftDTO sanitized = AbstractAuthzGovernedResourceService.sanitizeDuplicateDraftWithTracking(
                rawDraft,
                responseGovernanceContract,
                draftContract,
                targetEval,
                dualScope,
                callerCedente,
                callerCessionario,
                spec.technicalConcurrencyPointers(),
                spec.mandatoryScopeAnchorAttributeIds(),
                objectMapper,
                stripped
        );
        return new DuplicateDraftSimulationOutcome<>(
                true,
                null,
                sanitized,
                stripped
        );
    }

    /**
     * Simulates a governed collection export across {@code candidateEntities} in memory,
     * filtering out entities outside the caller's tenant/data scope, stripping
     * {@code exportable = false}, {@code VALUE + DENY}, and {@code OMIT_FIELD} attributes, and
     * applying active OPA {@link MaskDirective}s ({@code Fase P10.17-B}).
     */
    @SuppressWarnings("unchecked")
    public CollectionExportSimulationOutcome simulateCollectionExport(
            AuthzCallerContext caller,
            List<E> candidateEntities,
            java.util.function.Function<E, ResponseDTO> rawResponseMapper
    ) {
        Objects.requireNonNull(caller, "caller is required");
        Objects.requireNonNull(rawResponseMapper, "rawResponseMapper is required");
        HeaderSpoofingSimulationOutcome headerGuard = simulateHeaderSpoofingGuard(caller);
        if (!headerGuard.allowed()) {
            return new CollectionExportSimulationOutcome(
                    false,
                    headerGuard.reasonCode(),
                    List.of(),
                    Set.of(),
                    Set.of()
            );
        }
        AvailabilitySimulationOutcome collectionAvail = simulateCollectionAvailability(caller, "export");
        if (!collectionAvail.allowed()) {
            return new CollectionExportSimulationOutcome(
                    false,
                    collectionAvail.reason(),
                    List.of(),
                    Set.of(),
                    Set.of()
            );
        }
        if (candidateEntities == null || candidateEntities.isEmpty()) {
            return new CollectionExportSimulationOutcome(
                    true,
                    null,
                    List.of(),
                    Set.copyOf(responseGovernanceContract.nonExportableFieldNames()),
                    Set.of()
            );
        }
        Set<String> excludedFields = new LinkedHashSet<>(responseGovernanceContract.nonExportableFieldNames());
        for (var dir : responseGovernanceContract.baselineFieldUseDirectives()) {
            if (dir.category() == org.praxisplatform.authz.contracts.decisionpoint.FieldUseCategory.VALUE
                    && dir.effect() == org.praxisplatform.authz.contracts.envelope.RuleEffect.DENY) {
                excludedFields.add(dir.attributeId());
            }
        }
        Set<String> allMaskedAttrs = new LinkedHashSet<>();
        List<Map<String, Object>> exportedRows = new ArrayList<>();
        for (E entity : candidateEntities) {
            if (entity == null) {
                continue;
            }
            ResponseDTO rawDto = rawResponseMapper.apply(entity);
            ReadSimulationOutcome<ResponseDTO> readOut = simulateTargetRead(caller, entity, rawDto);
            if (!readOut.allowed() || readOut.maskedResponse() == null) {
                continue;
            }
            allMaskedAttrs.addAll(readOut.maskedAttributeIds());
            excludedFields.addAll(readOut.valueDeniedAttributeIds());
            for (var schema : responseGovernanceContract.fieldSchemas()) {
                if (excludedFields.contains(schema.wireFieldName()) || excludedFields.contains(schema.attributeId())) {
                    excludedFields.add(schema.wireFieldName());
                    excludedFields.add(schema.attributeId());
                }
            }
            Map<String, Object> rowMap = new LinkedHashMap<>(
                    objectMapper.convertValue(readOut.maskedResponse(), Map.class)
            );
            for (String forbidden : excludedFields) {
                rowMap.remove(forbidden);
            }
            exportedRows.add(java.util.Collections.unmodifiableMap(rowMap));
        }
        return new CollectionExportSimulationOutcome(
                true,
                null,
                exportedRows,
                excludedFields,
                allMaskedAttrs
        );
    }

    /**
     * Simulates a governed non-persistent reactive determination ({@code POST} preview endpoint)
     * using the default {@code "reactive-determination"} operation ID ({@code Fase P10.18-A},
     * {@code P05}, {@code P12}, {@code P13}, {@code P14}, {@code P50}).
     */
    public ReactiveDeterminationSimulationOutcome simulateReactiveDetermination(
            AuthzCallerContext caller,
            E entity,
            Map<String, Object> rawDeterminationPayload
    ) {
        return simulateReactiveDetermination(caller, "reactive-determination", entity, rawDeterminationPayload);
    }

    /**
     * Simulates a governed non-persistent reactive determination ({@code POST} preview endpoint)
     * using the decision point resolved for {@code determinationId} ({@code Fase P10.18-A},
     * {@code P05}, {@code P12}, {@code P13}, {@code P14}, {@code P50}).
     *
     * <p>Enforces tenant hard-scope, row-level {@code spec.verifyEntityAccessAllowed}, primary
     * plus operation-specific {@code TARGET} gate parity, and detached DTO masking via
     * {@link AuthzGovernedReactiveDeterminationProvider#evaluateGovernedDetermination}.</p>
     */
    public ReactiveDeterminationSimulationOutcome simulateReactiveDetermination(
            AuthzCallerContext caller,
            String determinationId,
            E entity,
            Map<String, Object> rawDeterminationPayload
    ) {
        Objects.requireNonNull(caller, "caller is required");
        Objects.requireNonNull(entity, "entity is required");
        HeaderSpoofingSimulationOutcome headerGuard = simulateHeaderSpoofingGuard(caller);
        if (!headerGuard.allowed()) {
            return new ReactiveDeterminationSimulationOutcome(
                    false,
                    headerGuard.reasonCode(),
                    Map.of(),
                    Set.of(),
                    Set.of()
            );
        }
        if (caller.tenantId() != null) {
            String entityTenant = spec.extractTenantFromEntity(entity);
            if (entityTenant != null && !Objects.equals(caller.tenantId(), entityTenant)) {
                return new ReactiveDeterminationSimulationOutcome(
                        false,
                        "hard-scope-tenant-mismatch",
                        Map.of(),
                        Set.of(),
                        Set.of()
                );
            }
        }
        try {
            spec.verifyEntityAccessAllowed(entity, caller, null);
        } catch (SecurityException ex) {
            return new ReactiveDeterminationSimulationOutcome(
                    false,
                    "policy-gate-denied",
                    Map.of(),
                    Set.of(),
                    Set.of()
            );
        }
        Map<String, Object> mergedFacts = new LinkedHashMap<>(caller.subjectAndEnvironmentFacts());
        if (caller.tenantId() != null) {
            mergedFacts.putIfAbsent("subject.tenantId", caller.tenantId());
        }
        Map<String, Object> targetFacts = spec.extractEntityTargetFacts(entity);
        if (targetFacts != null) {
            mergedFacts.putAll(targetFacts);
        }
        Map<String, FactResolutionStatus> statuses = new LinkedHashMap<>();
        for (String key : mergedFacts.keySet()) {
            statuses.put(key, FactResolutionStatus.PRESENT);
        }
        DecisionPointDescriptor effectiveDp = spec.actionDecisionPoints()
                .getOrDefault(determinationId != null ? determinationId : "reactive-determination", spec.decisionPoint());
        String factDigest = (effectiveDp.factContractRef() != null
                        && effectiveDp.factContractRef().factContractDigest() != null)
                ? effectiveDp.factContractRef().factContractDigest()
                : spec.factContractDigest();
        try {
            TargetReadProjectionEvaluation primaryEval = authorizationSeam.evaluateTargetReadProjection(
                    spec.decisionPoint(),
                    spec.factContractDigest(),
                    mergedFacts,
                    statuses
            );
            TargetReadProjectionEvaluation eval = primaryEval;
            if (!Objects.equals(effectiveDp.identity().pointKey(), spec.decisionPoint().identity().pointKey())) {
                eval = primaryEval.mergeWith(authorizationSeam.evaluateTargetReadProjection(
                        effectiveDp,
                        factDigest,
                        mergedFacts,
                        statuses
                ));
            }
            AuthzGovernedResourceServiceSupport support = new AuthzGovernedResourceServiceSupport(
                    authorizationSeam,
                    maskingProcessor,
                    dtoIntrospector
            );
            AuthzGovernedReactiveDeterminationProvider provider = new AuthzGovernedReactiveDeterminationProvider(
                    List::of,
                    support,
                    responseGovernanceContract
            );
            Map<String, Object> maskedPayload = provider.evaluateGovernedDetermination(
                    effectiveDp,
                    factDigest,
                    mergedFacts,
                    statuses,
                    () -> rawDeterminationPayload == null ? Map.of() : rawDeterminationPayload,
                    primaryEval.valueDeniedAttributeIds(),
                    primaryEval.maskDirectives()
            );
            Set<String> maskedAttrs = new LinkedHashSet<>();
            for (MaskDirective dir : eval.maskDirectives()) {
                if (dir != null && dir.attributeId() != null) {
                    maskedAttrs.add(dir.attributeId());
                }
            }
            Set<String> valueDenied = new LinkedHashSet<>(eval.valueDeniedAttributeIds());
            for (FieldUseEffectDirective dir : responseGovernanceContract.baselineFieldUseDirectives()) {
                if (dir.category() == FieldUseCategory.VALUE
                        && dir.effect() == org.praxisplatform.authz.contracts.envelope.RuleEffect.DENY) {
                    valueDenied.add(dir.attributeId());
                }
            }
            return new ReactiveDeterminationSimulationOutcome(
                    true,
                    null,
                    maskedPayload,
                    maskedAttrs,
                    valueDenied
            );
        } catch (SecurityException ex) {
            return new ReactiveDeterminationSimulationOutcome(
                    false,
                    "policy-gate-denied",
                    Map.of(),
                    Set.of(),
                    Set.of()
            );
        }
    }

    /**
     * Simulates a governed non-persistent reactive determination in {@code CREATE} / draft form
     * mode (without an existing persisted entity {@code E}) using the default
     * {@code "reactive-determination"} operation ID ({@code Fase P10.22-B}, {@code P05},
     * {@code P12}, {@code P13}, {@code P14}, {@code P50}).
     */
    public ReactiveDeterminationSimulationOutcome simulateDraftReactiveDetermination(
            AuthzCallerContext caller,
            Map<String, Object> draftInputPayload,
            Map<String, Object> rawDeterminationOutputPayload
    ) {
        return simulateDraftReactiveDetermination(
                caller,
                "reactive-determination",
                draftInputPayload,
                rawDeterminationOutputPayload
        );
    }

    /**
     * Simulates a governed non-persistent reactive determination in {@code CREATE} / draft form
     * mode (without an existing persisted entity {@code E}) using {@code determinationId}
     * ({@code Fase P10.22-B}, {@code P05}, {@code P12}, {@code P13}, {@code P14}, {@code P50}).
     *
     * <p>Enforces anti-spoofing headers, collection-level availability, rejection of
     * {@code VALUE + DENY} ({@code SECRET} / {@code CREDENTIAL}) attributes in
     * {@code draftInputPayload}, and detached DTO masking/suppression on
     * {@code rawDeterminationOutputPayload}.</p>
     */
    public ReactiveDeterminationSimulationOutcome simulateDraftReactiveDetermination(
            AuthzCallerContext caller,
            String determinationId,
            Map<String, Object> draftInputPayload,
            Map<String, Object> rawDeterminationOutputPayload
    ) {
        Objects.requireNonNull(caller, "caller is required");
        HeaderSpoofingSimulationOutcome headerGuard = simulateHeaderSpoofingGuard(caller);
        if (!headerGuard.allowed()) {
            return new ReactiveDeterminationSimulationOutcome(
                    false,
                    headerGuard.reasonCode(),
                    Map.of(),
                    Set.of(),
                    Set.of()
            );
        }
        AvailabilitySimulationOutcome collectionAvail = simulateCollectionAvailability(caller, "create");
        if (!collectionAvail.allowed()) {
            return new ReactiveDeterminationSimulationOutcome(
                    false,
                    collectionAvail.reason(),
                    Map.of(),
                    Set.of(),
                    Set.of()
            );
        }
        Set<String> staticValueDenied = new LinkedHashSet<>();
        for (FieldUseEffectDirective dir : responseGovernanceContract.baselineFieldUseDirectives()) {
            if (dir.category() == FieldUseCategory.VALUE
                    && dir.effect() == org.praxisplatform.authz.contracts.envelope.RuleEffect.DENY) {
                staticValueDenied.add(dir.attributeId());
            }
        }
        if (draftInputPayload != null && !draftInputPayload.isEmpty()) {
            for (String inputKey : draftInputPayload.keySet()) {
                if (inputKey == null || inputKey.isBlank()) {
                    continue;
                }
                String cleanKey = inputKey.startsWith("/") ? inputKey.substring(1) : inputKey;
                String mappedAttr = responseGovernanceContract.wirePointerToAttributeIdMap().get("/" + cleanKey);
                if (staticValueDenied.contains(cleanKey)
                        || (mappedAttr != null && staticValueDenied.contains(mappedAttr))) {
                    return new ReactiveDeterminationSimulationOutcome(
                            false,
                            "draft-input-value-denied",
                            Map.of(),
                            Set.of(),
                            staticValueDenied
                    );
                }
            }
        }
        Map<String, Object> mergedFacts = new LinkedHashMap<>(caller.subjectAndEnvironmentFacts());
        if (caller.tenantId() != null) {
            mergedFacts.putIfAbsent("subject.tenantId", caller.tenantId());
            mergedFacts.putIfAbsent("resource.tenantId", caller.tenantId());
        }
        if (draftInputPayload != null && !draftInputPayload.isEmpty()) {
            for (Map.Entry<String, Object> entry : draftInputPayload.entrySet()) {
                String rawKey = entry.getKey();
                Object val = entry.getValue();
                if (rawKey == null || rawKey.isBlank() || val == null) {
                    continue;
                }
                String cleanKey = rawKey.startsWith("/") ? rawKey.substring(1) : rawKey;
                mergedFacts.putIfAbsent(cleanKey, val);
                if (!cleanKey.startsWith("resource.") && !cleanKey.startsWith("subject.")) {
                    mergedFacts.putIfAbsent("resource." + cleanKey, val);
                }
                if (spec.fieldBindings() != null) {
                    for (var binding : spec.fieldBindings()) {
                        if (cleanKey.equals(binding.nativeJpaPath())
                                || cleanKey.equals(binding.fieldPath())
                                || ("resource." + cleanKey).equals(binding.fieldPath())) {
                            mergedFacts.putIfAbsent(binding.fieldPath(), val);
                        }
                    }
                }
            }
        }
        Map<String, FactResolutionStatus> statuses = new LinkedHashMap<>();
        for (String key : mergedFacts.keySet()) {
            statuses.put(key, FactResolutionStatus.PRESENT);
        }
        DecisionPointDescriptor effectiveDp = spec.actionDecisionPoints()
                .getOrDefault(determinationId != null ? determinationId : "reactive-determination", spec.decisionPoint());
        String factDigest = (effectiveDp.factContractRef() != null
                        && effectiveDp.factContractRef().factContractDigest() != null)
                ? effectiveDp.factContractRef().factContractDigest()
                : spec.factContractDigest();
        try {
            TargetReadProjectionEvaluation primaryEval = authorizationSeam.evaluateTargetReadProjection(
                    spec.decisionPoint(),
                    spec.factContractDigest(),
                    mergedFacts,
                    statuses
            );
            TargetReadProjectionEvaluation eval = primaryEval;
            if (!Objects.equals(effectiveDp.identity().pointKey(), spec.decisionPoint().identity().pointKey())) {
                eval = primaryEval.mergeWith(authorizationSeam.evaluateTargetReadProjection(
                        effectiveDp,
                        factDigest,
                        mergedFacts,
                        statuses
                ));
            }
            AuthzGovernedResourceServiceSupport support = new AuthzGovernedResourceServiceSupport(
                    authorizationSeam,
                    maskingProcessor,
                    dtoIntrospector
            );
            AuthzGovernedReactiveDeterminationProvider provider = new AuthzGovernedReactiveDeterminationProvider(
                    List::of,
                    support,
                    responseGovernanceContract
            );
            Map<String, Object> maskedPayload = provider.evaluateGovernedDetermination(
                    effectiveDp,
                    factDigest,
                    mergedFacts,
                    statuses,
                    () -> rawDeterminationOutputPayload == null ? Map.of() : rawDeterminationOutputPayload,
                    primaryEval.valueDeniedAttributeIds(),
                    primaryEval.maskDirectives()
            );
            Set<String> maskedAttrs = new LinkedHashSet<>();
            for (MaskDirective dir : eval.maskDirectives()) {
                if (dir != null && dir.attributeId() != null) {
                    maskedAttrs.add(dir.attributeId());
                }
            }
            Set<String> valueDenied = new LinkedHashSet<>(eval.valueDeniedAttributeIds());
            valueDenied.addAll(staticValueDenied);
            return new ReactiveDeterminationSimulationOutcome(
                    true,
                    null,
                    maskedPayload,
                    maskedAttrs,
                    valueDenied
            );
        } catch (SecurityException ex) {
            return new ReactiveDeterminationSimulationOutcome(
                    false,
                    "policy-gate-denied",
                    Map.of(),
                    Set.of(),
                    Set.of()
            );
        }
    }

    /**
     * Filters a raw list of {@link org.praxisplatform.uischema.exporting.CollectionExportField}s
     * for capability/schema discovery using the introspected {@code ResponseDTO} governance
     * contract ({@code Fase P10.22-B}, {@code P10}, {@code P16}, {@code P46}).
     */
    public List<org.praxisplatform.uischema.exporting.CollectionExportField> simulateFilteredExportFields(
            List<org.praxisplatform.uischema.exporting.CollectionExportField> rawExportFields
    ) {
        return AuthzGovernedCollectionExportExecutor.filterDiscoveryExportFields(
                rawExportFields,
                responseGovernanceContract
        );
    }

    /**
     * Simulates keyset/cursor pagination ({@code filterByCursor}) across {@code candidateEntities}
     * without custom filter/sort constraints ({@code Fase P10.23-B}, {@code P05}, {@code P06},
     * {@code P07}, {@code P12}, {@code P50}).
     */
    public <ID> CursorFilterSimulationOutcome<ID, ResponseDTO> simulateCursorFilter(
            AuthzCallerContext caller,
            List<E> candidateEntities,
            java.util.function.Function<E, ID> idExtractor,
            java.util.function.Function<E, ResponseDTO> rawDtoMapper,
            ID afterId,
            int pageSize
    ) {
        return simulateCursorFilter(
                caller,
                candidateEntities,
                idExtractor,
                rawDtoMapper,
                null,
                Set.of(),
                afterId,
                null,
                pageSize
        );
    }

    /**
     * Simulates keyset/cursor pagination ({@code filterByCursor}) across {@code candidateEntities}
     * enforcing anti-spoofing headers, pre-SQL {@link FieldUseCategory#FILTER} and
     * {@link FieldUseCategory#SORT} guards, {@code DataScopePlan} row scoping, keyset cursor slicing
     * ({@code afterId} / {@code beforeId} / {@code pageSize}), and detached DTO masking
     * ({@code Fase P10.23-B}, {@code P05}, {@code P06}, {@code P07}, {@code P12}, {@code P13},
     * {@code P14}, {@code P50}).
     */
    public <ID> CursorFilterSimulationOutcome<ID, ResponseDTO> simulateCursorFilter(
            AuthzCallerContext caller,
            List<E> candidateEntities,
            java.util.function.Function<E, ID> idExtractor,
            java.util.function.Function<E, ResponseDTO> rawDtoMapper,
            Object filterDto,
            Set<String> sortProperties,
            ID afterId,
            ID beforeId,
            int pageSize
    ) {
        Objects.requireNonNull(caller, "caller is required");
        Objects.requireNonNull(idExtractor, "idExtractor is required");
        Objects.requireNonNull(rawDtoMapper, "rawDtoMapper is required");
        int effectivePageSize = Math.max(1, pageSize);
        HeaderSpoofingSimulationOutcome headerGuard = simulateHeaderSpoofingGuard(caller);
        if (!headerGuard.allowed()) {
            return new CursorFilterSimulationOutcome<>(
                    false,
                    headerGuard.reasonCode(),
                    null,
                    Set.of(),
                    List.of(),
                    List.of(),
                    null,
                    null,
                    effectivePageSize
            );
        }
        Sort effectiveSort = (sortProperties == null || sortProperties.isEmpty())
                ? Sort.unsorted()
                : Sort.by(sortProperties.stream().filter(Objects::nonNull).toArray(String[]::new));
        QueryFieldUseSimulationOutcome fieldUseOut = simulateFilterAndSortFieldUse(caller, filterDto, effectiveSort);
        if (!fieldUseOut.allowed()) {
            return new CursorFilterSimulationOutcome<>(
                    false,
                    fieldUseOut.denialReason(),
                    fieldUseOut.violatedCategory(),
                    fieldUseOut.violatedAttributeIds(),
                    List.of(),
                    List.of(),
                    null,
                    null,
                    effectivePageSize
            );
        }
        AvailabilitySimulationOutcome collectionAvail = simulateCollectionAvailability(caller, "filter");
        if (!collectionAvail.allowed()) {
            return new CursorFilterSimulationOutcome<>(
                    false,
                    collectionAvail.reason(),
                    null,
                    Set.of(),
                    List.of(),
                    List.of(),
                    null,
                    null,
                    effectivePageSize
            );
        }
        List<ID> allAuthorizedIds = new ArrayList<>();
        List<ResponseDTO> allMaskedItems = new ArrayList<>();
        if (candidateEntities != null) {
            for (E entity : candidateEntities) {
                if (entity == null) {
                    continue;
                }
                ResponseDTO rawDto = rawDtoMapper.apply(entity);
                ReadSimulationOutcome<ResponseDTO> readOut = simulateTargetRead(caller, entity, rawDto);
                if (readOut.allowed() && readOut.maskedResponse() != null) {
                    allAuthorizedIds.add(idExtractor.apply(entity));
                    allMaskedItems.add(readOut.maskedResponse());
                }
            }
        }
        int startIdx = 0;
        int endIdx = allAuthorizedIds.size();
        if (afterId != null) {
            int pos = allAuthorizedIds.indexOf(afterId);
            startIdx = pos >= 0 ? pos + 1 : allAuthorizedIds.size();
        }
        if (beforeId != null) {
            int pos = allAuthorizedIds.indexOf(beforeId);
            if (pos >= 0) {
                endIdx = Math.min(endIdx, pos);
                startIdx = Math.max(startIdx, endIdx - effectivePageSize);
            }
        }
        int sliceEnd = Math.min(endIdx, startIdx + effectivePageSize);
        if (startIdx > sliceEnd) {
            startIdx = sliceEnd;
        }
        List<ID> pageIds = List.copyOf(allAuthorizedIds.subList(startIdx, sliceEnd));
        List<ResponseDTO> pageItems = List.copyOf(allMaskedItems.subList(startIdx, sliceEnd));
        String nextCursor = sliceEnd < allAuthorizedIds.size() && !pageIds.isEmpty()
                ? "cursor:after:" + pageIds.get(pageIds.size() - 1)
                : null;
        String prevCursor = startIdx > 0 && !pageIds.isEmpty()
                ? "cursor:before:" + pageIds.get(0)
                : null;
        return new CursorFilterSimulationOutcome<>(
                true,
                null,
                null,
                Set.of(),
                pageIds,
                pageItems,
                nextCursor,
                prevCursor,
                effectivePageSize
        );
    }

    /**
     * Simulates {@code AbstractBaseQueryResourceService.locate(filterDto, sort, targetId)} across
     * {@code candidateEntities} without custom filter/sort constraints ({@code Fase P10.24-B},
     * {@code P05}, {@code P06}, {@code P07}, {@code P50}).
     */
    public <ID> LocateSimulationOutcome<ID> simulateLocate(
            AuthzCallerContext caller,
            List<E> candidateEntities,
            java.util.function.Function<E, ID> idExtractor,
            java.util.function.Function<E, ResponseDTO> rawDtoMapper,
            ID targetId
    ) {
        return simulateLocate(
                caller,
                candidateEntities,
                idExtractor,
                rawDtoMapper,
                null,
                Set.of(),
                targetId
        );
    }

    /**
     * Simulates {@code AbstractBaseQueryResourceService.locate(filterDto, sort, targetId)} across
     * {@code candidateEntities}, enforcing anti-spoofing headers, pre-SQL
     * {@link FieldUseCategory#FILTER} and {@link FieldUseCategory#SORT} guards, collection
     * availability ({@code "filter"}), and zero out-of-scope existence leakage ({@code OptionalLong.empty()}
     * when {@code targetId} is cross-tenant or out-of-scope) ({@code Fase P10.24-B}, {@code P05},
     * {@code P06}, {@code P07}, {@code P13}, {@code P14}, {@code P50}).
     */
    public <ID> LocateSimulationOutcome<ID> simulateLocate(
            AuthzCallerContext caller,
            List<E> candidateEntities,
            java.util.function.Function<E, ID> idExtractor,
            java.util.function.Function<E, ResponseDTO> rawDtoMapper,
            Object filterDto,
            Set<String> sortProperties,
            ID targetId
    ) {
        Objects.requireNonNull(caller, "caller is required");
        Objects.requireNonNull(idExtractor, "idExtractor is required");
        Objects.requireNonNull(rawDtoMapper, "rawDtoMapper is required");
        HeaderSpoofingSimulationOutcome headerGuard = simulateHeaderSpoofingGuard(caller);
        if (!headerGuard.allowed()) {
            return new LocateSimulationOutcome<>(
                    false,
                    headerGuard.reasonCode(),
                    null,
                    Set.of(),
                    targetId,
                    java.util.OptionalLong.empty(),
                    List.of()
            );
        }
        Sort effectiveSort = (sortProperties == null || sortProperties.isEmpty())
                ? Sort.unsorted()
                : Sort.by(sortProperties.stream().filter(Objects::nonNull).toArray(String[]::new));
        QueryFieldUseSimulationOutcome fieldUseOut = simulateFilterAndSortFieldUse(caller, filterDto, effectiveSort);
        if (!fieldUseOut.allowed()) {
            return new LocateSimulationOutcome<>(
                    false,
                    fieldUseOut.denialReason(),
                    fieldUseOut.violatedCategory(),
                    fieldUseOut.violatedAttributeIds(),
                    targetId,
                    java.util.OptionalLong.empty(),
                    List.of()
            );
        }
        AvailabilitySimulationOutcome collectionAvail = simulateCollectionAvailability(caller, "filter");
        if (!collectionAvail.allowed()) {
            return new LocateSimulationOutcome<>(
                    false,
                    collectionAvail.reason(),
                    null,
                    Set.of(),
                    targetId,
                    java.util.OptionalLong.empty(),
                    List.of()
            );
        }
        List<ID> allAuthorizedIds = new ArrayList<>();
        if (candidateEntities != null) {
            for (E entity : candidateEntities) {
                if (entity == null) {
                    continue;
                }
                ResponseDTO rawDto = rawDtoMapper.apply(entity);
                ReadSimulationOutcome<ResponseDTO> readOut = simulateTargetRead(caller, entity, rawDto);
                if (readOut.allowed() && readOut.maskedResponse() != null) {
                    allAuthorizedIds.add(idExtractor.apply(entity));
                }
            }
        }
        int pos = targetId != null ? allAuthorizedIds.indexOf(targetId) : -1;
        java.util.OptionalLong locatedIndex = pos >= 0
                ? java.util.OptionalLong.of(pos)
                : java.util.OptionalLong.empty();
        return new LocateSimulationOutcome<>(
                true,
                null,
                null,
                Set.of(),
                targetId,
                locatedIndex,
                allAuthorizedIds
        );
    }

    /**
     * Simulates {@code AbstractBaseQueryResourceService.findAllById(Collection<ID> ids)} across
     * {@code candidateEntities}, preserving requested ID order, silently omitting out-of-scope or
     * cross-tenant IDs ({@code P06}, {@code P07}), and applying detached DTO masking
     * ({@code Fase P10.24-B}, {@code P05}, {@code P06}, {@code P07}, {@code P12}, {@code P50}).
     */
    public <ID> FindAllByIdSimulationOutcome<ID, ResponseDTO> simulateFindAllById(
            AuthzCallerContext caller,
            List<E> candidateEntities,
            java.util.function.Function<E, ID> idExtractor,
            java.util.function.Function<E, ResponseDTO> rawDtoMapper,
            java.util.Collection<ID> requestedIds
    ) {
        Objects.requireNonNull(caller, "caller is required");
        Objects.requireNonNull(idExtractor, "idExtractor is required");
        Objects.requireNonNull(rawDtoMapper, "rawDtoMapper is required");
        List<ID> requestedList = requestedIds == null ? List.of() : List.copyOf(requestedIds);
        HeaderSpoofingSimulationOutcome headerGuard = simulateHeaderSpoofingGuard(caller);
        if (!headerGuard.allowed()) {
            return new FindAllByIdSimulationOutcome<>(
                    false,
                    headerGuard.reasonCode(),
                    requestedList,
                    List.of(),
                    List.of()
            );
        }
        AvailabilitySimulationOutcome collectionAvail = simulateCollectionAvailability(caller, "filter");
        if (!collectionAvail.allowed()) {
            return new FindAllByIdSimulationOutcome<>(
                    false,
                    collectionAvail.reason(),
                    requestedList,
                    List.of(),
                    List.of()
            );
        }
        Map<ID, E> entityById = new LinkedHashMap<>();
        if (candidateEntities != null) {
            for (E entity : candidateEntities) {
                if (entity != null) {
                    ID id = idExtractor.apply(entity);
                    if (id != null) {
                        entityById.putIfAbsent(id, entity);
                    }
                }
            }
        }
        List<ID> authorizedIds = new ArrayList<>();
        List<ResponseDTO> maskedItems = new ArrayList<>();
        for (ID reqId : requestedList) {
            E entity = entityById.get(reqId);
            if (entity == null) {
                continue;
            }
            ResponseDTO rawDto = rawDtoMapper.apply(entity);
            ReadSimulationOutcome<ResponseDTO> readOut = simulateTargetRead(caller, entity, rawDto);
            if (readOut.allowed() && readOut.maskedResponse() != null) {
                authorizedIds.add(reqId);
                maskedItems.add(readOut.maskedResponse());
            }
        }
        return new FindAllByIdSimulationOutcome<>(
                true,
                null,
                requestedList,
                authorizedIds,
                maskedItems
        );
    }

    /**
     * Simulates an AI Context / Tool Grounding projection using the default {@code "ai-context"}
     * operation ID ({@code Fase P10.18-A}, {@code P47}, {@code P57}, {@code P62}).
     */
    public AiContextSimulationOutcome simulateAiContextProjection(
            AuthzCallerContext caller,
            E entity,
            ResponseDTO rawResponseDto
    ) {
        return simulateAiContextProjection(caller, "ai-context", entity, rawResponseDto);
    }

    /**
     * Simulates an AI Context / Tool Grounding projection using the decision point resolved for
     * {@code operationId} ({@code Fase P10.18-A}, {@code P47}, {@code P57}, {@code P62}).
     *
     * <p>Enforces tenant hard-scope, row-level {@code spec.verifyEntityAccessAllowed}, primary
     * plus operation-specific {@code TARGET} gate parity, and complete suppression of
     * {@code aiAllowed = false} / {@code LGPD_SENSITIVE_DATA} attributes via
     * {@link AuthzGovernedReactiveDeterminationProvider#projectGovernedAiContext}.</p>
     */
    public AiContextSimulationOutcome simulateAiContextProjection(
            AuthzCallerContext caller,
            String operationId,
            E entity,
            ResponseDTO rawResponseDto
    ) {
        Objects.requireNonNull(caller, "caller is required");
        Objects.requireNonNull(entity, "entity is required");
        HeaderSpoofingSimulationOutcome headerGuard = simulateHeaderSpoofingGuard(caller);
        if (!headerGuard.allowed()) {
            return new AiContextSimulationOutcome(
                    false,
                    headerGuard.reasonCode(),
                    null,
                    List.of(),
                    Set.of(),
                    Map.of()
            );
        }
        if (caller.tenantId() != null) {
            String entityTenant = spec.extractTenantFromEntity(entity);
            if (entityTenant != null && !Objects.equals(caller.tenantId(), entityTenant)) {
                return new AiContextSimulationOutcome(
                        false,
                        "hard-scope-tenant-mismatch",
                        null,
                        List.of(),
                        Set.of(),
                        Map.of()
                );
            }
        }
        try {
            spec.verifyEntityAccessAllowed(entity, caller, null);
        } catch (SecurityException ex) {
            return new AiContextSimulationOutcome(
                    false,
                    "policy-gate-denied",
                    null,
                    List.of(),
                    Set.of(),
                    Map.of()
            );
        }
        Map<String, Object> mergedFacts = new LinkedHashMap<>(caller.subjectAndEnvironmentFacts());
        if (caller.tenantId() != null) {
            mergedFacts.putIfAbsent("subject.tenantId", caller.tenantId());
        }
        Map<String, Object> targetFacts = spec.extractEntityTargetFacts(entity);
        if (targetFacts != null) {
            mergedFacts.putAll(targetFacts);
        }
        Map<String, FactResolutionStatus> statuses = new LinkedHashMap<>();
        for (String key : mergedFacts.keySet()) {
            statuses.put(key, FactResolutionStatus.PRESENT);
        }
        String cleanOp = operationId != null ? operationId : "ai-context";
        DecisionPointDescriptor effectiveDp = spec.actionDecisionPoints()
                .getOrDefault(cleanOp, spec.surfaceDecisionPoints().getOrDefault(cleanOp, spec.decisionPoint()));
        String factDigest = (effectiveDp.factContractRef() != null
                        && effectiveDp.factContractRef().factContractDigest() != null)
                ? effectiveDp.factContractRef().factContractDigest()
                : spec.factContractDigest();
        try {
            TargetReadProjectionEvaluation primaryEval = authorizationSeam.evaluateTargetReadProjection(
                    spec.decisionPoint(),
                    spec.factContractDigest(),
                    mergedFacts,
                    statuses
            );
            AuthzGovernedResourceServiceSupport support = new AuthzGovernedResourceServiceSupport(
                    authorizationSeam,
                    maskingProcessor,
                    dtoIntrospector
            );
            AuthzGovernedReactiveDeterminationProvider provider = new AuthzGovernedReactiveDeterminationProvider(
                    List::of,
                    support,
                    responseGovernanceContract
            );
            SanitizedAiToolProjection projection = provider.projectGovernedAiContext(
                    effectiveDp,
                    factDigest,
                    null,
                    null,
                    rawResponseDto != null ? rawResponseDto : entity,
                    mergedFacts,
                    statuses,
                    primaryEval.valueDeniedAttributeIds(),
                    primaryEval.maskDirectives()
            );
            return new AiContextSimulationOutcome(
                    true,
                    null,
                    projection,
                    projection.allowedWireColumns(),
                    projection.suppressedAiAttributeIds(),
                    projection.detachedPayload()
            );
        } catch (SecurityException ex) {
            return new AiContextSimulationOutcome(
                    false,
                    "policy-gate-denied",
                    null,
                    List.of(),
                    Set.of(),
                    Map.of()
            );
        }
    }

    /**
     * Simulates query field-use eligibility ({@code FILTER}, {@code SORT}, {@code GROUP},
     * {@code AGGREGATE}, {@code JOIN}) against static {@code @DomainGovernance} baseline directives
     * and live {@code SEARCH} evaluation {@link FieldUseEffectDirective}s ({@code Fase P10.18-B},
     * {@code P13}, {@code P14}, {@code P50}).
     *
     * <p>Attribute tokens in {@code requestedFieldUses} may be passed either as wire field names
     * (e.g. {@code "cidCodigo"}) or canonical {@code attributeId}s
     * (e.g. {@code "resource.payroll_leave.cidCodigo"}).</p>
     */
    public QueryFieldUseSimulationOutcome simulateQueryFieldUse(
            AuthzCallerContext caller,
            Map<FieldUseCategory, Set<String>> requestedFieldUses
    ) {
        Objects.requireNonNull(caller, "caller is required");
        HeaderSpoofingSimulationOutcome headerGuard = simulateHeaderSpoofingGuard(caller);
        if (!headerGuard.allowed()) {
            return new QueryFieldUseSimulationOutcome(
                    false,
                    headerGuard.reasonCode(),
                    null,
                    Set.of(),
                    responseGovernanceContract.baselineFieldUseDirectives()
            );
        }
        Map<String, Object> subjectFacts = new LinkedHashMap<>(caller.subjectAndEnvironmentFacts());
        if (caller.tenantId() != null) {
            subjectFacts.putIfAbsent("subject.tenantId", caller.tenantId());
        }
        Map<String, FactResolutionStatus> statuses = new LinkedHashMap<>();
        for (String key : subjectFacts.keySet()) {
            statuses.put(key, FactResolutionStatus.PRESENT);
        }
        Map<FieldUseCategory, Set<String>> normalizedUses = normalizeRequestedQueryFieldUses(requestedFieldUses);
        try {
            List<FieldUseEffectDirective> combined = authorizationSeam.validateSearchQueryFieldUses(
                    spec.decisionPoint(),
                    spec.factContractDigest(),
                    subjectFacts,
                    statuses,
                    normalizedUses,
                    responseGovernanceContract.baselineFieldUseDirectives()
            );
            return new QueryFieldUseSimulationOutcome(
                    true,
                    null,
                    null,
                    Set.of(),
                    combined
            );
        } catch (FieldUseViolationException ex) {
            return new QueryFieldUseSimulationOutcome(
                    false,
                    "field-use-denied",
                    ex.getCategory(),
                    ex.getForbiddenAttributeIds(),
                    responseGovernanceContract.baselineFieldUseDirectives()
            );
        } catch (SecurityException ex) {
            return new QueryFieldUseSimulationOutcome(
                    false,
                    "policy-gate-denied",
                    null,
                    Set.of(),
                    responseGovernanceContract.baselineFieldUseDirectives()
            );
        }
    }

    /**
     * Extracts {@link FieldUseCategory#FILTER} and {@link FieldUseCategory#SORT} uses directly from
     * a runtime {@code filterDto} instance and {@link Sort} specification and simulates their
     * eligibility against static and dynamic {@link FieldUseEffectDirective}s ({@code Fase P10.18-B}).
     */
    public QueryFieldUseSimulationOutcome simulateFilterAndSortFieldUse(
            AuthzCallerContext caller,
            Object filterDto,
            Sort sort
    ) {
        Map<FieldUseCategory, Set<String>> extracted = dtoIntrospector.extractQueryFieldUses(
                filterDto,
                sort,
                responseGovernanceContract,
                spec
        );
        return simulateQueryFieldUse(caller, extracted);
    }

    /**
     * Simulates analytical {@code GROUP BY} and {@code AGGREGATE} metric eligibility against
     * static {@code @DomainGovernance} baseline directives and live {@code SEARCH} evaluation
     * {@link FieldUseEffectDirective}s ({@code Fase P10.19-A}, {@code P05}, {@code P08},
     * {@code P10}, {@code P14}, {@code P46}, {@code P50}).
     */
    public StatsSimulationOutcome simulateGroupByStats(
            AuthzCallerContext caller,
            String groupByField,
            Set<String> metricFields
    ) {
        return simulateGroupByStats(caller, groupByField, metricFields, null);
    }

    /**
     * Simulates analytical {@code GROUP BY}, {@code AGGREGATE}, and {@code FILTER} eligibility
     * including a runtime {@code filterDto} ({@code Fase P10.20-B}, {@code P05}, {@code P08},
     * {@code P10}, {@code P14}, {@code P46}, {@code P50}).
     */
    public StatsSimulationOutcome simulateGroupByStats(
            AuthzCallerContext caller,
            String groupByField,
            Set<String> metricFields,
            Object filterDto
    ) {
        Map<FieldUseCategory, Set<String>> uses = new LinkedHashMap<>();
        if (filterDto != null) {
            Map<FieldUseCategory, Set<String>> extracted = dtoIntrospector.extractQueryFieldUses(
                    filterDto,
                    null,
                    responseGovernanceContract,
                    spec
            );
            Set<String> filterAttrs = extracted.get(FieldUseCategory.FILTER);
            if (filterAttrs != null && !filterAttrs.isEmpty()) {
                uses.put(FieldUseCategory.FILTER, filterAttrs);
            }
        }
        if (groupByField != null && !groupByField.isBlank()) {
            uses.put(FieldUseCategory.GROUP, Set.of(groupByField.trim()));
        }
        if (metricFields != null && !metricFields.isEmpty()) {
            uses.put(FieldUseCategory.AGGREGATE, metricFields);
        }
        QueryFieldUseSimulationOutcome qOut = simulateQueryFieldUse(caller, uses);
        return new StatsSimulationOutcome(
                qOut.allowed(),
                qOut.denialReason(),
                qOut.violatedCategory(),
                qOut.violatedAttributeIds()
        );
    }

    /**
     * Simulates analytical {@code TimeSeries} ({@code /stats/timeseries}) eligibility for
     * {@code timeField} ({@link FieldUseCategory#GROUP}) and {@code metricFields}
     * ({@link FieldUseCategory#AGGREGATE}) ({@code Fase P10.20-B}).
     */
    public StatsSimulationOutcome simulateTimeSeriesStats(
            AuthzCallerContext caller,
            String timeField,
            Set<String> metricFields
    ) {
        return simulateGroupByStats(caller, timeField, metricFields, null);
    }

    /**
     * Simulates analytical {@code TimeSeries} ({@code /stats/timeseries}) eligibility including
     * a runtime {@code filterDto} ({@code Fase P10.20-B}).
     */
    public StatsSimulationOutcome simulateTimeSeriesStats(
            AuthzCallerContext caller,
            String timeField,
            Set<String> metricFields,
            Object filterDto
    ) {
        return simulateGroupByStats(caller, timeField, metricFields, filterDto);
    }

    /**
     * Simulates analytical {@code Distribution} ({@code /stats/distribution}) eligibility for
     * {@code distributionField} ({@link FieldUseCategory#GROUP}) and optional {@code metricField}
     * ({@link FieldUseCategory#AGGREGATE}) ({@code Fase P10.20-B}).
     */
    public StatsSimulationOutcome simulateDistributionStats(
            AuthzCallerContext caller,
            String distributionField,
            String metricField
    ) {
        return simulateDistributionStats(caller, distributionField, metricField, null);
    }

    /**
     * Simulates analytical {@code Distribution} ({@code /stats/distribution}) eligibility including
     * a runtime {@code filterDto} ({@code Fase P10.20-B}).
     */
    public StatsSimulationOutcome simulateDistributionStats(
            AuthzCallerContext caller,
            String distributionField,
            String metricField,
            Object filterDto
    ) {
        Set<String> metrics = (metricField == null || metricField.isBlank())
                ? Set.of()
                : Set.of(metricField.trim());
        return simulateGroupByStats(caller, distributionField, metrics, filterDto);
    }

    /**
     * Simulates analytical {@code Comparison} ({@code /stats/comparison}) eligibility across
     * {@code dimensionField} ({@link FieldUseCategory#GROUP}), {@code metricFields}
     * ({@link FieldUseCategory#AGGREGATE}), {@code primaryFilterDto} ({@link FieldUseCategory#FILTER}),
     * and {@code comparisonFilterDto} ({@link FieldUseCategory#FILTER}) ({@code Fase P10.20-B}).
     */
    public StatsSimulationOutcome simulateComparisonStats(
            AuthzCallerContext caller,
            String dimensionField,
            Set<String> metricFields,
            Object primaryFilterDto,
            Object comparisonFilterDto
    ) {
        Map<FieldUseCategory, Set<String>> uses = new LinkedHashMap<>();
        Set<String> mergedFilterAttrs = new LinkedHashSet<>();
        if (primaryFilterDto != null) {
            Map<FieldUseCategory, Set<String>> extractedPrimary = dtoIntrospector.extractQueryFieldUses(
                    primaryFilterDto,
                    null,
                    responseGovernanceContract,
                    spec
            );
            Set<String> attrs = extractedPrimary.get(FieldUseCategory.FILTER);
            if (attrs != null) {
                mergedFilterAttrs.addAll(attrs);
            }
        }
        if (comparisonFilterDto != null) {
            Map<FieldUseCategory, Set<String>> extractedComp = dtoIntrospector.extractQueryFieldUses(
                    comparisonFilterDto,
                    null,
                    responseGovernanceContract,
                    spec
            );
            Set<String> attrs = extractedComp.get(FieldUseCategory.FILTER);
            if (attrs != null) {
                mergedFilterAttrs.addAll(attrs);
            }
        }
        if (!mergedFilterAttrs.isEmpty()) {
            uses.put(FieldUseCategory.FILTER, mergedFilterAttrs);
        }
        if (dimensionField != null && !dimensionField.isBlank()) {
            uses.put(FieldUseCategory.GROUP, Set.of(dimensionField.trim()));
        }
        if (metricFields != null && !metricFields.isEmpty()) {
            uses.put(FieldUseCategory.AGGREGATE, metricFields);
        }
        QueryFieldUseSimulationOutcome qOut = simulateQueryFieldUse(caller, uses);
        return new StatsSimulationOutcome(
                qOut.allowed(),
                qOut.denialReason(),
                qOut.violatedCategory(),
                qOut.violatedAttributeIds()
        );
    }

    /**
     * Filters a raw {@link StatsFieldRegistry} for capability/schema discovery using the
     * introspected {@code ResponseDTO} governance contract ({@code Fase P10.19-A}, {@code P10}, {@code P46}).
     */
    public StatsFieldRegistry simulateFilteredStatsRegistry(StatsFieldRegistry rawRegistry) {
        AuthzGovernedResourceServiceSupport support = new AuthzGovernedResourceServiceSupport(
                authorizationSeam,
                maskingProcessor,
                dtoIntrospector
        );
        AuthzGovernedStatsQueryExecutor executor = new AuthzGovernedStatsQueryExecutor(
                new org.praxisplatform.uischema.stats.service.StatsQueryExecutor() {
                    @Override
                    public <T> org.praxisplatform.uischema.stats.dto.GroupByStatsResponse executeGroupBy(
                            jakarta.persistence.EntityManager em,
                            Class<T> entityClass,
                            org.springframework.data.jpa.domain.Specification<T> spec,
                            StatsFieldDescriptor groupDescriptor,
                            List<org.praxisplatform.uischema.stats.service.ResolvedStatsMetric> resolvedMetrics,
                            org.praxisplatform.uischema.stats.dto.GroupByStatsRequest<?> request,
                            int maxBuckets
                    ) {
                        throw new UnsupportedOperationException();
                    }

                    @Override
                    public <T> org.praxisplatform.uischema.stats.dto.TimeSeriesStatsResponse executeTimeSeries(
                            jakarta.persistence.EntityManager em,
                            Class<T> entityClass,
                            org.springframework.data.jpa.domain.Specification<T> spec,
                            StatsFieldDescriptor timeDescriptor,
                            List<org.praxisplatform.uischema.stats.service.ResolvedStatsMetric> resolvedMetrics,
                            org.praxisplatform.uischema.stats.dto.TimeSeriesStatsRequest<?> request,
                            int maxPoints
                    ) {
                        throw new UnsupportedOperationException();
                    }

                    @Override
                    public <T> org.praxisplatform.uischema.stats.dto.DistributionStatsResponse executeDistribution(
                            jakarta.persistence.EntityManager em,
                            Class<T> entityClass,
                            org.springframework.data.jpa.domain.Specification<T> spec,
                            StatsFieldDescriptor distributionDescriptor,
                            StatsFieldDescriptor metricDescriptor,
                            org.praxisplatform.uischema.stats.dto.DistributionStatsRequest<?> request,
                            int maxBuckets
                    ) {
                        throw new UnsupportedOperationException();
                    }
                },
                support,
                responseGovernanceContract,
                spec
        );
        return executor.filterStatsFieldRegistry(rawRegistry);
    }

    /**
     * Simulates a governed {@code OptionSource} filter/byIds execution across {@code candidateEntities}
     * using default {@link OptionSourceOperation#FILTER} semantics ({@code Fase P10.19-A},
     * {@code P05}, {@code P06}, {@code P07}, {@code P09}, {@code P12}, {@code P50}).
     */
    public OptionSourceSimulationOutcome simulateOptionSource(
            AuthzCallerContext caller,
            List<E> candidateEntities,
            java.util.function.Function<E, OptionDTO<Object>> rawOptionMapper
    ) {
        return simulateOptionSource(
                caller,
                candidateEntities,
                rawOptionMapper,
                null,
                OptionSourceOperation.FILTER,
                List.of()
        );
    }

    /**
     * Simulates a governed {@code OptionSource} execution across {@code candidateEntities} with an
     * explicit {@link OptionSourceDescriptor}, {@link OptionSourceOperation}, and
     * {@code includeOrByIds} reload list ({@code Fase P10.19-A}, {@code P05}, {@code P06},
     * {@code P07}, {@code P09}, {@code P12}, {@code P50}).
     */
    public OptionSourceSimulationOutcome simulateOptionSource(
            AuthzCallerContext caller,
            List<E> candidateEntities,
            java.util.function.Function<E, OptionDTO<Object>> rawOptionMapper,
            OptionSourceDescriptor descriptor,
            OptionSourceOperation operation,
            java.util.Collection<Object> includeOrByIds
    ) {
        return simulateOptionSource(
                caller,
                candidateEntities,
                rawOptionMapper,
                descriptor,
                operation,
                includeOrByIds,
                List.of(),
                null,
                null
        );
    }

    /**
     * Simulates a governed {@code OptionSource} execution across {@code candidateEntities} with
     * structured {@code lookupFilters}, symbolic or property {@code sortKey}, and free-text
     * {@code search} term, enforcing anti-spoofing headers, pre-SQL {@link FieldUseCategory#FILTER}
     * and {@link FieldUseCategory#SORT} guards, collection availability, row-level scoping, and
     * {@link OptionDTO} sanitization ({@code Fase P10.25-B}, {@code P05}, {@code P06}, {@code P07},
     * {@code P09}, {@code P12}, {@code P13}, {@code P14}, {@code P50}).
     */
    public OptionSourceSimulationOutcome simulateOptionSource(
            AuthzCallerContext caller,
            List<E> candidateEntities,
            java.util.function.Function<E, OptionDTO<Object>> rawOptionMapper,
            OptionSourceDescriptor descriptor,
            OptionSourceOperation operation,
            java.util.Collection<Object> includeOrByIds,
            List<org.praxisplatform.uischema.options.LookupFilterRequest> lookupFilters,
            String sortKey,
            String search
    ) {
        Objects.requireNonNull(caller, "caller is required");
        Objects.requireNonNull(rawOptionMapper, "rawOptionMapper is required");
        HeaderSpoofingSimulationOutcome headerGuard = simulateHeaderSpoofingGuard(caller);
        if (!headerGuard.allowed()) {
            return new OptionSourceSimulationOutcome(
                    false,
                    headerGuard.reasonCode(),
                    null,
                    Set.of(),
                    List.of(),
                    Set.of(),
                    Set.of(),
                    Set.of()
            );
        }
        Set<String> filterUses = new LinkedHashSet<>();
        if (lookupFilters != null) {
            for (org.praxisplatform.uischema.options.LookupFilterRequest lf : lookupFilters) {
                if (lf != null && lf.field() != null && !lf.field().isBlank()) {
                    filterUses.add(lf.field().trim());
                }
            }
        }
        if (search != null && !search.isBlank() && descriptor != null) {
            boolean searchAllowed = descriptor.policy() == null
                    || (descriptor.policy().allowSearch() && !"none".equalsIgnoreCase(descriptor.policy().searchMode()));
            if (searchAllowed) {
                boolean hasExplicitSearchPaths = false;
                if (descriptor.entityLookup() != null && descriptor.entityLookup().searchPropertyPaths() != null) {
                    for (String sp : descriptor.entityLookup().searchPropertyPaths()) {
                        if (sp != null && !sp.isBlank()) {
                            filterUses.add(sp.trim());
                            hasExplicitSearchPaths = true;
                        }
                    }
                }
                if (!hasExplicitSearchPaths) {
                    String fallbackLabelPath = (descriptor.labelPropertyPath() != null && !descriptor.labelPropertyPath().isBlank())
                            ? descriptor.labelPropertyPath()
                            : descriptor.propertyPath();
                    if (fallbackLabelPath != null && !fallbackLabelPath.isBlank()) {
                        filterUses.add(fallbackLabelPath.trim());
                    }
                }
                var effectiveFiltering = descriptor.effectiveFiltering();
                if (effectiveFiltering != null && effectiveFiltering.quickFilterFields() != null) {
                    for (String qf : effectiveFiltering.quickFilterFields()) {
                        if (qf != null && !qf.isBlank()) {
                            filterUses.add(qf.trim());
                        }
                    }
                }
            }
        }
        Set<String> sortUses = new LinkedHashSet<>();
        String effectiveSortKey = (sortKey != null && !sortKey.isBlank())
                ? sortKey
                : ((operation == null || operation == OptionSourceOperation.FILTER)
                        && descriptor != null
                        && descriptor.effectiveFiltering() != null
                        ? descriptor.effectiveFiltering().defaultSort()
                        : null);
        if (effectiveSortKey != null && !effectiveSortKey.isBlank()) {
            String normalizedSort = effectiveSortKey.trim();
            int colonIdx = normalizedSort.indexOf(':');
            if (colonIdx > 0) {
                normalizedSort = normalizedSort.substring(0, colonIdx).trim();
            }
            if (!normalizedSort.isEmpty()) {
                boolean matchedSymbolic = false;
                if (descriptor != null && descriptor.effectiveFiltering() != null
                        && descriptor.effectiveFiltering().sortOptions() != null) {
                    for (var sortOpt : descriptor.effectiveFiltering().sortOptions()) {
                        if (sortOpt != null
                                && (normalizedSort.equals(sortOpt.key()) || effectiveSortKey.trim().equals(sortOpt.key()))
                                && sortOpt.field() != null
                                && !sortOpt.field().isBlank()) {
                            sortUses.add(sortOpt.field().trim());
                            matchedSymbolic = true;
                        }
                    }
                }
                if (!matchedSymbolic && descriptor != null) {
                    if ("label".equals(normalizedSort)) {
                        String labelPath = (descriptor.labelPropertyPath() != null && !descriptor.labelPropertyPath().isBlank())
                                ? descriptor.labelPropertyPath()
                                : descriptor.propertyPath();
                        if (labelPath != null && !labelPath.isBlank()) {
                            sortUses.add(labelPath.trim());
                            matchedSymbolic = true;
                        }
                    } else if ("id".equals(normalizedSort)) {
                        String valuePath = (descriptor.valuePropertyPath() != null && !descriptor.valuePropertyPath().isBlank())
                                ? descriptor.valuePropertyPath()
                                : descriptor.propertyPath();
                        if (valuePath != null && !valuePath.isBlank()) {
                            sortUses.add(valuePath.trim());
                            matchedSymbolic = true;
                        }
                    }
                }
                if (!matchedSymbolic) {
                    sortUses.add(normalizedSort);
                }
            }
        }
        Map<FieldUseCategory, Set<String>> requestedUses = new LinkedHashMap<>();
        if (!filterUses.isEmpty()) {
            requestedUses.put(FieldUseCategory.FILTER, filterUses);
        }
        if (!sortUses.isEmpty()) {
            requestedUses.put(FieldUseCategory.SORT, sortUses);
        }
        if (!requestedUses.isEmpty()) {
            QueryFieldUseSimulationOutcome fieldUseOut = simulateQueryFieldUse(caller, requestedUses);
            if (!fieldUseOut.allowed()) {
                return new OptionSourceSimulationOutcome(
                        false,
                        fieldUseOut.denialReason(),
                        fieldUseOut.violatedCategory(),
                        fieldUseOut.violatedAttributeIds(),
                        List.of(),
                        Set.of(),
                        Set.of(),
                        Set.of()
                );
            }
        }
        AvailabilitySimulationOutcome collectionAvail = simulateCollectionAvailability(caller, "filter");
        if (!collectionAvail.allowed()) {
            return new OptionSourceSimulationOutcome(
                    false,
                    collectionAvail.reason(),
                    List.of(),
                    Set.of(),
                    Set.of(),
                    Set.of()
            );
        }
        if (candidateEntities == null || candidateEntities.isEmpty()) {
            return new OptionSourceSimulationOutcome(
                    true,
                    null,
                    List.of(),
                    Set.of(),
                    Set.of(),
                    Set.of()
            );
        }
        AuthzGovernedResourceServiceSupport support = new AuthzGovernedResourceServiceSupport(
                authorizationSeam,
                maskingProcessor,
                dtoIntrospector
        );
        AuthzGovernedOptionSourceProvider optionProvider = new AuthzGovernedOptionSourceProvider(
                (org.praxisplatform.uischema.options.service.OptionSourceProvider) new org.praxisplatform.uischema.options.service.OptionSourceProvider() {
                    @Override
                    public boolean supports(
                            OptionSourceDescriptor d,
                            org.praxisplatform.uischema.options.service.OptionSourceExecutionContext c,
                            OptionSourceOperation op
                    ) {
                        return true;
                    }

                    @Override
                    public org.springframework.data.domain.Page<OptionDTO<Object>> filter(
                            org.praxisplatform.uischema.options.service.OptionSourceExecutionRequest<?> req
                    ) {
                        return org.springframework.data.domain.Page.empty();
                    }

                    @Override
                    public List<OptionDTO<Object>> byIds(
                            org.praxisplatform.uischema.options.service.OptionSourceExecutionRequest<?> req
                    ) {
                        return List.of();
                    }
                },
                support,
                maskingProcessor,
                responseGovernanceContract,
                spec
        );
        List<OptionDTO<Object>> sanitizedOptions = new ArrayList<>();
        Set<Object> admittedIds = new LinkedHashSet<>();
        Set<String> allMasked = new LinkedHashSet<>();
        Set<String> allValueDenied = new LinkedHashSet<>();
        for (FieldUseEffectDirective dir : responseGovernanceContract.baselineFieldUseDirectives()) {
            if (dir.category() == FieldUseCategory.VALUE
                    && dir.effect() == org.praxisplatform.authz.contracts.envelope.RuleEffect.DENY) {
                allValueDenied.add(dir.attributeId());
            }
        }
        for (E entity : candidateEntities) {
            if (entity == null) {
                continue;
            }
            if (caller.tenantId() != null) {
                String entityTenant = spec.extractTenantFromEntity(entity);
                if (entityTenant != null && !Objects.equals(caller.tenantId(), entityTenant)) {
                    continue;
                }
            }
            try {
                spec.verifyEntityAccessAllowed(entity, caller, null);
            } catch (SecurityException ex) {
                continue;
            }
            Map<String, Object> mergedFacts = new LinkedHashMap<>(caller.subjectAndEnvironmentFacts());
            if (caller.tenantId() != null) {
                mergedFacts.putIfAbsent("subject.tenantId", caller.tenantId());
            }
            Map<String, Object> targetFacts = spec.extractEntityTargetFacts(entity);
            if (targetFacts != null) {
                mergedFacts.putAll(targetFacts);
            }
            Map<String, FactResolutionStatus> statuses = new LinkedHashMap<>();
            for (String key : mergedFacts.keySet()) {
                statuses.put(key, FactResolutionStatus.PRESENT);
            }
            TargetReadProjectionEvaluation eval;
            try {
                eval = authorizationSeam.evaluateTargetReadProjection(
                        spec.decisionPoint(),
                        spec.factContractDigest(),
                        mergedFacts,
                        statuses
                );
            } catch (SecurityException ex) {
                continue;
            }
            for (MaskDirective dir : eval.maskDirectives()) {
                if (dir != null && dir.attributeId() != null) {
                    allMasked.add(dir.attributeId());
                }
            }
            allValueDenied.addAll(eval.valueDeniedAttributeIds());
            OptionDTO<Object> rawOpt = rawOptionMapper.apply(entity);
            if (rawOpt == null || rawOpt.id() == null) {
                continue;
            }
            List<OptionDTO<Object>> itemSanitized = optionProvider.sanitizeOptionsWithDirectives(
                    List.of(rawOpt),
                    descriptor,
                    operation != null ? operation : OptionSourceOperation.FILTER,
                    includeOrByIds != null ? includeOrByIds : List.of(),
                    eval.valueDeniedAttributeIds(),
                    eval.maskDirectives()
            );
            for (OptionDTO<Object> sOpt : itemSanitized) {
                sanitizedOptions.add(sOpt);
                admittedIds.add(sOpt.id());
            }
        }
        return new OptionSourceSimulationOutcome(
                true,
                null,
                sanitizedOptions,
                admittedIds,
                allMasked,
                allValueDenied
        );
    }

    /**
     * Simulates pre-hydration {@code CREATE} authorization at {@code STEP_11}
     * ({@code WriteIntent} extraction, mandatory scope anchor verification,
     * {@link DualScopeDelegationSpec} custody, and {@link FieldWriteAuthorizer})
     * ({@code Fase P10.19-B}, {@code R-07}, {@code R-11}, {@code P13}, {@code P14}, {@code P17}).
     */
    @SuppressWarnings("unchecked")
    public WriteMutationSimulationOutcome simulateCreateMutation(
            AuthzCallerContext caller,
            Object createDto,
            E candidateEntity
    ) {
        Objects.requireNonNull(caller, "caller is required");
        Objects.requireNonNull(candidateEntity, "candidateEntity is required");
        if (caller.tenantId() != null) {
            String entityTenant = spec.extractTenantFromEntity(candidateEntity);
            if (entityTenant != null && !Objects.equals(caller.tenantId(), entityTenant)) {
                return new WriteMutationSimulationOutcome(
                        false,
                        "hard-scope-tenant-mismatch",
                        "AUTHZ_HARD_SCOPE_TENANT_MISMATCH",
                        Set.of(),
                        Set.of(),
                        null
                );
            }
        }
        try {
            spec.verifyEntityAccessAllowed(candidateEntity, caller, null);
        } catch (SecurityException ex) {
            return new WriteMutationSimulationOutcome(
                    false,
                    "policy-gate-denied",
                    "AUTHZ_ROW_SCOPE_DENIED",
                    Set.of(),
                    Set.of(),
                    null
            );
        }
        IntrospectedDtoGovernanceContract writeContract = (createDto == null
                        || createDto instanceof Map<?, ?>
                        || createDto instanceof String)
                ? responseGovernanceContract
                : dtoIntrospector.introspectWriteDto(createDto.getClass(), responseDtoClass, spec.resourceKey());
        Map<String, Object> dtoMap = createDto == null
                ? Map.of()
                : (createDto instanceof Map<?, ?> m
                        ? (Map<String, Object>) m
                        : objectMapper.convertValue(createDto, Map.class));
        Set<String> anchors = spec.mandatoryScopeAnchorAttributeIds();
        Map<String, String> wireToAttr = writeContract.wirePointerToAttributeIdMap();
        Map<String, Object> filtered = new LinkedHashMap<>();
        Set<String> presentAnchorAttrs = new LinkedHashSet<>();
        for (Map.Entry<String, Object> entry : dtoMap.entrySet()) {
            String key = entry.getKey();
            Object val = entry.getValue();
            String attrId = wireToAttr.get("/" + key);
            if (val != null || (attrId != null && anchors.contains(attrId))) {
                filtered.put(key, val);
                if (attrId != null && anchors.contains(attrId) && val != null) {
                    presentAnchorAttrs.add(attrId);
                }
            }
        }
        for (String anchorAttrId : anchors) {
            if (!presentAnchorAttrs.contains(anchorAttrId)) {
                String anchorWireKey = findWireKeyForAttr(wireToAttr, anchorAttrId);
                if (anchorWireKey == null) {
                    return new WriteMutationSimulationOutcome(
                            false,
                            "scope-anchor-clear-forbidden",
                            "AUTHZ_SCOPE_ANCHOR_CLEAR_FORBIDDEN",
                            Set.of(),
                            Set.of(anchorAttrId),
                            null
                    );
                }
                filtered.put(anchorWireKey, null);
            }
        }
        return executeStep11MutationSimulation(
                caller,
                spec.decisionPoint(),
                spec.factContractDigest(),
                "POST",
                true,
                filtered,
                wireToAttr,
                candidateEntity
        );
    }

    /**
     * Simulates pre-hydration {@code UPDATE} ({@code PATCH}) authorization at {@code STEP_11}
     * ({@code Fase P10.19-B}, {@code R-07}, {@code R-11}, {@code P13}, {@code P14}, {@code P17}).
     */
    public WriteMutationSimulationOutcome simulateUpdateMutation(
            AuthzCallerContext caller,
            E existingEntity,
            Object updateDto
    ) {
        return simulateUpdateMutation(caller, existingEntity, updateDto, null);
    }

    /**
     * Simulates pre-hydration {@code UPDATE} ({@code PATCH}) authorization at {@code STEP_11},
     * computing the delta against {@code baselineResponseDto} when provided ({@code Fase P10.19-B}).
     */
    @SuppressWarnings("unchecked")
    public WriteMutationSimulationOutcome simulateUpdateMutation(
            AuthzCallerContext caller,
            E existingEntity,
            Object updateDto,
            ResponseDTO baselineResponseDto
    ) {
        Objects.requireNonNull(caller, "caller is required");
        Objects.requireNonNull(existingEntity, "existingEntity is required");
        if (caller.tenantId() != null) {
            String entityTenant = spec.extractTenantFromEntity(existingEntity);
            if (entityTenant != null && !Objects.equals(caller.tenantId(), entityTenant)) {
                return new WriteMutationSimulationOutcome(
                        false,
                        "hard-scope-tenant-mismatch",
                        "AUTHZ_HARD_SCOPE_TENANT_MISMATCH",
                        Set.of(),
                        Set.of(),
                        null
                );
            }
        }
        try {
            spec.verifyEntityAccessAllowed(existingEntity, caller, null);
        } catch (SecurityException ex) {
            return new WriteMutationSimulationOutcome(
                    false,
                    "policy-gate-denied",
                    "AUTHZ_ROW_SCOPE_DENIED",
                    Set.of(),
                    Set.of(),
                    null
            );
        }
        IntrospectedDtoGovernanceContract writeContract = (updateDto == null
                        || updateDto instanceof Map<?, ?>
                        || updateDto instanceof String)
                ? responseGovernanceContract
                : dtoIntrospector.introspectWriteDto(updateDto.getClass(), responseDtoClass, spec.resourceKey());
        Map<String, Object> dtoMap = updateDto == null
                ? Map.of()
                : (updateDto instanceof Map<?, ?> m
                        ? (Map<String, Object>) m
                        : objectMapper.convertValue(updateDto, Map.class));
        Map<String, Object> baselineMap = baselineResponseDto == null
                ? Map.of()
                : objectMapper.convertValue(baselineResponseDto, Map.class);
        Set<String> anchors = spec.mandatoryScopeAnchorAttributeIds();
        Map<String, String> wireToAttr = writeContract.wirePointerToAttributeIdMap();
        Map<String, Object> delta = new LinkedHashMap<>();
        for (Map.Entry<String, Object> entry : dtoMap.entrySet()) {
            String key = entry.getKey();
            Object newVal = entry.getValue();
            String attrId = wireToAttr.get("/" + key);
            if (newVal == null) {
                if (attrId != null && anchors.contains(attrId)) {
                    delta.put(key, null);
                }
                continue;
            }
            if (baselineResponseDto != null && Objects.equals(newVal, baselineMap.get(key))) {
                continue;
            }
            delta.put(key, newVal);
        }
        return executeStep11MutationSimulation(
                caller,
                spec.decisionPoint(),
                spec.factContractDigest(),
                "PATCH",
                true,
                delta,
                wireToAttr,
                existingEntity
        );
    }

    /**
     * Simulates pre-deletion {@code DELETE} authorization at {@code STEP_11}
     * ({@code Fase P10.19-B}, {@code R-07}, {@code R-11}, {@code P17}).
     */
    public WriteMutationSimulationOutcome simulateDeleteMutation(
            AuthzCallerContext caller,
            E existingEntity
    ) {
        Objects.requireNonNull(caller, "caller is required");
        Objects.requireNonNull(existingEntity, "existingEntity is required");
        if (caller.tenantId() != null) {
            String entityTenant = spec.extractTenantFromEntity(existingEntity);
            if (entityTenant != null && !Objects.equals(caller.tenantId(), entityTenant)) {
                return new WriteMutationSimulationOutcome(
                        false,
                        "hard-scope-tenant-mismatch",
                        "AUTHZ_HARD_SCOPE_TENANT_MISMATCH",
                        Set.of(),
                        Set.of(),
                        null
                );
            }
        }
        try {
            spec.verifyEntityAccessAllowed(existingEntity, caller, null);
        } catch (SecurityException ex) {
            return new WriteMutationSimulationOutcome(
                    false,
                    "policy-gate-denied",
                    "AUTHZ_ROW_SCOPE_DENIED",
                    Set.of(),
                    Set.of(),
                    null
            );
        }
        return executeStep11MutationSimulation(
                caller,
                spec.decisionPoint(),
                spec.factContractDigest(),
                "DELETE",
                false,
                Map.of(),
                Map.of(),
                existingEntity
        );
    }

    /**
     * Simulates an item-scoped {@code @WorkflowAction} or {@code @ResourceIntent} command mutation
     * at {@code STEP_11} ({@code Fase P10.19-B}, {@code R-07}, {@code R-11}, {@code P10..P22}).
     */
    @SuppressWarnings("unchecked")
    public WriteMutationSimulationOutcome simulateItemCommandMutation(
            AuthzCallerContext caller,
            String actionOrOperationId,
            E existingEntity,
            Object commandDto
    ) {
        Objects.requireNonNull(caller, "caller is required");
        Objects.requireNonNull(actionOrOperationId, "actionOrOperationId is required");
        Objects.requireNonNull(existingEntity, "existingEntity is required");
        if (caller.tenantId() != null) {
            String entityTenant = spec.extractTenantFromEntity(existingEntity);
            if (entityTenant != null && !Objects.equals(caller.tenantId(), entityTenant)) {
                return new WriteMutationSimulationOutcome(
                        false,
                        "hard-scope-tenant-mismatch",
                        "AUTHZ_HARD_SCOPE_TENANT_MISMATCH",
                        Set.of(),
                        Set.of(),
                        null
                );
            }
        }
        try {
            spec.verifyEntityAccessAllowed(existingEntity, caller, null);
        } catch (SecurityException ex) {
            return new WriteMutationSimulationOutcome(
                    false,
                    "policy-gate-denied",
                    "AUTHZ_ROW_SCOPE_DENIED",
                    Set.of(),
                    Set.of(),
                    null
            );
        }
        DecisionPointDescriptor effectiveDp = spec.actionDecisionPoints()
                .getOrDefault(actionOrOperationId, spec.surfaceDecisionPoints().getOrDefault(actionOrOperationId, spec.decisionPoint()));
        String factDigest = (effectiveDp.factContractRef() != null
                        && effectiveDp.factContractRef().factContractDigest() != null)
                ? effectiveDp.factContractRef().factContractDigest()
                : spec.factContractDigest();
        IntrospectedDtoGovernanceContract cmdContract = (commandDto == null
                        || commandDto instanceof Map<?, ?>
                        || commandDto instanceof String)
                ? responseGovernanceContract
                : dtoIntrospector.introspectWriteDto(commandDto.getClass(), responseDtoClass, spec.resourceKey());
        Map<String, String> mergedWireToAttr = new LinkedHashMap<>(responseGovernanceContract.wirePointerToAttributeIdMap());
        mergedWireToAttr.putAll(cmdContract.wirePointerToAttributeIdMap());

        Map<String, Object> payload = new LinkedHashMap<>();
        Set<String> presentAttrIds = new LinkedHashSet<>();
        Set<String> anchors = spec.mandatoryScopeAnchorAttributeIds();
        Set<String> declaredModifiedAttrs = spec.operationModifiedAttributes()
                .getOrDefault(actionOrOperationId, Set.of());
        if (commandDto != null) {
            Map<String, Object> dtoMap = commandDto instanceof Map<?, ?> m
                    ? (Map<String, Object>) m
                    : objectMapper.convertValue(commandDto, Map.class);
            for (Map.Entry<String, Object> entry : dtoMap.entrySet()) {
                String key = entry.getKey();
                Object val = entry.getValue();
                String attrId = mergedWireToAttr.get("/" + key);
                if (val != null) {
                    payload.put(key, val);
                    if (attrId != null) {
                        presentAttrIds.add(attrId);
                    }
                } else if (attrId != null && anchors.contains(attrId)) {
                    payload.put(key, null);
                    presentAttrIds.add(attrId);
                }
            }
        }
        for (String attrId : declaredModifiedAttrs) {
            if (!presentAttrIds.contains(attrId)) {
                String wireKey = findWireKeyForAttr(mergedWireToAttr, attrId);
                if (wireKey == null) {
                    wireKey = attrId;
                    mergedWireToAttr.put("/" + wireKey, attrId);
                }
                payload.putIfAbsent(wireKey, "__governed_command_transition__");
            }
        }
        return executeStep11MutationSimulation(
                caller,
                effectiveDp,
                factDigest,
                "POST",
                true,
                payload,
                mergedWireToAttr,
                existingEntity
        );
    }

    /**
     * Simulates a cohort-scoped {@code BulkMode.UNIFORM_UPDATE} operation at {@code STEP_11}
     * across {@code candidateEntities} under {@code batchMode} ({@code REJECT_ALL} or {@code PER_ITEM})
     * ({@code Fase P10.20-B}, {@code P13}, {@code P14}, {@code P15}, {@code P18}, {@code P34}).
     */
    public <ID> BulkMutationSimulationOutcome<ID> simulateBulkUpdateCohort(
            AuthzCallerContext caller,
            List<E> candidateEntities,
            java.util.function.Function<E, ID> idExtractor,
            Object uniformUpdateDto,
            org.praxisplatform.authz.contracts.binding.BatchAuthorizationMode batchMode
    ) {
        return evaluateBulkCohortAtStep11(
                caller,
                "filter",
                candidateEntities,
                idExtractor,
                batchMode,
                entity -> simulateUpdateMutation(caller, entity, uniformUpdateDto)
        );
    }

    /**
     * Simulates a cohort-scoped {@code BulkMode.PER_ITEM_UPDATE} operation at {@code STEP_11}
     * across {@code candidateEntities} using per-item DTOs from {@code updateDtoById} under
     * {@code batchMode} ({@code REJECT_ALL} or {@code PER_ITEM}) ({@code Fase P10.20-B}).
     */
    public <ID> BulkMutationSimulationOutcome<ID> simulateBulkPerItemUpdateCohort(
            AuthzCallerContext caller,
            List<E> candidateEntities,
            java.util.function.Function<E, ID> idExtractor,
            Map<ID, ?> updateDtoById,
            org.praxisplatform.authz.contracts.binding.BatchAuthorizationMode batchMode
    ) {
        Objects.requireNonNull(idExtractor, "idExtractor is required");
        Map<ID, ?> safeDtoMap = updateDtoById == null ? Map.of() : updateDtoById;
        return evaluateBulkCohortAtStep11(
                caller,
                "filter",
                candidateEntities,
                idExtractor,
                batchMode,
                entity -> {
                    ID id = idExtractor.apply(entity);
                    Object itemDto = safeDtoMap.get(id);
                    return simulateUpdateMutation(caller, entity, itemDto);
                }
        );
    }

    /**
     * Simulates a cohort-scoped bulk {@code DELETE} operation at {@code STEP_11} across
     * {@code candidateEntities} under {@code batchMode} ({@code REJECT_ALL} or {@code PER_ITEM})
     * ({@code Fase P10.20-B}).
     */
    public <ID> BulkMutationSimulationOutcome<ID> simulateBulkDeleteCohort(
            AuthzCallerContext caller,
            List<E> candidateEntities,
            java.util.function.Function<E, ID> idExtractor,
            org.praxisplatform.authz.contracts.binding.BatchAuthorizationMode batchMode
    ) {
        return evaluateBulkCohortAtStep11(
                caller,
                "filter",
                candidateEntities,
                idExtractor,
                batchMode,
                entity -> simulateDeleteMutation(caller, entity)
        );
    }

    /**
     * Simulates a cohort-scoped {@code BulkMode.DOMAIN_COMMAND} ({@code ActionScope.COLLECTION})
     * operation at {@code STEP_11} across {@code candidateEntities} with full {@code commandDto}
     * {@code WriteIntent} evaluation under {@code batchMode} ({@code REJECT_ALL} or {@code PER_ITEM})
     * ({@code Fase P10.20-B}, {@code P13}, {@code P14}, {@code P15}).
     */
    public <ID> BulkMutationSimulationOutcome<ID> simulateBulkCommandCohort(
            AuthzCallerContext caller,
            String actionOrOperationId,
            List<E> candidateEntities,
            java.util.function.Function<E, ID> idExtractor,
            Object commandDto,
            org.praxisplatform.authz.contracts.binding.BatchAuthorizationMode batchMode
    ) {
        Objects.requireNonNull(actionOrOperationId, "actionOrOperationId is required");
        return evaluateBulkCohortAtStep11(
                caller,
                actionOrOperationId,
                candidateEntities,
                idExtractor,
                batchMode,
                entity -> simulateItemCommandMutation(caller, actionOrOperationId, entity, commandDto)
        );
    }

    /**
     * Simulates the 2-phase bulk proposal &amp; confirmation lifecycle
     * ({@link AuthzGovernedBulkDomainResourceAdapter.GovernedBulkProposalGrant},
     * {@code Fase P10.21-B}, {@code P15}, {@code P18}, {@code P34}):
     * <ol>
     *   <li><b>Phase 1 (Proposal Evaluation &amp; Preview Sanitization):</b> evaluates the cohort
     *       under {@code proposingCaller} and computes masked/sanitized candidate preview projections
     *       for admitted items;</li>
     *   <li><b>Phase 2 (Confirmation Grant Verification &amp; Execution):</b> enforces anti-confused-deputy
     *       ({@code proposingCaller} vs {@code confirmingCaller} principal and tenant), policy digest
     *       continuity ({@code proposalPolicyDigest} vs {@code confirmPolicyDigest}), and live
     *       {@code STEP_11} cohort revalidation under {@code batchMode}.</li>
     * </ol>
     */
    public <ID> BulkTwoPhaseSimulationOutcome<ID, ResponseDTO> simulateTwoPhaseBulkProposalAndConfirm(
            AuthzCallerContext proposingCaller,
            AuthzCallerContext confirmingCaller,
            String proposalPolicyDigest,
            String confirmPolicyDigest,
            List<E> candidateEntities,
            java.util.function.Function<E, ID> idExtractor,
            java.util.function.Function<E, ResponseDTO> rawResponseMapper,
            Object uniformUpdateDto,
            org.praxisplatform.authz.contracts.binding.BatchAuthorizationMode batchMode
    ) {
        return simulateTwoPhaseBulkInternal(
                proposingCaller,
                confirmingCaller,
                proposalPolicyDigest,
                confirmPolicyDigest,
                candidateEntities,
                idExtractor,
                rawResponseMapper,
                batchMode,
                (caller, entities) -> simulateBulkUpdateCohort(
                        caller, entities, idExtractor, uniformUpdateDto, batchMode
                )
        );
    }

    /**
     * Simulates the 2-phase bulk proposal &amp; confirmation lifecycle for
     * {@code BulkMode.PER_ITEM_UPDATE} ({@code payloadsByItemId}) ({@code Fase P10.21-R03}).
     */
    public <ID> BulkTwoPhaseSimulationOutcome<ID, ResponseDTO> simulateTwoPhaseBulkPerItemProposalAndConfirm(
            AuthzCallerContext proposingCaller,
            AuthzCallerContext confirmingCaller,
            String proposalPolicyDigest,
            String confirmPolicyDigest,
            List<E> candidateEntities,
            java.util.function.Function<E, ID> idExtractor,
            java.util.function.Function<E, ResponseDTO> rawResponseMapper,
            Map<ID, Object> payloadsByItemId,
            org.praxisplatform.authz.contracts.binding.BatchAuthorizationMode batchMode
    ) {
        return simulateTwoPhaseBulkInternal(
                proposingCaller,
                confirmingCaller,
                proposalPolicyDigest,
                confirmPolicyDigest,
                candidateEntities,
                idExtractor,
                rawResponseMapper,
                batchMode,
                (caller, entities) -> simulateBulkPerItemUpdateCohort(
                        caller, entities, idExtractor, payloadsByItemId, batchMode
                )
        );
    }

    private <ID> BulkTwoPhaseSimulationOutcome<ID, ResponseDTO> simulateTwoPhaseBulkInternal(
            AuthzCallerContext proposingCaller,
            AuthzCallerContext confirmingCaller,
            String proposalPolicyDigest,
            String confirmPolicyDigest,
            List<E> candidateEntities,
            java.util.function.Function<E, ID> idExtractor,
            java.util.function.Function<E, ResponseDTO> rawResponseMapper,
            org.praxisplatform.authz.contracts.binding.BatchAuthorizationMode batchMode,
            java.util.function.BiFunction<AuthzCallerContext, List<E>, BulkMutationSimulationOutcome<ID>> cohortRunner
    ) {
        Objects.requireNonNull(proposingCaller, "proposingCaller is required");
        Objects.requireNonNull(confirmingCaller, "confirmingCaller is required");
        Objects.requireNonNull(idExtractor, "idExtractor is required");
        Objects.requireNonNull(rawResponseMapper, "rawResponseMapper is required");
        Objects.requireNonNull(batchMode, "batchMode is required");

        HeaderSpoofingSimulationOutcome proposalHeaderGuard = simulateHeaderSpoofingGuard(proposingCaller);
        if (!proposalHeaderGuard.allowed()) {
            return new BulkTwoPhaseSimulationOutcome<>(
                    false,
                    false,
                    proposalHeaderGuard.reasonCode(),
                    Map.of(),
                    null
            );
        }

        BulkMutationSimulationOutcome<ID> proposalCohort = cohortRunner.apply(proposingCaller, candidateEntities);
        if (proposalCohort.batchAborted() || proposalCohort.committedIds().isEmpty()) {
            return new BulkTwoPhaseSimulationOutcome<>(
                    false,
                    false,
                    "PROPOSAL_REJECTED",
                    Map.of(),
                    proposalCohort
            );
        }

        Map<ID, ReadSimulationOutcome<ResponseDTO>> previews = new LinkedHashMap<>();
        List<E> admittedEntities = new ArrayList<>();
        if (candidateEntities != null) {
            for (E entity : candidateEntities) {
                if (entity == null) {
                    continue;
                }
                ID id = idExtractor.apply(entity);
                if (proposalCohort.committedIds().contains(id)) {
                    admittedEntities.add(entity);
                    previews.put(
                            id,
                            simulateTargetRead(proposingCaller, entity, rawResponseMapper.apply(entity))
                    );
                }
            }
        }

        HeaderSpoofingSimulationOutcome confirmHeaderGuard = simulateHeaderSpoofingGuard(confirmingCaller);
        if (!confirmHeaderGuard.allowed()) {
            return new BulkTwoPhaseSimulationOutcome<>(
                    true,
                    false,
                    confirmHeaderGuard.reasonCode(),
                    previews,
                    null
            );
        }

        String proposalPrincipal = String.valueOf(
                proposingCaller.subjectAndEnvironmentFacts().getOrDefault("subject.principalId", "anonymous")
        );
        String confirmPrincipal = String.valueOf(
                confirmingCaller.subjectAndEnvironmentFacts().getOrDefault("subject.principalId", "anonymous")
        );
        if (!Objects.equals(proposalPrincipal, confirmPrincipal)
                || !Objects.equals(proposingCaller.tenantId(), confirmingCaller.tenantId())) {
            return new BulkTwoPhaseSimulationOutcome<>(
                    true,
                    false,
                    "AUTHZ_BULK_CONFUSED_DEPUTY_DENIED",
                    previews,
                    null
            );
        }
        if (!Objects.equals(proposalPolicyDigest, confirmPolicyDigest)) {
            return new BulkTwoPhaseSimulationOutcome<>(
                    true,
                    false,
                    "AUTHZ_BULK_POLICY_REVOKED_OR_ROTATED",
                    previews,
                    null
            );
        }

        BulkMutationSimulationOutcome<ID> confirmCohort = cohortRunner.apply(confirmingCaller, admittedEntities);
        if (confirmCohort.batchAborted()) {
            return new BulkTwoPhaseSimulationOutcome<>(
                    true,
                    false,
                    confirmCohort.abortReason(),
                    previews,
                    confirmCohort
            );
        }
        if (confirmCohort.committedIds().isEmpty()) {
            return new BulkTwoPhaseSimulationOutcome<>(
                    true,
                    false,
                    "CONFIRMATION_ALL_ITEMS_REJECTED",
                    previews,
                    confirmCohort
            );
        }
        return new BulkTwoPhaseSimulationOutcome<>(
                true,
                true,
                null,
                previews,
                confirmCohort
        );
    }

    /**
     * Simulates {@link UntrustedRequestHeaderGuard} against {@link AuthzCallerContext#incomingHeaderNames()}
     * ({@code Fase P10.21-B}, {@code P02}, {@code P53}).
     *
     * @param caller caller context containing incoming HTTP header names
     * @return structured {@link HeaderSpoofingSimulationOutcome}
     */
    public HeaderSpoofingSimulationOutcome simulateHeaderSpoofingGuard(AuthzCallerContext caller) {
        Objects.requireNonNull(caller, "caller is required");
        Set<String> headers = caller.incomingHeaderNames();
        if ((headers == null || headers.isEmpty()) && caller.incomingHeaders().isEmpty()) {
            return new HeaderSpoofingSimulationOutcome(true, List.of(), null);
        }
        Map<String, String> effectiveProbe = caller.effectiveHeaderProbeMap();
        Map<String, org.praxisplatform.authz.contracts.context.ResolvedFactValue> authoritativeFacts =
                MetadataResourceAuthorizationSeam.toAuthoritativeSubjectFactMap(
                        caller.subjectAndEnvironmentFacts(),
                        caller.factStatuses(),
                        caller.tenantId()
                );
        List<String> rejected = new ArrayList<>();
        for (Map.Entry<String, String> entry : effectiveProbe.entrySet()) {
            String h = entry.getKey();
            if (h == null || h.isBlank()) {
                continue;
            }
            try {
                UntrustedRequestHeaderGuard.assertNoAuthoritySpoofingHeaders(
                        Map.of(h, entry.getValue()),
                        authoritativeFacts
                );
            } catch (RuntimeException ex) {
                rejected.add(h);
            }
        }
        if (!rejected.isEmpty()) {
            return new HeaderSpoofingSimulationOutcome(
                    false,
                    rejected,
                    "UNTRUSTED_AUTHORITY_HEADER_SPOOFING"
            );
        }
        return new HeaderSpoofingSimulationOutcome(true, List.of(), null);
    }

    private <ID> BulkMutationSimulationOutcome<ID> evaluateBulkCohortAtStep11(
            AuthzCallerContext caller,
            String collectionOperationId,
            List<E> candidateEntities,
            java.util.function.Function<E, ID> idExtractor,
            org.praxisplatform.authz.contracts.binding.BatchAuthorizationMode batchMode,
            java.util.function.Function<E, WriteMutationSimulationOutcome> itemEvaluator
    ) {
        Objects.requireNonNull(caller, "caller is required");
        Objects.requireNonNull(idExtractor, "idExtractor is required");
        Objects.requireNonNull(batchMode, "batchMode is required");
        if (candidateEntities == null || candidateEntities.isEmpty()) {
            return new BulkMutationSimulationOutcome<>(
                    batchMode,
                    false,
                    null,
                    List.of(),
                    Set.of(),
                    Set.of(),
                    Map.of()
            );
        }
        AvailabilitySimulationOutcome collectionAvail =
                simulateCollectionAvailability(caller, collectionOperationId);
        if (!collectionAvail.allowed()) {
            String collectionRejectionCode = (collectionAvail.reason() != null
                            && (collectionAvail.reason().contains("dual-scope")
                                    || collectionAvail.reason().contains("field-write")))
                    ? "FIELD_WRITE_DENIED"
                    : "ACCESS_OR_SCOPE_DENIED";
            List<AuthzGovernedBulkDomainResourceAdapter.BulkCohortItemOutcome<ID>> deniedAll =
                    new ArrayList<>(candidateEntities.size());
            Set<ID> rejected = new LinkedHashSet<>();
            Map<ID, String> reasons = new LinkedHashMap<>();
            for (E entity : candidateEntities) {
                ID id = entity == null ? null : idExtractor.apply(entity);
                deniedAll.add(new AuthzGovernedBulkDomainResourceAdapter.BulkCohortItemOutcome<>(
                        id, false, null, collectionRejectionCode
                ));
                if (id != null) {
                    rejected.add(id);
                    reasons.put(id, collectionRejectionCode);
                }
            }
            boolean aborted = batchMode == org.praxisplatform.authz.contracts.binding.BatchAuthorizationMode.REJECT_ALL;
            return new BulkMutationSimulationOutcome<>(
                    batchMode,
                    aborted,
                    aborted ? collectionAvail.reason() : null,
                    deniedAll,
                    Set.of(),
                    rejected,
                    reasons
            );
        }

        List<AuthzGovernedBulkDomainResourceAdapter.BulkCohortItemOutcome<ID>> rawOutcomes =
                new ArrayList<>(candidateEntities.size());
        Set<ID> committed = new LinkedHashSet<>();
        Set<ID> rejected = new LinkedHashSet<>();
        Map<ID, String> reasons = new LinkedHashMap<>();
        String firstFailureReason = null;

        for (E entity : candidateEntities) {
            ID id = entity == null ? null : idExtractor.apply(entity);
            if (entity == null) {
                rawOutcomes.add(new AuthzGovernedBulkDomainResourceAdapter.BulkCohortItemOutcome<>(
                        id, false, null, "ENTITY_NOT_FOUND"
                ));
                if (id != null) {
                    rejected.add(id);
                    reasons.put(id, "ENTITY_NOT_FOUND");
                }
                if (firstFailureReason == null) {
                    firstFailureReason = "ENTITY_NOT_FOUND";
                }
                continue;
            }
            WriteMutationSimulationOutcome itemOut = itemEvaluator.apply(entity);
            if (itemOut.allowed()) {
                rawOutcomes.add(new AuthzGovernedBulkDomainResourceAdapter.BulkCohortItemOutcome<>(
                        id, true, null, "COMMITTED"
                ));
                if (id != null) {
                    committed.add(id);
                    reasons.put(id, "COMMITTED");
                }
            } else {
                String code = ("dual-scope-custody-denied".equals(itemOut.denialReason())
                                || "field-write-denied".equals(itemOut.denialReason())
                                || "scope-anchor-clear-forbidden".equals(itemOut.denialReason()))
                        ? "FIELD_WRITE_DENIED"
                        : "ACCESS_OR_SCOPE_DENIED";
                rawOutcomes.add(new AuthzGovernedBulkDomainResourceAdapter.BulkCohortItemOutcome<>(
                        id, false, null, code
                ));
                if (id != null) {
                    rejected.add(id);
                    reasons.put(id, code);
                }
                if (firstFailureReason == null) {
                    firstFailureReason = code;
                }
            }
        }

        if (batchMode == org.praxisplatform.authz.contracts.binding.BatchAuthorizationMode.REJECT_ALL
                && firstFailureReason != null) {
            List<AuthzGovernedBulkDomainResourceAdapter.BulkCohortItemOutcome<ID>> abortedOutcomes =
                    new ArrayList<>(rawOutcomes.size());
            Set<ID> allRejected = new LinkedHashSet<>();
            Map<ID, String> abortedReasons = new LinkedHashMap<>();
            for (AuthzGovernedBulkDomainResourceAdapter.BulkCohortItemOutcome<ID> out : rawOutcomes) {
                String code = out.committed() ? "BATCH_ABORTED" : out.reasonCode();
                abortedOutcomes.add(new AuthzGovernedBulkDomainResourceAdapter.BulkCohortItemOutcome<>(
                        out.targetId(), false, null, code
                ));
                if (out.targetId() != null) {
                    allRejected.add(out.targetId());
                    abortedReasons.put(out.targetId(), code);
                }
            }
            return new BulkMutationSimulationOutcome<>(
                    batchMode,
                    true,
                    firstFailureReason,
                    abortedOutcomes,
                    Set.of(),
                    allRejected,
                    abortedReasons
            );
        }

        return new BulkMutationSimulationOutcome<>(
                batchMode,
                false,
                null,
                rawOutcomes,
                committed,
                rejected,
                reasons
        );
    }

    private WriteMutationSimulationOutcome executeStep11MutationSimulation(
            AuthzCallerContext caller,
            DecisionPointDescriptor effectiveDp,
            String factDigest,
            String operationVerb,
            boolean partialPatch,
            Map<String, Object> payloadMap,
            Map<String, String> wireToAttr,
            E targetEntity
    ) {
        Map<String, Object> mergedFacts = new LinkedHashMap<>(caller.subjectAndEnvironmentFacts());
        if (caller.tenantId() != null) {
            mergedFacts.putIfAbsent("subject.tenantId", caller.tenantId());
        }
        Map<String, Object> targetFacts = spec.extractEntityTargetFacts(targetEntity);
        if (targetFacts != null) {
            mergedFacts.putAll(targetFacts);
        }
        Map<String, FactResolutionStatus> statuses = new LinkedHashMap<>();
        for (String key : mergedFacts.keySet()) {
            statuses.put(key, FactResolutionStatus.PRESENT);
        }
        String rawJson;
        try {
            rawJson = payloadMap == null || payloadMap.isEmpty()
                    ? "{}"
                    : objectMapper.writeValueAsString(payloadMap);
        } catch (Exception ex) {
            rawJson = "{}";
        }
        try {
            if (spec.decisionPoint() != null
                    && !Objects.equals(effectiveDp.identity().pointKey(), spec.decisionPoint().identity().pointKey())) {
                authorizationSeam.evaluateTargetReadProjection(
                        spec.decisionPoint(),
                        spec.factContractDigest(),
                        mergedFacts,
                        statuses
                );
            }
            AuthorizedPreMutationContext preCtx = authorizationSeam.authorizePreHydrationMutation(
                    effectiveDp,
                    factDigest,
                    operationVerb,
                    partialPatch,
                    rawJson,
                    wireToAttr,
                    spec.technicalConcurrencyPointers(),
                    spec.mandatoryScopeAnchorAttributeIds(),
                    spec.dualScopeDelegationSpec(),
                    spec.isCallerCedente(targetEntity, caller),
                    spec.isCallerCessionario(targetEntity, caller),
                    mergedFacts,
                    statuses
            );
            Set<String> modifiedAttrs = new LinkedHashSet<>();
            for (WriteFieldChange change : preCtx.writeIntent().changes()) {
                modifiedAttrs.add(change.attributeId());
            }
            return new WriteMutationSimulationOutcome(
                    true,
                    null,
                    null,
                    modifiedAttrs,
                    Set.of(),
                    preCtx.writeIntent()
            );
        } catch (FieldWriteViolationException ex) {
            String reasonCode = ex.getReasonCode();
            String denialReason = (reasonCode != null && reasonCode.contains("DUAL_SCOPE"))
                    ? "dual-scope-custody-denied"
                    : "field-write-denied";
            return new WriteMutationSimulationOutcome(
                    false,
                    denialReason,
                    reasonCode,
                    Set.of(),
                    ex.getForbiddenAttributeIds(),
                    null
            );
        } catch (SecurityException ex) {
            String msg = ex.getMessage() != null ? ex.getMessage() : "";
            String denialReason = msg.contains("AUTHZ_SCOPE_ANCHOR_CLEAR_FORBIDDEN")
                    ? "scope-anchor-clear-forbidden"
                    : "policy-gate-denied";
            return new WriteMutationSimulationOutcome(
                    false,
                    denialReason,
                    msg,
                    Set.of(),
                    Set.of(),
                    null
            );
        }
    }

    private static String findWireKeyForAttr(Map<String, String> wireToAttr, String targetAttributeId) {
        for (Map.Entry<String, String> entry : wireToAttr.entrySet()) {
            if (targetAttributeId.equals(entry.getValue())) {
                String pointer = entry.getKey();
                return pointer.startsWith("/") ? pointer.substring(1) : pointer;
            }
        }
        return null;
    }

    private Map<FieldUseCategory, Set<String>> normalizeRequestedQueryFieldUses(
            Map<FieldUseCategory, Set<String>> rawUses
    ) {
        if (rawUses == null || rawUses.isEmpty()) {
            return Map.of();
        }
        Map<FieldUseCategory, Set<String>> normalized = new LinkedHashMap<>();
        for (Map.Entry<FieldUseCategory, Set<String>> entry : rawUses.entrySet()) {
            FieldUseCategory cat = entry.getKey();
            Set<String> rawSet = entry.getValue();
            if (cat == null || rawSet == null || rawSet.isEmpty()) {
                continue;
            }
            Set<String> resolved = new LinkedHashSet<>();
            for (String token : rawSet) {
                if (token == null || token.isBlank()) {
                    continue;
                }
                String clean = token.trim();
                String cleanNoSlash = clean.startsWith("/") ? clean.substring(1) : clean;
                String mapped = responseGovernanceContract.wirePointerToAttributeIdMap().get("/" + cleanNoSlash);
                if (mapped != null) {
                    resolved.add(mapped);
                } else {
                    boolean matchedBinding = false;
                    for (var binding : spec.fieldBindings()) {
                        if (cleanNoSlash.equals(binding.nativeJpaPath())
                                || cleanNoSlash.equals(binding.fieldPath())
                                || ("resource." + cleanNoSlash).equals(binding.fieldPath())
                                || cleanNoSlash.equals(binding.attributeId())) {
                            resolved.add(binding.attributeId());
                            matchedBinding = true;
                        }
                    }
                    if (!matchedBinding) {
                        resolved.add(clean);
                    }
                }
            }
            if (!resolved.isEmpty()) {
                normalized.put(cat, Set.copyOf(resolved));
            }
        }
        return Map.copyOf(normalized);
    }

    /**
     * Starts a fluent tabular matrix runner for verifying multiple authorization scenarios in one call.
     */
    public MatrixRunner<E, ResponseDTO> matrix() {
        return new MatrixRunner<>(this);
    }

    @SuppressWarnings("unchecked")
    private ReadSimulationOutcome<ResponseDTO> simulateProjectionReadInternal(
            AuthzCallerContext caller,
            DecisionPointDescriptor effectiveDp,
            E entity,
            ResponseDTO rawResponseDto
    ) {
        Objects.requireNonNull(caller, "caller is required");
        Objects.requireNonNull(entity, "entity is required");
        if (caller.tenantId() != null) {
            String entityTenant = spec.extractTenantFromEntity(entity);
            if (entityTenant != null && !Objects.equals(caller.tenantId(), entityTenant)) {
                return new ReadSimulationOutcome<>(
                        false,
                        "hard-scope-tenant-mismatch",
                        null,
                        Set.of(),
                        Set.of()
                );
            }
        }
        try {
            spec.verifyEntityAccessAllowed(entity, caller, null);
        } catch (SecurityException ex) {
            return new ReadSimulationOutcome<>(
                    false,
                    "policy-gate-denied",
                    null,
                    Set.of(),
                    Set.of()
            );
        }
        Map<String, Object> mergedFacts = new LinkedHashMap<>(caller.subjectAndEnvironmentFacts());
        if (caller.tenantId() != null) {
            mergedFacts.putIfAbsent("subject.tenantId", caller.tenantId());
        }
        Map<String, Object> targetFacts = spec.extractEntityTargetFacts(entity);
        if (targetFacts != null) {
            mergedFacts.putAll(targetFacts);
        }
        Map<String, FactResolutionStatus> statuses = new LinkedHashMap<>();
        for (String key : mergedFacts.keySet()) {
            statuses.put(key, FactResolutionStatus.PRESENT);
        }
        String factDigest = (effectiveDp.factContractRef() != null
                        && effectiveDp.factContractRef().factContractDigest() != null)
                ? effectiveDp.factContractRef().factContractDigest()
                : spec.factContractDigest();
        try {
            // P10.16-R01: When simulating a custom @UiSurface decision point, verify primary resource
            // TARGET gate first (mirroring findEntityById(id) at runtime execution).
            if (spec.decisionPoint() != null
                    && !Objects.equals(
                            effectiveDp.identity().pointKey(),
                            spec.decisionPoint().identity().pointKey()
                    )) {
                authorizationSeam.evaluateTargetReadProjection(
                        spec.decisionPoint(),
                        spec.factContractDigest(),
                        mergedFacts,
                        statuses
                );
            }
            TargetReadProjectionEvaluation eval = authorizationSeam.evaluateTargetReadProjection(
                    effectiveDp,
                    factDigest,
                    mergedFacts,
                    statuses
            );
            Set<String> maskedAttrs = new LinkedHashSet<>();
            if (eval.maskDirectives() != null) {
                for (MaskDirective dir : eval.maskDirectives()) {
                    if (dir != null && dir.attributeId() != null) {
                        maskedAttrs.add(dir.attributeId());
                    }
                }
            }
            ResponseDTO maskedDto = null;
            if (rawResponseDto != null) {
                List<DetachedDtoMaskingResult> results = maskingProcessor.projectAndMaskPage(
                        List.of(new RowMaskingInput(
                                rawResponseDto,
                                eval.valueDeniedAttributeIds(),
                                eval.maskDirectives()
                        )),
                        responseGovernanceContract.fieldSchemas()
                );
                if (!results.isEmpty()) {
                    maskedDto = objectMapper.convertValue(results.getFirst().detachedProjection(), responseDtoClass);
                }
            }
            return new ReadSimulationOutcome<>(
                    true,
                    null,
                    maskedDto,
                    Set.copyOf(maskedAttrs),
                    eval.valueDeniedAttributeIds()
            );
        } catch (SecurityException ex) {
            return new ReadSimulationOutcome<>(
                    false,
                    "policy-gate-denied",
                    null,
                    Set.of(),
                    Set.of()
            );
        }
    }

    private AuthzResourceOperationAvailabilityProvider buildProviderForCaller(
            AuthzCallerContext caller,
            E entity
    ) {
        Map<String, Object> subjectFacts = new LinkedHashMap<>(caller.subjectAndEnvironmentFacts());
        if (caller.tenantId() != null) {
            subjectFacts.putIfAbsent("subject.tenantId", caller.tenantId());
        }
        Map<String, FactResolutionStatus> subjectStatuses = new LinkedHashMap<>();
        for (String key : subjectFacts.keySet()) {
            subjectStatuses.put(key, FactResolutionStatus.PRESENT);
        }
        boolean callerCedente = spec.isCallerCedente(entity, caller);
        boolean callerCessionario = spec.isCallerCessionario(entity, caller);

        CallerAvailabilityFactContext callerAvailCtx = new CallerAvailabilityFactContext(
                subjectFacts,
                subjectStatuses,
                callerCedente,
                callerCessionario,
                caller.tenantId()
        );

        ResourceAvailabilityPolicyBinding binding = new ResourceAvailabilityPolicyBinding(
                spec.resourceKey(),
                spec.decisionPoint(),
                spec.factContractDigest(),
                spec.dualScopeDelegationSpec(),
                spec.operationModifiedAttributes(),
                () -> callerAvailCtx,
                spec::extractSnapshotTargetFacts,
                rawId -> entity == null ? Optional.empty() : Optional.of(spec.toResourceStateSnapshot(entity)),
                (ctx, snap) -> entity != null ? spec.isCallerCedente(entity, caller) : spec.isCallerCedenteForSnapshot(snap, caller),
                (ctx, snap) -> entity != null ? spec.isCallerCessionario(entity, caller) : spec.isCallerCessionarioForSnapshot(snap, caller),
                spec.actionDecisionPoints(),
                spec.surfaceDecisionPoints()
        );

        AuthzResourceOperationAvailabilityProvider provider =
                new AuthzResourceOperationAvailabilityProvider(authorizationSeam);
        provider.registerResourceBinding(binding);
        return provider;
    }

    @SuppressWarnings("unchecked")
    private static AvailabilitySimulationOutcome toAvailabilityOutcome(AvailabilityDecision decision) {
        Map<String, Object> meta = decision.metadata() == null ? Map.of() : decision.metadata();
        String denialCategory = meta.get("denialCategory") instanceof String s ? s : null;
        String custodyRole = meta.get("dualScopeCustodyRole") instanceof String s ? s : null;
        List<String> forbiddenWriteAttrs = meta.get("forbiddenWriteAttributeIds") instanceof List<?> list
                ? (List<String>) list
                : List.of();
        List<String> reasonCodes = meta.get("policyReasonCodes") instanceof List<?> list
                ? (List<String>) list
                : List.of();
        return new AvailabilitySimulationOutcome(
                decision.allowed(),
                decision.reason(),
                denialCategory,
                custodyRole,
                forbiddenWriteAttrs,
                reasonCodes,
                meta
        );
    }

    /**
     * Fluent tabular runner for executing and asserting multiple policy simulation rows
     * ({@code Fase P10.16-C}).
     *
     * @param <E> entity type
     * @param <ResponseDTO> response DTO type
     */
    public static final class MatrixRunner<E, ResponseDTO> {

        private final AuthzPolicySimulationHarness<E, ResponseDTO> harness;
        private final List<Runnable> checks = new ArrayList<>();
        private final List<String> failures = new ArrayList<>();

        private MatrixRunner(AuthzPolicySimulationHarness<E, ResponseDTO> harness) {
            this.harness = harness;
        }

        /** Adds an item-scoped availability expectation row to the matrix. */
        public MatrixRunner<E, ResponseDTO> expectItemAvailability(
                String scenarioLabel,
                AuthzCallerContext caller,
                String operationId,
                E entity,
                boolean expectedAllowed,
                String expectedDenialReason
        ) {
            checks.add(() -> {
                AvailabilitySimulationOutcome out = harness.simulateItemAvailability(caller, operationId, entity);
                if (out.allowed() != expectedAllowed) {
                    failures.add("[" + scenarioLabel + "] operation='" + operationId + "': expected allowed="
                            + expectedAllowed + ", actual allowed=" + out.allowed()
                            + " (reason=" + out.reason() + ", metadata=" + out.metadata() + ")");
                } else if (!expectedAllowed && expectedDenialReason != null
                        && !Objects.equals(expectedDenialReason, out.reason())) {
                    failures.add("[" + scenarioLabel + "] operation='" + operationId + "': expected denial reason='"
                            + expectedDenialReason + "', actual='" + out.reason() + "'");
                }
            });
            return this;
        }

        /** Adds a collection-scoped availability expectation row to the matrix. */
        public MatrixRunner<E, ResponseDTO> expectCollectionAvailability(
                String scenarioLabel,
                AuthzCallerContext caller,
                String operationId,
                boolean expectedAllowed,
                String expectedDenialReason
        ) {
            checks.add(() -> {
                AvailabilitySimulationOutcome out = harness.simulateCollectionAvailability(caller, operationId);
                if (out.allowed() != expectedAllowed) {
                    failures.add("[" + scenarioLabel + "] collection operation='" + operationId + "': expected allowed="
                            + expectedAllowed + ", actual allowed=" + out.allowed()
                            + " (reason=" + out.reason() + ", metadata=" + out.metadata() + ")");
                } else if (!expectedAllowed && expectedDenialReason != null
                        && !Objects.equals(expectedDenialReason, out.reason())) {
                    failures.add("[" + scenarioLabel + "] collection operation='" + operationId
                            + "': expected denial reason='" + expectedDenialReason + "', actual='" + out.reason() + "'");
                }
            });
            return this;
        }

        /** Adds a target read projection &amp; masking expectation row to the matrix. */
        public MatrixRunner<E, ResponseDTO> expectTargetReadAllowed(
                String scenarioLabel,
                AuthzCallerContext caller,
                E entity,
                ResponseDTO rawDto,
                Set<String> expectedMaskedAttributeIds
        ) {
            checks.add(() -> {
                ReadSimulationOutcome<ResponseDTO> out = harness.simulateTargetRead(caller, entity, rawDto);
                if (!out.allowed()) {
                    failures.add("[" + scenarioLabel + "] targetRead: expected ALLOWED, actual DENIED ("
                            + out.denialReason() + ")");
                } else if (expectedMaskedAttributeIds != null
                        && !Objects.equals(expectedMaskedAttributeIds, out.maskedAttributeIds())) {
                    failures.add("[" + scenarioLabel + "] targetRead: expected maskedAttributeIds="
                            + expectedMaskedAttributeIds + ", actual=" + out.maskedAttributeIds());
                }
            });
            return this;
        }

        /** Adds a surface read projection &amp; masking expectation row to the matrix. */
        public MatrixRunner<E, ResponseDTO> expectSurfaceReadAllowed(
                String scenarioLabel,
                AuthzCallerContext caller,
                String surfaceKey,
                E entity,
                ResponseDTO rawDto,
                Set<String> expectedMaskedAttributeIds
        ) {
            checks.add(() -> {
                ReadSimulationOutcome<ResponseDTO> out = harness.simulateSurfaceRead(caller, surfaceKey, entity, rawDto);
                if (!out.allowed()) {
                    failures.add("[" + scenarioLabel + "] surfaceRead('" + surfaceKey
                            + "'): expected ALLOWED, actual DENIED (" + out.denialReason() + ")");
                } else if (expectedMaskedAttributeIds != null
                        && !Objects.equals(expectedMaskedAttributeIds, out.maskedAttributeIds())) {
                    failures.add("[" + scenarioLabel + "] surfaceRead('" + surfaceKey
                            + "'): expected maskedAttributeIds=" + expectedMaskedAttributeIds
                            + ", actual=" + out.maskedAttributeIds());
                }
            });
            return this;
        }

        /** Adds a bulk workflow command cohort simulation expectation row to the matrix ({@code P10.16-R05}). */
        public <ID> MatrixRunner<E, ResponseDTO> expectBulkCommand(
                String scenarioLabel,
                AuthzCallerContext caller,
                String actionKey,
                List<E> candidateEntities,
                java.util.function.Function<E, ID> idExtractor,
                org.praxisplatform.authz.contracts.binding.BatchAuthorizationMode batchMode,
                List<Boolean> expectedCommittedFlags
        ) {
            checks.add(() -> {
                List<AuthzGovernedBulkDomainResourceAdapter.BulkCohortItemOutcome<ID>> outcomes =
                        harness.simulateBulkCommand(caller, actionKey, candidateEntities, idExtractor, batchMode);
                List<Boolean> actualFlags = outcomes.stream()
                        .map(AuthzGovernedBulkDomainResourceAdapter.BulkCohortItemOutcome::committed)
                        .toList();
                if (!Objects.equals(expectedCommittedFlags, actualFlags)) {
                    failures.add("[" + scenarioLabel + "] bulkCommand('" + actionKey + "'): expected committed="
                            + expectedCommittedFlags + ", actual=" + actualFlags + " (outcomes=" + outcomes + ")");
                }
            });
            return this;
        }

        /** Adds an assisted {@code DuplicateDraft} simulation expectation row to the matrix ({@code Fase P10.17-B}). */
        public <DraftDTO> MatrixRunner<E, ResponseDTO> expectDuplicateDraft(
                String scenarioLabel,
                AuthzCallerContext caller,
                E sourceEntity,
                DraftDTO rawDraft,
                boolean expectedAllowed,
                Set<String> expectedStrippedAttributes
        ) {
            checks.add(() -> {
                DuplicateDraftSimulationOutcome<DraftDTO> out =
                        harness.simulateDuplicateDraft(caller, sourceEntity, rawDraft);
                if (out.allowed() != expectedAllowed) {
                    failures.add("[" + scenarioLabel + "] duplicateDraft: expected allowed=" + expectedAllowed
                            + ", actual allowed=" + out.allowed() + " (reason=" + out.denialReason() + ")");
                } else if (expectedAllowed && expectedStrippedAttributes != null
                        && ! out.strippedAttributes().containsAll(expectedStrippedAttributes)) {
                    failures.add("[" + scenarioLabel + "] duplicateDraft: expected strippedAttributes to contain "
                            + expectedStrippedAttributes + ", actual=" + out.strippedAttributes());
                }
            });
            return this;
        }

        /** Adds a governed collection export simulation expectation row to the matrix ({@code Fase P10.17-B}). */
        public MatrixRunner<E, ResponseDTO> expectCollectionExport(
                String scenarioLabel,
                AuthzCallerContext caller,
                List<E> candidateEntities,
                java.util.function.Function<E, ResponseDTO> rawResponseMapper,
                int expectedRowCount,
                Set<String> expectedExcludedFields
        ) {
            checks.add(() -> {
                CollectionExportSimulationOutcome out =
                        harness.simulateCollectionExport(caller, candidateEntities, rawResponseMapper);
                if (!out.allowed()) {
                    failures.add("[" + scenarioLabel + "] collectionExport: expected ALLOWED, actual DENIED ("
                            + out.denialReason() + ")");
                } else if (out.exportedRows().size() != expectedRowCount) {
                    failures.add("[" + scenarioLabel + "] collectionExport: expected rowCount=" + expectedRowCount
                            + ", actual=" + out.exportedRows().size());
                } else if (expectedExcludedFields != null
                        && !out.excludedFields().containsAll(expectedExcludedFields)) {
                    failures.add("[" + scenarioLabel + "] collectionExport: expected excludedFields to contain "
                            + expectedExcludedFields + ", actual=" + out.excludedFields());
                }
            });
            return this;
        }

        /** Adds a governed reactive determination simulation expectation row to the matrix ({@code Fase P10.18-A}). */
        public MatrixRunner<E, ResponseDTO> expectReactiveDetermination(
                String scenarioLabel,
                AuthzCallerContext caller,
                E entity,
                Map<String, Object> rawDeterminationPayload,
                boolean expectedAllowed,
                Set<String> expectedMaskedAttributeIds
        ) {
            checks.add(() -> {
                ReactiveDeterminationSimulationOutcome out =
                        harness.simulateReactiveDetermination(caller, entity, rawDeterminationPayload);
                if (out.allowed() != expectedAllowed) {
                    failures.add("[" + scenarioLabel + "] reactiveDetermination: expected allowed=" + expectedAllowed
                            + ", actual allowed=" + out.allowed() + " (reason=" + out.denialReason() + ")");
                } else if (expectedAllowed && expectedMaskedAttributeIds != null
                        && !out.maskedAttributeIds().containsAll(expectedMaskedAttributeIds)) {
                    failures.add("[" + scenarioLabel + "] reactiveDetermination: expected maskedAttributeIds to contain "
                            + expectedMaskedAttributeIds + ", actual=" + out.maskedAttributeIds());
                }
            });
            return this;
        }

        /** Adds an AI Context / Tool Grounding projection expectation row to the matrix ({@code Fase P10.18-A}). */
        public MatrixRunner<E, ResponseDTO> expectAiContextProjection(
                String scenarioLabel,
                AuthzCallerContext caller,
                E entity,
                ResponseDTO rawResponseDto,
                boolean expectedAllowed,
                Set<String> expectedSuppressedAttributes
        ) {
            checks.add(() -> {
                AiContextSimulationOutcome out =
                        harness.simulateAiContextProjection(caller, entity, rawResponseDto);
                if (out.allowed() != expectedAllowed) {
                    failures.add("[" + scenarioLabel + "] aiContextProjection: expected allowed=" + expectedAllowed
                            + ", actual allowed=" + out.allowed() + " (reason=" + out.denialReason() + ")");
                } else if (expectedAllowed && expectedSuppressedAttributes != null
                        && !out.suppressedAttributeIds().containsAll(expectedSuppressedAttributes)) {
                    failures.add("[" + scenarioLabel + "] aiContextProjection: expected suppressedAttributeIds to contain "
                            + expectedSuppressedAttributes + ", actual=" + out.suppressedAttributeIds());
                }
            });
            return this;
        }

        /** Adds a query field-use ({@code FILTER}/{@code SORT}/{@code GROUP}/{@code AGGREGATE}) expectation row to the matrix ({@code Fase P10.18-B}). */
        public MatrixRunner<E, ResponseDTO> expectQueryFieldUse(
                String scenarioLabel,
                AuthzCallerContext caller,
                Map<FieldUseCategory, Set<String>> requestedFieldUses,
                boolean expectedAllowed,
                FieldUseCategory expectedViolatedCategory,
                String expectedViolatedAttributeId
        ) {
            checks.add(() -> {
                QueryFieldUseSimulationOutcome out = harness.simulateQueryFieldUse(caller, requestedFieldUses);
                if (out.allowed() != expectedAllowed) {
                    failures.add("[" + scenarioLabel + "] queryFieldUse: expected allowed=" + expectedAllowed
                            + ", actual allowed=" + out.allowed() + " (reason=" + out.denialReason()
                            + ", category=" + out.violatedCategory()
                            + ", attributes=" + out.violatedAttributeIds() + ")");
                } else if (!expectedAllowed) {
                    if (expectedViolatedCategory != null && out.violatedCategory() != expectedViolatedCategory) {
                        failures.add("[" + scenarioLabel + "] queryFieldUse: expected violatedCategory="
                                + expectedViolatedCategory + ", actual=" + out.violatedCategory());
                    }
                    if (expectedViolatedAttributeId != null
                            && !out.violatedAttributeIds().contains(expectedViolatedAttributeId)) {
                        failures.add("[" + scenarioLabel + "] queryFieldUse: expected violatedAttributeIds to contain '"
                                + expectedViolatedAttributeId + "', actual=" + out.violatedAttributeIds());
                    }
                }
            });
            return this;
        }

        /** Adds an analytical {@code GROUP BY} / {@code AGGREGATE} simulation expectation row to the matrix ({@code Fase P10.19-A}). */
        public MatrixRunner<E, ResponseDTO> expectGroupByStats(
                String scenarioLabel,
                AuthzCallerContext caller,
                String groupByField,
                Set<String> metricFields,
                boolean expectedAllowed,
                FieldUseCategory expectedViolatedCategory,
                String expectedViolatedAttributeId
        ) {
            checks.add(() -> {
                StatsSimulationOutcome out = harness.simulateGroupByStats(caller, groupByField, metricFields);
                if (out.allowed() != expectedAllowed) {
                    failures.add("[" + scenarioLabel + "] groupByStats('" + groupByField + "'): expected allowed="
                            + expectedAllowed + ", actual allowed=" + out.allowed()
                            + " (reason=" + out.denialReason() + ", category=" + out.violatedCategory()
                            + ", attributes=" + out.violatedAttributeIds() + ")");
                } else if (!expectedAllowed) {
                    if (expectedViolatedCategory != null && out.violatedCategory() != expectedViolatedCategory) {
                        failures.add("[" + scenarioLabel + "] groupByStats('" + groupByField
                                + "'): expected violatedCategory=" + expectedViolatedCategory
                                + ", actual=" + out.violatedCategory());
                    }
                    if (expectedViolatedAttributeId != null
                            && !out.violatedAttributeIds().contains(expectedViolatedAttributeId)) {
                        failures.add("[" + scenarioLabel + "] groupByStats('" + groupByField
                                + "'): expected violatedAttributeIds to contain '" + expectedViolatedAttributeId
                                + "', actual=" + out.violatedAttributeIds());
                    }
                }
            });
            return this;
        }

        /** Adds a governed {@code OptionSource} simulation expectation row to the matrix ({@code Fase P10.19-A}). */
        public MatrixRunner<E, ResponseDTO> expectOptionSource(
                String scenarioLabel,
                AuthzCallerContext caller,
                List<E> candidateEntities,
                java.util.function.Function<E, OptionDTO<Object>> rawOptionMapper,
                Set<Object> expectedAdmittedIds
        ) {
            checks.add(() -> {
                OptionSourceSimulationOutcome out =
                        harness.simulateOptionSource(caller, candidateEntities, rawOptionMapper);
                if (!out.allowed()) {
                    failures.add("[" + scenarioLabel + "] optionSource: expected ALLOWED, actual DENIED ("
                            + out.denialReason() + ")");
                } else if (expectedAdmittedIds != null && !Objects.equals(expectedAdmittedIds, out.admittedIds())) {
                    failures.add("[" + scenarioLabel + "] optionSource: expected admittedIds="
                            + expectedAdmittedIds + ", actual=" + out.admittedIds());
                }
            });
            return this;
        }

        /** Adds a pre-hydration {@code CREATE} mutation simulation row to the matrix ({@code Fase P10.19-B}). */
        public MatrixRunner<E, ResponseDTO> expectCreateMutation(
                String scenarioLabel,
                AuthzCallerContext caller,
                Object createDto,
                E candidateEntity,
                boolean expectedAllowed,
                String expectedDenialReason
        ) {
            checks.add(() -> {
                WriteMutationSimulationOutcome out =
                        harness.simulateCreateMutation(caller, createDto, candidateEntity);
                if (out.allowed() != expectedAllowed) {
                    failures.add("[" + scenarioLabel + "] createMutation: expected allowed=" + expectedAllowed
                            + ", actual allowed=" + out.allowed() + " (reason=" + out.denialReason()
                            + ", reasonCode=" + out.reasonCode() + ")");
                } else if (!expectedAllowed && expectedDenialReason != null
                        && !Objects.equals(expectedDenialReason, out.denialReason())) {
                    failures.add("[" + scenarioLabel + "] createMutation: expected denialReason='"
                            + expectedDenialReason + "', actual='" + out.denialReason() + "'");
                }
            });
            return this;
        }

        /** Adds a pre-hydration {@code UPDATE} ({@code PATCH}) mutation simulation row to the matrix ({@code Fase P10.19-B}). */
        public MatrixRunner<E, ResponseDTO> expectUpdateMutation(
                String scenarioLabel,
                AuthzCallerContext caller,
                E existingEntity,
                Object updateDto,
                boolean expectedAllowed,
                String expectedDenialReason
        ) {
            checks.add(() -> {
                WriteMutationSimulationOutcome out =
                        harness.simulateUpdateMutation(caller, existingEntity, updateDto);
                if (out.allowed() != expectedAllowed) {
                    failures.add("[" + scenarioLabel + "] updateMutation: expected allowed=" + expectedAllowed
                            + ", actual allowed=" + out.allowed() + " (reason=" + out.denialReason()
                            + ", reasonCode=" + out.reasonCode() + ")");
                } else if (!expectedAllowed && expectedDenialReason != null
                        && !Objects.equals(expectedDenialReason, out.denialReason())) {
                    failures.add("[" + scenarioLabel + "] updateMutation: expected denialReason='"
                            + expectedDenialReason + "', actual='" + out.denialReason() + "'");
                }
            });
            return this;
        }

        /** Adds a pre-deletion {@code DELETE} mutation simulation row to the matrix ({@code Fase P10.19-B}). */
        public MatrixRunner<E, ResponseDTO> expectDeleteMutation(
                String scenarioLabel,
                AuthzCallerContext caller,
                E existingEntity,
                boolean expectedAllowed,
                String expectedDenialReason
        ) {
            checks.add(() -> {
                WriteMutationSimulationOutcome out = harness.simulateDeleteMutation(caller, existingEntity);
                if (out.allowed() != expectedAllowed) {
                    failures.add("[" + scenarioLabel + "] deleteMutation: expected allowed=" + expectedAllowed
                            + ", actual allowed=" + out.allowed() + " (reason=" + out.denialReason()
                            + ", reasonCode=" + out.reasonCode() + ")");
                } else if (!expectedAllowed && expectedDenialReason != null
                        && !Objects.equals(expectedDenialReason, out.denialReason())) {
                    failures.add("[" + scenarioLabel + "] deleteMutation: expected denialReason='"
                            + expectedDenialReason + "', actual='" + out.denialReason() + "'");
                }
            });
            return this;
        }

        /** Adds an item {@code @WorkflowAction} / {@code @ResourceIntent} command mutation simulation row to the matrix ({@code Fase P10.19-B}). */
        public MatrixRunner<E, ResponseDTO> expectItemCommandMutation(
                String scenarioLabel,
                AuthzCallerContext caller,
                String actionOrOperationId,
                E existingEntity,
                Object commandDto,
                boolean expectedAllowed,
                String expectedDenialReason
        ) {
            checks.add(() -> {
                WriteMutationSimulationOutcome out = harness.simulateItemCommandMutation(
                        caller,
                        actionOrOperationId,
                        existingEntity,
                        commandDto
                );
                if (out.allowed() != expectedAllowed) {
                    failures.add("[" + scenarioLabel + "] itemCommandMutation('" + actionOrOperationId
                            + "'): expected allowed=" + expectedAllowed
                            + ", actual allowed=" + out.allowed() + " (reason=" + out.denialReason()
                            + ", reasonCode=" + out.reasonCode() + ")");
                } else if (!expectedAllowed && expectedDenialReason != null
                        && !Objects.equals(expectedDenialReason, out.denialReason())) {
                    failures.add("[" + scenarioLabel + "] itemCommandMutation('" + actionOrOperationId
                            + "'): expected denialReason='" + expectedDenialReason
                            + "', actual='" + out.denialReason() + "'");
                }
            });
            return this;
        }

        /** Adds a {@code TimeSeries} ({@code /stats/timeseries}) simulation row to the matrix ({@code Fase P10.20-B}). */
        public MatrixRunner<E, ResponseDTO> expectTimeSeriesStats(
                String scenarioLabel,
                AuthzCallerContext caller,
                String timeField,
                Set<String> metricFields,
                Object filterDto,
                boolean expectedAllowed,
                FieldUseCategory expectedViolatedCategory,
                String expectedViolatedAttributeId
        ) {
            checks.add(() -> {
                StatsSimulationOutcome out =
                        harness.simulateTimeSeriesStats(caller, timeField, metricFields, filterDto);
                verifyStatsMatrixRow(
                        scenarioLabel,
                        "timeSeriesStats('" + timeField + "')",
                        out,
                        expectedAllowed,
                        expectedViolatedCategory,
                        expectedViolatedAttributeId
                );
            });
            return this;
        }

        /** Adds a {@code Distribution} ({@code /stats/distribution}) simulation row to the matrix ({@code Fase P10.20-B}). */
        public MatrixRunner<E, ResponseDTO> expectDistributionStats(
                String scenarioLabel,
                AuthzCallerContext caller,
                String distributionField,
                String metricField,
                Object filterDto,
                boolean expectedAllowed,
                FieldUseCategory expectedViolatedCategory,
                String expectedViolatedAttributeId
        ) {
            checks.add(() -> {
                StatsSimulationOutcome out =
                        harness.simulateDistributionStats(caller, distributionField, metricField, filterDto);
                verifyStatsMatrixRow(
                        scenarioLabel,
                        "distributionStats('" + distributionField + "')",
                        out,
                        expectedAllowed,
                        expectedViolatedCategory,
                        expectedViolatedAttributeId
                );
            });
            return this;
        }

        /** Adds a {@code Comparison} ({@code /stats/comparison}) simulation row to the matrix ({@code Fase P10.20-B}). */
        public MatrixRunner<E, ResponseDTO> expectComparisonStats(
                String scenarioLabel,
                AuthzCallerContext caller,
                String dimensionField,
                Set<String> metricFields,
                Object primaryFilterDto,
                Object comparisonFilterDto,
                boolean expectedAllowed,
                FieldUseCategory expectedViolatedCategory,
                String expectedViolatedAttributeId
        ) {
            checks.add(() -> {
                StatsSimulationOutcome out = harness.simulateComparisonStats(
                        caller,
                        dimensionField,
                        metricFields,
                        primaryFilterDto,
                        comparisonFilterDto
                );
                verifyStatsMatrixRow(
                        scenarioLabel,
                        "comparisonStats('" + dimensionField + "')",
                        out,
                        expectedAllowed,
                        expectedViolatedCategory,
                        expectedViolatedAttributeId
                );
            });
            return this;
        }

        /** Adds a cohort-scoped {@code BulkMode.UNIFORM_UPDATE} simulation row to the matrix ({@code Fase P10.20-B}). */
        public <ID> MatrixRunner<E, ResponseDTO> expectBulkUpdateCohort(
                String scenarioLabel,
                AuthzCallerContext caller,
                List<E> candidateEntities,
                java.util.function.Function<E, ID> idExtractor,
                Object uniformUpdateDto,
                org.praxisplatform.authz.contracts.binding.BatchAuthorizationMode batchMode,
                boolean expectedBatchAborted,
                Set<ID> expectedCommittedIds
        ) {
            checks.add(() -> {
                BulkMutationSimulationOutcome<ID> out = harness.simulateBulkUpdateCohort(
                        caller,
                        candidateEntities,
                        idExtractor,
                        uniformUpdateDto,
                        batchMode
                );
                verifyBulkCohortMatrixRow(scenarioLabel, "bulkUpdateCohort", out, expectedBatchAborted, expectedCommittedIds);
            });
            return this;
        }

        /** Adds a cohort-scoped {@code BulkMode.PER_ITEM_UPDATE} simulation row to the matrix ({@code Fase P10.21-R04}). */
        public <ID> MatrixRunner<E, ResponseDTO> expectBulkPerItemUpdateCohort(
                String scenarioLabel,
                AuthzCallerContext caller,
                List<E> candidateEntities,
                java.util.function.Function<E, ID> idExtractor,
                Map<ID, Object> payloadsByItemId,
                org.praxisplatform.authz.contracts.binding.BatchAuthorizationMode batchMode,
                boolean expectedBatchAborted,
                Set<ID> expectedCommittedIds
        ) {
            checks.add(() -> {
                BulkMutationSimulationOutcome<ID> out = harness.simulateBulkPerItemUpdateCohort(
                        caller,
                        candidateEntities,
                        idExtractor,
                        payloadsByItemId,
                        batchMode
                );
                verifyBulkCohortMatrixRow(
                        scenarioLabel,
                        "bulkPerItemUpdateCohort",
                        out,
                        expectedBatchAborted,
                        expectedCommittedIds
                );
            });
            return this;
        }

        /** Adds a cohort-scoped bulk {@code DELETE} simulation row to the matrix ({@code Fase P10.20-B}). */
        public <ID> MatrixRunner<E, ResponseDTO> expectBulkDeleteCohort(
                String scenarioLabel,
                AuthzCallerContext caller,
                List<E> candidateEntities,
                java.util.function.Function<E, ID> idExtractor,
                org.praxisplatform.authz.contracts.binding.BatchAuthorizationMode batchMode,
                boolean expectedBatchAborted,
                Set<ID> expectedCommittedIds
        ) {
            checks.add(() -> {
                BulkMutationSimulationOutcome<ID> out = harness.simulateBulkDeleteCohort(
                        caller,
                        candidateEntities,
                        idExtractor,
                        batchMode
                );
                verifyBulkCohortMatrixRow(scenarioLabel, "bulkDeleteCohort", out, expectedBatchAborted, expectedCommittedIds);
            });
            return this;
        }

        /** Adds a cohort-scoped {@code BulkMode.DOMAIN_COMMAND} simulation row to the matrix ({@code Fase P10.20-B}). */
        public <ID> MatrixRunner<E, ResponseDTO> expectBulkCommandCohort(
                String scenarioLabel,
                AuthzCallerContext caller,
                String actionOrOperationId,
                List<E> candidateEntities,
                java.util.function.Function<E, ID> idExtractor,
                Object commandDto,
                org.praxisplatform.authz.contracts.binding.BatchAuthorizationMode batchMode,
                boolean expectedBatchAborted,
                Set<ID> expectedCommittedIds
        ) {
            checks.add(() -> {
                BulkMutationSimulationOutcome<ID> out = harness.simulateBulkCommandCohort(
                        caller,
                        actionOrOperationId,
                        candidateEntities,
                        idExtractor,
                        commandDto,
                        batchMode
                );
                verifyBulkCohortMatrixRow(
                        scenarioLabel,
                        "bulkCommandCohort('" + actionOrOperationId + "')",
                        out,
                        expectedBatchAborted,
                        expectedCommittedIds
                );
            });
            return this;
        }

        /** Adds a 2-phase bulk proposal &amp; confirmation simulation row to the matrix ({@code Fase P10.21-B}). */
        public <ID> MatrixRunner<E, ResponseDTO> expectTwoPhaseBulkConfirm(
                String scenarioLabel,
                AuthzCallerContext proposingCaller,
                AuthzCallerContext confirmingCaller,
                String proposalPolicyDigest,
                String confirmPolicyDigest,
                List<E> candidateEntities,
                java.util.function.Function<E, ID> idExtractor,
                java.util.function.Function<E, ResponseDTO> rawResponseMapper,
                Object uniformUpdateDto,
                org.praxisplatform.authz.contracts.binding.BatchAuthorizationMode batchMode,
                boolean expectedConfirmAllowed,
                String expectedConfirmDenialReason
        ) {
            checks.add(() -> {
                BulkTwoPhaseSimulationOutcome<ID, ResponseDTO> out = harness.simulateTwoPhaseBulkProposalAndConfirm(
                        proposingCaller,
                        confirmingCaller,
                        proposalPolicyDigest,
                        confirmPolicyDigest,
                        candidateEntities,
                        idExtractor,
                        rawResponseMapper,
                        uniformUpdateDto,
                        batchMode
                );
                if (out.confirmAllowed() != expectedConfirmAllowed) {
                    failures.add("[" + scenarioLabel + "] twoPhaseBulkConfirm: expected confirmAllowed="
                            + expectedConfirmAllowed + ", actual=" + out.confirmAllowed()
                            + " (confirmDenialReason=" + out.confirmDenialReason() + ")");
                } else if (!expectedConfirmAllowed && expectedConfirmDenialReason != null
                        && !Objects.equals(expectedConfirmDenialReason, out.confirmDenialReason())) {
                    failures.add("[" + scenarioLabel + "] twoPhaseBulkConfirm: expected confirmDenialReason='"
                            + expectedConfirmDenialReason + "', actual='" + out.confirmDenialReason() + "'");
                }
            });
            return this;
        }

        /** Adds an untrusted request header anti-spoofing simulation row to the matrix ({@code Fase P10.21-B}). */
        public MatrixRunner<E, ResponseDTO> expectHeaderSpoofingGuard(
                String scenarioLabel,
                AuthzCallerContext caller,
                boolean expectedAllowed,
                String expectedRejectedHeaderName
        ) {
            checks.add(() -> {
                HeaderSpoofingSimulationOutcome out = harness.simulateHeaderSpoofingGuard(caller);
                if (out.allowed() != expectedAllowed) {
                    failures.add("[" + scenarioLabel + "] headerSpoofingGuard: expected allowed="
                            + expectedAllowed + ", actual=" + out.allowed()
                            + " (rejectedHeaderNames=" + out.rejectedHeaderNames() + ")");
                } else if (!expectedAllowed && expectedRejectedHeaderName != null
                        && out.rejectedHeaderNames().stream().noneMatch(h -> h.equalsIgnoreCase(expectedRejectedHeaderName))) {
                    failures.add("[" + scenarioLabel + "] headerSpoofingGuard: expected rejectedHeaderNames to contain '"
                            + expectedRejectedHeaderName + "', actual=" + out.rejectedHeaderNames());
                }
            });
            return this;
        }

        /** Adds a {@code @UiSurface} read projection simulation row to the matrix ({@code Fase P10.22-B}). */
        public MatrixRunner<E, ResponseDTO> expectSurfaceRead(
                String scenarioLabel,
                AuthzCallerContext caller,
                String surfaceKey,
                E entity,
                ResponseDTO rawResponseDto,
                boolean expectedAllowed,
                Set<String> expectedMaskedAttributes
        ) {
            checks.add(() -> {
                ReadSimulationOutcome<ResponseDTO> out = harness.simulateSurfaceRead(
                        caller,
                        surfaceKey,
                        entity,
                        rawResponseDto
                );
                if (out.allowed() != expectedAllowed) {
                    failures.add("[" + scenarioLabel + "] surfaceRead('" + surfaceKey + "'): expected allowed="
                            + expectedAllowed + ", actual=" + out.allowed()
                            + " (denialReason=" + out.denialReason() + ")");
                } else if (expectedAllowed && expectedMaskedAttributes != null
                        && !out.maskedAttributeIds().containsAll(expectedMaskedAttributes)) {
                    failures.add("[" + scenarioLabel + "] surfaceRead('" + surfaceKey + "'): expected maskedAttributeIds to contain "
                            + expectedMaskedAttributes + ", actual=" + out.maskedAttributeIds());
                }
            });
            return this;
        }

        /** Adds an item-scoped reactive determination simulation row to the matrix ({@code Fase P10.22-B}). */
        public MatrixRunner<E, ResponseDTO> expectReactiveDetermination(
                String scenarioLabel,
                AuthzCallerContext caller,
                String determinationId,
                E entity,
                Map<String, Object> rawDeterminationPayload,
                boolean expectedAllowed,
                Set<String> expectedMaskedAttributes
        ) {
            checks.add(() -> {
                ReactiveDeterminationSimulationOutcome out = harness.simulateReactiveDetermination(
                        caller,
                        determinationId,
                        entity,
                        rawDeterminationPayload
                );
                if (out.allowed() != expectedAllowed) {
                    failures.add("[" + scenarioLabel + "] reactiveDetermination('" + determinationId + "'): expected allowed="
                            + expectedAllowed + ", actual=" + out.allowed()
                            + " (denialReason=" + out.denialReason() + ")");
                } else if (expectedAllowed && expectedMaskedAttributes != null
                        && !out.maskedAttributeIds().containsAll(expectedMaskedAttributes)) {
                    failures.add("[" + scenarioLabel + "] reactiveDetermination('" + determinationId + "'): expected maskedAttributeIds to contain "
                            + expectedMaskedAttributes + ", actual=" + out.maskedAttributeIds());
                }
            });
            return this;
        }

        /** Adds a draft/create-mode reactive determination simulation row to the matrix ({@code Fase P10.22-B}). */
        public MatrixRunner<E, ResponseDTO> expectDraftReactiveDetermination(
                String scenarioLabel,
                AuthzCallerContext caller,
                String determinationId,
                Map<String, Object> draftInputPayload,
                Map<String, Object> rawDeterminationOutputPayload,
                boolean expectedAllowed,
                Set<String> expectedMaskedAttributes
        ) {
            checks.add(() -> {
                ReactiveDeterminationSimulationOutcome out = harness.simulateDraftReactiveDetermination(
                        caller,
                        determinationId,
                        draftInputPayload,
                        rawDeterminationOutputPayload
                );
                if (out.allowed() != expectedAllowed) {
                    failures.add("[" + scenarioLabel + "] draftReactiveDetermination('" + determinationId + "'): expected allowed="
                            + expectedAllowed + ", actual=" + out.allowed()
                            + " (denialReason=" + out.denialReason() + ")");
                } else if (expectedAllowed && expectedMaskedAttributes != null
                        && !out.maskedAttributeIds().containsAll(expectedMaskedAttributes)) {
                    failures.add("[" + scenarioLabel + "] draftReactiveDetermination('" + determinationId + "'): expected maskedAttributeIds to contain "
                            + expectedMaskedAttributes + ", actual=" + out.maskedAttributeIds());
                }
            });
            return this;
        }

        /** Adds an option-source simulation row with explicit descriptor/operation/reload IDs to the matrix ({@code Fase P10.23-B}). */
        public MatrixRunner<E, ResponseDTO> expectOptionSource(
                String scenarioLabel,
                AuthzCallerContext caller,
                List<E> candidateEntities,
                java.util.function.Function<E, OptionDTO<Object>> rawOptionMapper,
                OptionSourceDescriptor descriptor,
                OptionSourceOperation operation,
                java.util.Collection<Object> includeOrByIds,
                Set<Object> expectedAdmittedIds
        ) {
            checks.add(() -> {
                OptionSourceSimulationOutcome out = harness.simulateOptionSource(
                        caller,
                        candidateEntities,
                        rawOptionMapper,
                        descriptor,
                        operation,
                        includeOrByIds
                );
                if (!out.allowed()) {
                    failures.add("[" + scenarioLabel + "] optionSource: expected allowed=true, actual=false (denialReason="
                            + out.denialReason() + ")");
                } else if (expectedAdmittedIds != null && !Objects.equals(expectedAdmittedIds, out.admittedIds())) {
                    failures.add("[" + scenarioLabel + "] optionSource: expected admittedIds="
                            + expectedAdmittedIds + ", actual=" + out.admittedIds());
                }
            });
            return this;
        }

        /** Adds an option-source simulation row with structured filters, symbolic sortKey, and search term to the matrix ({@code Fase P10.25-B}). */
        public MatrixRunner<E, ResponseDTO> expectOptionSource(
                String scenarioLabel,
                AuthzCallerContext caller,
                List<E> candidateEntities,
                java.util.function.Function<E, OptionDTO<Object>> rawOptionMapper,
                OptionSourceDescriptor descriptor,
                OptionSourceOperation operation,
                java.util.Collection<Object> includeOrByIds,
                List<org.praxisplatform.uischema.options.LookupFilterRequest> lookupFilters,
                String sortKey,
                String search,
                boolean expectedAllowed,
                Set<Object> expectedAdmittedIds
        ) {
            checks.add(() -> {
                OptionSourceSimulationOutcome out = harness.simulateOptionSource(
                        caller,
                        candidateEntities,
                        rawOptionMapper,
                        descriptor,
                        operation,
                        includeOrByIds,
                        lookupFilters,
                        sortKey,
                        search
                );
                if (out.allowed() != expectedAllowed) {
                    failures.add("[" + scenarioLabel + "] optionSource: expected allowed="
                            + expectedAllowed + ", actual=" + out.allowed()
                            + " (denialReason=" + out.denialReason() + ")");
                } else if (expectedAllowed && expectedAdmittedIds != null
                        && !Objects.equals(expectedAdmittedIds, out.admittedIds())) {
                    failures.add("[" + scenarioLabel + "] optionSource: expected admittedIds="
                            + expectedAdmittedIds + ", actual=" + out.admittedIds());
                }
            });
            return this;
        }

        /** Adds a cursor/keyset pagination simulation row to the matrix ({@code Fase P10.23-B}). */
        public <ID> MatrixRunner<E, ResponseDTO> expectCursorFilter(
                String scenarioLabel,
                AuthzCallerContext caller,
                List<E> candidateEntities,
                java.util.function.Function<E, ID> idExtractor,
                java.util.function.Function<E, ResponseDTO> rawDtoMapper,
                Object filterDto,
                Set<String> sortProperties,
                ID afterId,
                ID beforeId,
                int pageSize,
                boolean expectedAllowed,
                List<ID> expectedPageIds
        ) {
            checks.add(() -> {
                CursorFilterSimulationOutcome<ID, ResponseDTO> out = harness.simulateCursorFilter(
                        caller,
                        candidateEntities,
                        idExtractor,
                        rawDtoMapper,
                        filterDto,
                        sortProperties,
                        afterId,
                        beforeId,
                        pageSize
                );
                if (out.allowed() != expectedAllowed) {
                    failures.add("[" + scenarioLabel + "] cursorFilter: expected allowed="
                            + expectedAllowed + ", actual=" + out.allowed()
                            + " (denialReason=" + out.denialReason() + ")");
                } else if (expectedAllowed && expectedPageIds != null
                        && !Objects.equals(expectedPageIds, out.authorizedPageIds())) {
                    failures.add("[" + scenarioLabel + "] cursorFilter: expected pageIds="
                            + expectedPageIds + ", actual=" + out.authorizedPageIds());
                }
            });
            return this;
        }

        /** Adds a {@code locate(filterDto, sort, targetId)} simulation row to the matrix ({@code Fase P10.24-B}). */
        public <ID> MatrixRunner<E, ResponseDTO> expectLocate(
                String scenarioLabel,
                AuthzCallerContext caller,
                List<E> candidateEntities,
                java.util.function.Function<E, ID> idExtractor,
                java.util.function.Function<E, ResponseDTO> rawDtoMapper,
                Object filterDto,
                Set<String> sortProperties,
                ID targetId,
                boolean expectedAllowed,
                java.util.OptionalLong expectedLocatedIndex
        ) {
            checks.add(() -> {
                LocateSimulationOutcome<ID> out = harness.simulateLocate(
                        caller,
                        candidateEntities,
                        idExtractor,
                        rawDtoMapper,
                        filterDto,
                        sortProperties,
                        targetId
                );
                if (out.allowed() != expectedAllowed) {
                    failures.add("[" + scenarioLabel + "] locate('" + targetId + "'): expected allowed="
                            + expectedAllowed + ", actual=" + out.allowed()
                            + " (denialReason=" + out.denialReason() + ")");
                } else if (expectedAllowed && expectedLocatedIndex != null
                        && !Objects.equals(expectedLocatedIndex, out.locatedIndex())) {
                    failures.add("[" + scenarioLabel + "] locate('" + targetId + "'): expected locatedIndex="
                            + expectedLocatedIndex + ", actual=" + out.locatedIndex());
                }
            });
            return this;
        }

        /** Adds a {@code findAllById(requestedIds)} simulation row to the matrix ({@code Fase P10.24-B}). */
        public <ID> MatrixRunner<E, ResponseDTO> expectFindAllById(
                String scenarioLabel,
                AuthzCallerContext caller,
                List<E> candidateEntities,
                java.util.function.Function<E, ID> idExtractor,
                java.util.function.Function<E, ResponseDTO> rawDtoMapper,
                java.util.Collection<ID> requestedIds,
                boolean expectedAllowed,
                List<ID> expectedAuthorizedIds
        ) {
            checks.add(() -> {
                FindAllByIdSimulationOutcome<ID, ResponseDTO> out = harness.simulateFindAllById(
                        caller,
                        candidateEntities,
                        idExtractor,
                        rawDtoMapper,
                        requestedIds
                );
                if (out.allowed() != expectedAllowed) {
                    failures.add("[" + scenarioLabel + "] findAllById: expected allowed="
                            + expectedAllowed + ", actual=" + out.allowed()
                            + " (denialReason=" + out.denialReason() + ")");
                } else if (expectedAllowed && expectedAuthorizedIds != null
                        && !Objects.equals(expectedAuthorizedIds, out.authorizedIds())) {
                    failures.add("[" + scenarioLabel + "] findAllById: expected authorizedIds="
                            + expectedAuthorizedIds + ", actual=" + out.authorizedIds());
                }
            });
            return this;
        }

        private void verifyStatsMatrixRow(
                String scenarioLabel,
                String operationTag,
                StatsSimulationOutcome out,
                boolean expectedAllowed,
                FieldUseCategory expectedViolatedCategory,
                String expectedViolatedAttributeId
        ) {
            if (out.allowed() != expectedAllowed) {
                failures.add("[" + scenarioLabel + "] " + operationTag + ": expected allowed="
                        + expectedAllowed + ", actual allowed=" + out.allowed()
                        + " (reason=" + out.denialReason() + ", category=" + out.violatedCategory()
                        + ", attributes=" + out.violatedAttributeIds() + ")");
            } else if (!expectedAllowed) {
                if (expectedViolatedCategory != null && out.violatedCategory() != expectedViolatedCategory) {
                    failures.add("[" + scenarioLabel + "] " + operationTag + ": expected violatedCategory="
                            + expectedViolatedCategory + ", actual=" + out.violatedCategory());
                }
                if (expectedViolatedAttributeId != null
                        && !out.violatedAttributeIds().contains(expectedViolatedAttributeId)) {
                    failures.add("[" + scenarioLabel + "] " + operationTag + ": expected violatedAttributeIds to contain '"
                            + expectedViolatedAttributeId + "', actual=" + out.violatedAttributeIds());
                }
            }
        }

        private <ID> void verifyBulkCohortMatrixRow(
                String scenarioLabel,
                String operationTag,
                BulkMutationSimulationOutcome<ID> out,
                boolean expectedBatchAborted,
                Set<ID> expectedCommittedIds
        ) {
            if (out.batchAborted() != expectedBatchAborted) {
                failures.add("[" + scenarioLabel + "] " + operationTag + ": expected batchAborted="
                        + expectedBatchAborted + ", actual=" + out.batchAborted()
                        + " (abortReason=" + out.abortReason() + ", reasonCodeById=" + out.reasonCodeById() + ")");
            } else if (expectedCommittedIds != null && !Objects.equals(expectedCommittedIds, out.committedIds())) {
                failures.add("[" + scenarioLabel + "] " + operationTag + ": expected committedIds="
                        + expectedCommittedIds + ", actual=" + out.committedIds()
                        + " (reasonCodeById=" + out.reasonCodeById() + ")");
            }
        }

        /**
         * Executes all registered matrix rows, asserts that every row passed, and returns the
         * {@link MatrixVerificationReport}.
         */
        public MatrixVerificationReport verifyAll() {
            failures.clear();
            for (Runnable check : checks) {
                check.run();
            }
            MatrixVerificationReport report = new MatrixVerificationReport(checks.size(), failures);
            return report.assertAllPassed();
        }
    }

    /**
     * Outcome of a keyset/cursor pagination simulation ({@code Fase P10.23-B}).
     */
    public record CursorFilterSimulationOutcome<ID, ResponseDTO>(
            boolean allowed,
            String denialReason,
            FieldUseCategory violatedCategory,
            Set<String> violatedAttributeIds,
            List<ID> authorizedPageIds,
            List<ResponseDTO> maskedItems,
            String nextCursor,
            String prevCursor,
            int pageSize
    ) {
        public CursorFilterSimulationOutcome {
            violatedAttributeIds = violatedAttributeIds == null ? Set.of() : Set.copyOf(violatedAttributeIds);
            authorizedPageIds = authorizedPageIds == null ? List.of() : List.copyOf(authorizedPageIds);
            maskedItems = maskedItems == null ? List.of() : List.copyOf(maskedItems);
        }

        public CursorFilterSimulationOutcome<ID, ResponseDTO> assertAllowed() {
            if (!allowed) {
                throw new IllegalStateException("Expected cursor filter ALLOWED, but was DENIED with reason='"
                        + denialReason + "', category=" + violatedCategory
                        + ", violatedAttributeIds=" + violatedAttributeIds);
            }
            return this;
        }

        public CursorFilterSimulationOutcome<ID, ResponseDTO> assertAllowedIds(List<ID> expectedPageIds) {
            assertAllowed();
            if (!Objects.equals(expectedPageIds, authorizedPageIds)) {
                throw new IllegalStateException("Expected cursor page IDs " + expectedPageIds
                        + ", but got " + authorizedPageIds);
            }
            return this;
        }

        public CursorFilterSimulationOutcome<ID, ResponseDTO> assertNextCursorPresent() {
            assertAllowed();
            if (nextCursor == null || nextCursor.isBlank()) {
                throw new IllegalStateException("Expected non-blank nextCursor, but was " + nextCursor);
            }
            return this;
        }

        public CursorFilterSimulationOutcome<ID, ResponseDTO> assertPrevCursorPresent() {
            assertAllowed();
            if (prevCursor == null || prevCursor.isBlank()) {
                throw new IllegalStateException("Expected non-blank prevCursor, but was " + prevCursor);
            }
            return this;
        }

        public CursorFilterSimulationOutcome<ID, ResponseDTO> assertItem(
                int index,
                java.util.function.Predicate<ResponseDTO> itemPredicate
        ) {
            assertAllowed();
            if (index < 0 || index >= maskedItems.size()) {
                throw new IllegalStateException("Cursor page item index " + index
                        + " out of bounds (size=" + maskedItems.size() + ")");
            }
            if (!itemPredicate.test(maskedItems.get(index))) {
                throw new IllegalStateException("Cursor page item at index " + index
                        + " failed predicate: " + maskedItems.get(index));
            }
            return this;
        }

        public CursorFilterSimulationOutcome<ID, ResponseDTO> assertDenied(
                FieldUseCategory expectedCategory,
                String expectedAttributeId
        ) {
            if (allowed) {
                throw new IllegalStateException("Expected cursor filter DENIED, but was ALLOWED with pageIds="
                        + authorizedPageIds);
            }
            if (expectedCategory != null && violatedCategory != expectedCategory) {
                throw new IllegalStateException("Expected violatedCategory=" + expectedCategory
                        + ", but got " + violatedCategory);
            }
            if (expectedAttributeId != null && !violatedAttributeIds.contains(expectedAttributeId)) {
                throw new IllegalStateException("Expected violatedAttributeIds to contain '" + expectedAttributeId
                        + "', but got " + violatedAttributeIds);
            }
            return this;
        }

        public CursorFilterSimulationOutcome<ID, ResponseDTO> assertDeniedReason(String expectedReason) {
            if (allowed) {
                throw new IllegalStateException("Expected cursor filter DENIED, but was ALLOWED with pageIds="
                        + authorizedPageIds);
            }
            if (expectedReason != null && !expectedReason.equals(denialReason)) {
                throw new IllegalStateException("Expected denialReason='" + expectedReason
                        + "', but got '" + denialReason + "'");
            }
            return this;
        }
    }

    /**
     * Outcome of a {@code locate(filterDto, sort, targetId)} simulation ({@code Fase P10.24-B}).
     */
    public record LocateSimulationOutcome<ID>(
            boolean allowed,
            String denialReason,
            FieldUseCategory violatedCategory,
            Set<String> violatedAttributeIds,
            ID targetId,
            java.util.OptionalLong locatedIndex,
            List<ID> authorizedScopeIds
    ) {
        public LocateSimulationOutcome {
            violatedAttributeIds = violatedAttributeIds == null ? Set.of() : Set.copyOf(violatedAttributeIds);
            locatedIndex = locatedIndex == null ? java.util.OptionalLong.empty() : locatedIndex;
            authorizedScopeIds = authorizedScopeIds == null ? List.of() : List.copyOf(authorizedScopeIds);
        }

        public LocateSimulationOutcome<ID> assertAllowed() {
            if (!allowed) {
                throw new IllegalStateException("Expected locate ALLOWED, but was DENIED with reason='"
                        + denialReason + "', category=" + violatedCategory
                        + ", violatedAttributeIds=" + violatedAttributeIds);
            }
            return this;
        }

        public LocateSimulationOutcome<ID> assertLocatedAt(long expectedIndex) {
            assertAllowed();
            if (locatedIndex.isEmpty() || locatedIndex.getAsLong() != expectedIndex) {
                throw new IllegalStateException("Expected targetId=" + targetId
                        + " located at index " + expectedIndex + ", but was " + locatedIndex
                        + " (authorizedScopeIds=" + authorizedScopeIds + ")");
            }
            return this;
        }

        public LocateSimulationOutcome<ID> assertNotFoundOrOutOfScope() {
            assertAllowed();
            if (locatedIndex.isPresent()) {
                throw new IllegalStateException("Expected targetId=" + targetId
                        + " to be absent/out-of-scope (OptionalLong.empty), but was located at index "
                        + locatedIndex.getAsLong());
            }
            return this;
        }

        public LocateSimulationOutcome<ID> assertDenied(
                FieldUseCategory expectedCategory,
                String expectedAttributeId
        ) {
            if (allowed) {
                throw new IllegalStateException("Expected locate DENIED, but was ALLOWED with locatedIndex="
                        + locatedIndex);
            }
            if (expectedCategory != null && violatedCategory != expectedCategory) {
                throw new IllegalStateException("Expected violatedCategory=" + expectedCategory
                        + ", but got " + violatedCategory);
            }
            if (expectedAttributeId != null && !violatedAttributeIds.contains(expectedAttributeId)) {
                throw new IllegalStateException("Expected violatedAttributeIds to contain '" + expectedAttributeId
                        + "', but got " + violatedAttributeIds);
            }
            return this;
        }

        public LocateSimulationOutcome<ID> assertDeniedReason(String expectedReason) {
            if (allowed) {
                throw new IllegalStateException("Expected locate DENIED, but was ALLOWED with locatedIndex="
                        + locatedIndex);
            }
            if (expectedReason != null && !expectedReason.equals(denialReason)) {
                throw new IllegalStateException("Expected denialReason='" + expectedReason
                        + "', but got '" + denialReason + "'");
            }
            return this;
        }
    }

    /**
     * Outcome of a {@code findAllById(Collection<ID>)} simulation ({@code Fase P10.24-B}).
     */
    public record FindAllByIdSimulationOutcome<ID, ResponseDTO>(
            boolean allowed,
            String denialReason,
            List<ID> requestedIds,
            List<ID> authorizedIds,
            List<ResponseDTO> maskedItems
    ) {
        public FindAllByIdSimulationOutcome {
            requestedIds = requestedIds == null ? List.of() : List.copyOf(requestedIds);
            authorizedIds = authorizedIds == null ? List.of() : List.copyOf(authorizedIds);
            maskedItems = maskedItems == null ? List.of() : List.copyOf(maskedItems);
        }

        public FindAllByIdSimulationOutcome<ID, ResponseDTO> assertAllowed() {
            if (!allowed) {
                throw new IllegalStateException("Expected findAllById ALLOWED, but was DENIED with reason='"
                        + denialReason + "'");
            }
            return this;
        }

        public FindAllByIdSimulationOutcome<ID, ResponseDTO> assertAllowedIds(List<ID> expectedIds) {
            assertAllowed();
            if (!Objects.equals(expectedIds, authorizedIds)) {
                throw new IllegalStateException("Expected findAllById authorized IDs " + expectedIds
                        + ", but got " + authorizedIds);
            }
            return this;
        }

        public FindAllByIdSimulationOutcome<ID, ResponseDTO> assertItem(
                int index,
                java.util.function.Predicate<ResponseDTO> itemPredicate
        ) {
            assertAllowed();
            if (index < 0 || index >= maskedItems.size()) {
                throw new IllegalStateException("findAllById item index " + index
                        + " out of bounds (size=" + maskedItems.size() + ")");
            }
            if (!itemPredicate.test(maskedItems.get(index))) {
                throw new IllegalStateException("findAllById item at index " + index
                        + " failed predicate: " + maskedItems.get(index));
            }
            return this;
        }

        public FindAllByIdSimulationOutcome<ID, ResponseDTO> assertDeniedReason(String expectedReason) {
            if (allowed) {
                throw new IllegalStateException("Expected findAllById DENIED, but was ALLOWED with authorizedIds="
                        + authorizedIds);
            }
            if (expectedReason != null && !expectedReason.equals(denialReason)) {
                throw new IllegalStateException("Expected denialReason='" + expectedReason
                        + "', but got '" + denialReason + "'");
            }
            return this;
        }
    }
}
