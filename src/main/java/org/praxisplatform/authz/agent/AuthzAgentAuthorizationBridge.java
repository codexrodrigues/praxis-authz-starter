package org.praxisplatform.authz.agent;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import org.praxisplatform.authz.contracts.context.FactResolutionStatus;
import org.praxisplatform.authz.contracts.decisionpoint.DecisionPointDescriptor;
import org.praxisplatform.authz.contracts.decisionpoint.EvaluationMode;
import org.praxisplatform.authz.enforcement.masking.DtoFieldSchemaMetadata;
import org.praxisplatform.authz.host.metadata.AuthzCallerContext;
import org.praxisplatform.authz.host.metadata.AuthzResourceOperationAvailabilityProvider;
import org.praxisplatform.authz.host.metadata.MetadataDtoGovernanceIntrospector;
import org.praxisplatform.authz.host.metadata.MetadataDtoGovernanceIntrospector.IntrospectedDtoGovernanceContract;
import org.praxisplatform.authz.host.metadata.ThreadLocalAuthzCallerContextProvider;
import org.praxisplatform.authz.seams.GovernedExportAndAiToolAuthorizationSeam;
import org.praxisplatform.authz.seams.GovernedExportAndAiToolAuthorizationSeam.SanitizedAiToolProjection;
import org.praxisplatform.authz.seams.RuntimeDecisionPointRegistry;
import org.praxisplatform.config.ai.agent.bridge.DefaultMetadataGovernanceAgentAuthorizationBridge;
import org.praxisplatform.config.ai.agent.spi.AgentAuthorizationBridge;
import org.praxisplatform.config.ai.agent.spi.AgentExecutionContext;
import org.praxisplatform.config.ai.agent.spi.DualProjectedPayload;
import org.praxisplatform.uischema.capability.AvailabilityDecision;
import org.praxisplatform.uischema.capability.ResourceOperationAvailabilityContext;

/**
 * Implementacao de {@link AgentAuthorizationBridge} integrada ao {@code praxis-authz-starter}.
 *
 * <p>Combina governanca declarativa em DTOs ({@code @DomainGovernance}, {@code @AiUsagePolicy} e
 * {@code @UISchema}) com verificacoes ao vivo OPA ({@link GovernedExportAndAiToolAuthorizationSeam}
 * e {@link AuthzResourceOperationAvailabilityProvider}) sempre que pontos {@code TARGET}
 * estiverem registrados no {@link RuntimeDecisionPointRegistry}.
 */
public final class AuthzAgentAuthorizationBridge implements AgentAuthorizationBridge {

    private final DefaultMetadataGovernanceAgentAuthorizationBridge metadataGovernance;
    private final GovernedExportAndAiToolAuthorizationSeam aiToolSeam;
    private final RuntimeDecisionPointRegistry decisionPointRegistry;
    private final ThreadLocalAuthzCallerContextProvider callerContextProvider;
    private final MetadataDtoGovernanceIntrospector dtoIntrospector;
    private final AuthzResourceOperationAvailabilityProvider availabilityProvider;
    private final Map<String, String> resourcePathToTargetPointKey;

    public AuthzAgentAuthorizationBridge(
            DefaultMetadataGovernanceAgentAuthorizationBridge metadataGovernance,
            GovernedExportAndAiToolAuthorizationSeam aiToolSeam,
            RuntimeDecisionPointRegistry decisionPointRegistry,
            ThreadLocalAuthzCallerContextProvider callerContextProvider,
            MetadataDtoGovernanceIntrospector dtoIntrospector,
            AuthzResourceOperationAvailabilityProvider availabilityProvider,
            Map<String, String> resourcePathToTargetPointKey) {
        this.metadataGovernance = metadataGovernance != null
                ? metadataGovernance
                : new DefaultMetadataGovernanceAgentAuthorizationBridge();
        this.aiToolSeam = aiToolSeam;
        this.decisionPointRegistry = decisionPointRegistry;
        this.callerContextProvider = callerContextProvider;
        this.dtoIntrospector = dtoIntrospector;
        this.availabilityProvider = availabilityProvider;
        this.resourcePathToTargetPointKey = resourcePathToTargetPointKey == null
                ? Map.of()
                : Map.copyOf(resourcePathToTargetPointKey);
    }

    @Override
    public boolean canReadResource(AgentExecutionContext context, String resourcePath) {
        if (availabilityProvider != null) {
            Optional<DecisionPointDescriptor> targetPoint = resolveTargetDescriptor(resourcePath);
            if (targetPoint.isPresent()) {
                String resourceKey = targetPoint.get().identity().resourceKey();
                if (availabilityProvider.hasResourceBinding(resourceKey)) {
                    AvailabilityDecision decision = availabilityProvider.evaluate(
                            ResourceOperationAvailabilityContext.collection(resourceKey, resourcePath, "read"));
                    if (decision == null || !decision.allowed()) {
                        return false;
                    }
                }
            }
        }
        return metadataGovernance.canReadResource(context, resourcePath);
    }

    @Override
    public boolean canInvokeAction(
            AgentExecutionContext context,
            String resourcePath,
            String actionId,
            Object entityId) {
        if (availabilityProvider != null) {
            Optional<DecisionPointDescriptor> targetPoint = resolveTargetDescriptor(resourcePath);
            if (targetPoint.isPresent()) {
                String resourceKey = targetPoint.get().identity().resourceKey();
                if (availabilityProvider.hasResourceBinding(resourceKey)) {
                    AvailabilityDecision decision = entityId == null
                            ? availabilityProvider.evaluate(
                                    ResourceOperationAvailabilityContext.collection(resourceKey, resourcePath, actionId))
                            : availabilityProvider.evaluate(
                                    ResourceOperationAvailabilityContext.item(resourceKey, resourcePath, actionId, entityId));
                    if (decision == null || !decision.allowed()) {
                        return false;
                    }
                }
            }
        }
        return metadataGovernance.canInvokeAction(context, resourcePath, actionId, entityId);
    }

    @Override
    public DualProjectedPayload projectRecord(
            AgentExecutionContext context,
            String resourcePath,
            Class<?> dtoType,
            Map<String, Object> rawRecord) {
        DualProjectedPayload base = metadataGovernance.projectRecord(context, resourcePath, dtoType, rawRecord);
        if (rawRecord == null || rawRecord.isEmpty()) {
            return base;
        }

        Optional<DecisionPointDescriptor> targetPoint = resolveTargetDescriptor(resourcePath);
        String defaultResourceKey = targetPoint.map(dp -> dp.identity().resourceKey()).orElse(resourcePath);
        IntrospectedDtoGovernanceContract contract = dtoType != null && dtoIntrospector != null
                ? dtoIntrospector.introspect(dtoType, defaultResourceKey)
                : null;

        Map<String, Object> uiRecord = new LinkedHashMap<>(base.uiRecord());
        Map<String, Object> modelSafeRecord = new LinkedHashMap<>(base.modelSafeRecord());
        Set<String> hiddenFields = new LinkedHashSet<>(base.hiddenFields());
        Set<String> maskedForAiFields = new LinkedHashSet<>(base.maskedForAiFields());

        if (contract != null && !contract.aiContextDeniedAttributeIds().isEmpty()) {
            for (DtoFieldSchemaMetadata field : contract.fieldSchemas()) {
                if (contract.aiContextDeniedAttributeIds().contains(field.attributeId())
                        && modelSafeRecord.containsKey(field.wireFieldName())) {
                    modelSafeRecord.remove(field.wireFieldName());
                    maskedForAiFields.add(field.wireFieldName());
                }
            }
        }

        if (targetPoint.isPresent() && aiToolSeam != null) {
            String pointKey = targetPoint.get().identity().pointKey();
            List<DtoFieldSchemaMetadata> fieldSchemas = contract != null
                    ? contract.fieldSchemas()
                    : deriveAdHocSchemas(rawRecord);
            Map<String, Object> trustedFacts = new LinkedHashMap<>();
            Map<String, FactResolutionStatus> trustedStatuses = new LinkedHashMap<>();

            AuthzCallerContext caller = callerContextProvider != null
                    ? callerContextProvider.currentCallerContextOptional().orElse(null)
                    : null;
            if (caller != null) {
                trustedFacts.putAll(caller.subjectAndEnvironmentFacts());
                trustedStatuses.putAll(caller.factStatuses());
            } else if (context != null) {
                if (context.userId() != null) {
                    trustedFacts.put("subject.id", context.userId());
                    trustedStatuses.put("subject.id", FactResolutionStatus.PRESENT);
                }
                if (context.tenantId() != null) {
                    trustedFacts.put("tenant.id", context.tenantId());
                    trustedStatuses.put("tenant.id", FactResolutionStatus.PRESENT);
                }
            }
            if (rawRecord.containsKey("id") && rawRecord.get("id") != null) {
                trustedFacts.putIfAbsent("resource.id", rawRecord.get("id"));
                trustedStatuses.putIfAbsent("resource.id", FactResolutionStatus.PRESENT);
            }

            String tenantId = caller != null ? caller.tenantId()
                    : (context != null && context.tenantId() != null ? context.tenantId() : "default");
            String env = context != null && context.environment() != null ? context.environment() : "prod";

            SanitizedAiToolProjection opaProjected = aiToolSeam.authorizeAndProjectAiToolPayloadByPointKey(
                    pointKey,
                    tenantId,
                    env,
                    rawRecord,
                    fieldSchemas,
                    trustedFacts,
                    trustedStatuses);

            Set<String> allowedWireColumns = new LinkedHashSet<>(opaProjected.allowedWireColumns());
            List<String> modelKeys = new ArrayList<>(modelSafeRecord.keySet());
            for (String key : modelKeys) {
                if (!allowedWireColumns.contains(key) || !opaProjected.detachedPayload().containsKey(key)) {
                    modelSafeRecord.remove(key);
                    maskedForAiFields.add(key);
                } else {
                    Object opaValue = opaProjected.detachedPayload().get(key);
                    Object existingValue = modelSafeRecord.get(key);
                    if (!Objects.equals(opaValue, existingValue) && opaValue != null) {
                        modelSafeRecord.put(key, opaValue);
                        maskedForAiFields.add(key);
                    }
                }
            }
        }

        return new DualProjectedPayload(
                uiRecord,
                modelSafeRecord,
                List.copyOf(hiddenFields),
                List.copyOf(maskedForAiFields));
    }

    private Optional<DecisionPointDescriptor> resolveTargetDescriptor(String resourcePath) {
        if (decisionPointRegistry == null || resourcePath == null || resourcePath.isBlank()) {
            return Optional.empty();
        }
        String mappedKey = resourcePathToTargetPointKey.get(resourcePath);
        if (mappedKey != null) {
            return decisionPointRegistry.findRegisteredPoint(mappedKey)
                    .map(RuntimeDecisionPointRegistry.RegisteredDecisionPointContext::decisionPoint)
                    .filter(dp -> dp.evaluationModes().contains(EvaluationMode.TARGET));
        }
        for (DecisionPointDescriptor descriptor : decisionPointRegistry.getDecisionPointsByKey().values()) {
            if (!descriptor.evaluationModes().contains(EvaluationMode.TARGET)) {
                continue;
            }
            if (resourcePath.equals(descriptor.canonicalPath())
                    || resourcePath.equals(descriptor.identity().resourceKey())) {
                return Optional.of(descriptor);
            }
        }
        return Optional.empty();
    }

    private static List<DtoFieldSchemaMetadata> deriveAdHocSchemas(Map<String, Object> rawRecord) {
        List<DtoFieldSchemaMetadata> list = new ArrayList<>(rawRecord.size());
        for (String key : rawRecord.keySet()) {
            list.add(new DtoFieldSchemaMetadata(
                    key,
                    "attr:" + key,
                    org.praxisplatform.authz.contracts.context.FactValueType.STRING,
                    true));
        }
        return list;
    }
}
