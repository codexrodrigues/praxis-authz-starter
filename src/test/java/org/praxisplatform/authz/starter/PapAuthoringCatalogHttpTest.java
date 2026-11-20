package org.praxisplatform.authz.starter;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.contains;
import static org.mockito.Mockito.mock;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.praxisplatform.authz.autoconfigure.PraxisAuthzPapCatalogAutoConfiguration;
import org.praxisplatform.authz.autoconfigure.PraxisAuthzProperties;
import org.praxisplatform.authz.catalog.PapAuthoringCatalogController;
import org.praxisplatform.authz.catalog.PapCatalogServiceScopeResolver;
import org.praxisplatform.authz.catalog.SemanticDecisionPointCatalogService;
import org.praxisplatform.authz.controlplane.ConfigMaterializationToOpaReconciler;
import org.praxisplatform.authz.controlplane.GovernedPapAdminOperationsService;
import org.praxisplatform.authz.pilot.WorkforceLeaveAuthzPilotBlueprint;
import org.praxisplatform.authz.seams.RuntimeDecisionPointRegistry;
import org.praxisplatform.config.service.AiPrincipalContextResolver;
import org.praxisplatform.config.service.DomainRuleGovernancePrincipalResolver;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class PapAuthoringCatalogHttpTest {
    private static final String PATH = "/api/praxis/config/domain-rules/authorization/catalog";
    private static final String AUTHORITY = "pap:catalog:read";
    private static final String READER = "RULE_DEFINITION_READER";
    private final PraxisAuthzProperties properties = new PraxisAuthzProperties();
    private final WorkforceLeaveAuthzPilotBlueprint pilot = WorkforceLeaveAuthzPilotBlueprint.createWorkforceLeaveBlueprint();
    private final DomainRuleGovernancePrincipalResolver principals = new DomainRuleGovernancePrincipalResolver(
            new AiPrincipalContextResolver(true, false, "", "", "", "test"), true);
    private final RuntimeDecisionPointRegistry registry = new RuntimeDecisionPointRegistry(pilot.admissionRecords(), pilot.coordinates());
    private final PapCatalogServiceScopeResolver scope = (principal, authentication) ->
            principal.tenantId().equals("allowed") && principal.environment().equals("test")
                    && principal.actorRef().equals(authentication.getName()) ? Set.of(pilot.serviceKey()) : Set.of();
    private final UsernamePasswordAuthenticationToken caller = UsernamePasswordAuthenticationToken.authenticated(
            "reader", null, List.of(new SimpleGrantedAuthority(AUTHORITY)));

    private MockMvc mvc(RuntimeDecisionPointRegistry runtime) {
        properties.getAdminEndpoints().setEnabled(true);
        properties.getDiscovery().setRequiredCatalogAuthority(AUTHORITY);
        var outside = WorkforceLeaveAuthzPilotBlueprint.createHostBlueprint("other-service", "other-resource", "other");
        var catalog = new SemanticDecisionPointCatalogService(properties,
                List.of(pilot.admissionRecords().getFirst(), outside.admissionRecords().getFirst()));
        var admin = new GovernedPapAdminOperationsService(properties, catalog, mock(ConfigMaterializationToOpaReconciler.class), runtime);
        return MockMvcBuilders.standaloneSetup(new PapAuthoringCatalogController(properties, admin, runtime, principals, scope)).build();
    }

    @Test
    void returnsOnlyScopedPointAndItsContractedFactsInEachMode() throws Exception {
        var point = "$.services[0].decisionPoints[0]";
        mvc(registry).perform(get(PATH).principal(caller).with(request -> { request.addUserRole(READER); return request; })
                        .requestAttr("tenantId", "allowed").requestAttr("environment", "test")
                        .param("serviceKey", "other-service").header("X-Tenant-ID", "other"))
                .andExpect(status().isOk()).andExpect(header().string("Cache-Control", "no-store"))
                .andExpect(jsonPath("$.services.length()").value(1))
                .andExpect(jsonPath("$.services[0].serviceKey").value(pilot.serviceKey()))
                .andExpect(jsonPath(point + ".pointKey").value(pilot.decisionPoint().identity().pointKey()))
                .andExpect(jsonPath(point + ".descriptorDigest").value(pilot.decisionPoint().descriptorDigest()))
                .andExpect(jsonPath(point + ".factContractDigest").value(pilot.factContract().factContractDigest()))
                .andExpect(jsonPath(point + ".factsByMode.SEARCH[*].factPath",
                        contains("subject.organizationUnitIds", "subject.principalId")))
                .andExpect(jsonPath(point + ".factsByMode.TARGET[0].factPath").value("resource.cidCodigo"))
                .andExpect(jsonPath(point + ".factsByMode.TARGET[0].valueType").value("STRING"))
                .andExpect(jsonPath(point + ".factsByMode.TARGET[0].length()").value(4));
    }

    @Test
    void requiresAuthenticationCatalogAuthorityReaderRoleAndDelegationOnServer() throws Exception {
        MockMvc http = mvc(registry);
        http.perform(get(PATH).header("X-User-ID", "reader").header("X-Roles", AUTHORITY))
                .andExpect(status().isUnauthorized());
        http.perform(get(PATH).principal(UsernamePasswordAuthenticationToken.authenticated("reader", null, List.of()))
                .header("X-Roles", AUTHORITY)).andExpect(status().isForbidden());
        http.perform(get(PATH).principal(caller).requestAttr("tenantId", "allowed")).andExpect(status().isForbidden());
        http.perform(get(PATH).principal(caller).with(request -> { request.addUserRole(READER); return request; })
                .requestAttr("tenantId", "outside").header("X-Tenant-ID", "allowed")
                .param("allowedServiceScopes", pilot.serviceKey())).andExpect(status().isForbidden());
    }

    @Test
    void mismatchedRuntimeCannotSupplyFacts() throws Exception {
        mvc(new RuntimeDecisionPointRegistry(List.of(), null))
                .perform(get(PATH).principal(caller).with(request -> { request.addUserRole(READER); return request; })
                        .requestAttr("tenantId", "allowed")).andExpect(status().isServiceUnavailable());
    }

    @Test
    void onlyRegistersRouteWhenAdminAndHostScopeArePresent() {
        var context = new WebApplicationContextRunner().withConfiguration(AutoConfigurations.of(PraxisAuthzPapCatalogAutoConfiguration.class))
                .withBean(PraxisAuthzProperties.class, () -> properties)
                .withBean(GovernedPapAdminOperationsService.class, () -> mock(GovernedPapAdminOperationsService.class))
                .withBean(RuntimeDecisionPointRegistry.class, () -> registry)
                .withBean(DomainRuleGovernancePrincipalResolver.class, () -> principals);
        context.withBean(PapCatalogServiceScopeResolver.class, () -> scope).run(app ->
                assertThat(app).doesNotHaveBean(PapAuthoringCatalogController.class));
        var enabled = context.withPropertyValues("praxis.authz.admin-endpoints.enabled=true");
        enabled.run(app -> assertThat(app).doesNotHaveBean(PapAuthoringCatalogController.class));
        enabled.withBean(PapCatalogServiceScopeResolver.class, () -> scope).run(app ->
                assertThat(app).hasSingleBean(PapAuthoringCatalogController.class));
    }
}
