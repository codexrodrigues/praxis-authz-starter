package org.praxisplatform.authz.host.metadata;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.List;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.praxisplatform.authz.contracts.policy.MaskContributionSpec;
import org.praxisplatform.authz.contracts.policy.PolicyFieldSelector;
import org.praxisplatform.authz.enforcement.fielduse.FieldUseQueryGuard;
import org.praxisplatform.authz.enforcement.masking.DetachedDtoMaskingProcessor;
import org.praxisplatform.authz.enforcement.obligation.ObligationBarrierCoordinator;
import org.praxisplatform.authz.enforcement.writeintent.DtoWriteIntentExtractor;
import org.praxisplatform.authz.enforcement.writeintent.FieldWriteAuthorizer;
import org.praxisplatform.authz.opa.client.DeterministicLocalOpaTransport;
import org.praxisplatform.authz.opa.client.OpaAuthorizationProviderAdapter;
import org.praxisplatform.authz.seams.MetadataResourceAuthorizationSeam;
import org.praxisplatform.uischema.filter.dto.GenericFilterDTO;
import org.praxisplatform.uischema.governance.AccessMode;
import org.praxisplatform.uischema.service.base.BaseResourceQueryService;
import org.praxisplatform.uischema.service.base.ResourceFilterAccessScope;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionSynchronizationUtils;

class AuthzResourceGovernanceInterceptorFrameTest {
    interface Vacancies extends BaseResourceQueryService<Row, Long, GenericFilterDTO> {}
    interface Pensions extends BaseResourceQueryService<Row, Long, GenericFilterDTO> {}

    public static class Row {
        public Long tenantId = 10L;
        public Long organizationId = 1L;
        public String reference = "original";
    }

    private final Vacancies vacancies = mock(Vacancies.class);
    private final Pensions pensions = mock(Pensions.class);
    private final Row row = new Row();
    private AuthzGovernedResourceServiceSupport support;
    private AuthzResourceGovernanceInterceptor interceptor;
    private int searches;

    @BeforeEach
    void setUp() {
        when(vacancies.getResourceKey()).thenReturn("vacancies");
        when(pensions.getResourceKey()).thenReturn("pensions");
        var builder = AuthzHostPolicyBootstrapBuilder.forService("personnel");
        for (String resource : List.of("vacancies", "pensions")) {
            var spec = AuthzResourceGovernanceSpec.<Row>builder(resource)
                    .serviceKey("personnel")
                    .tenantField("tenantId")
                    .introspectFromResource(Row.class, Row.class, null, Row.class, Row.class, null, null)
                    .build();
            var mask = new MaskContributionSpec(PolicyFieldSelector.exact(Set.of(resource + ".reference")),
                    "REDACT_CONSTANT", Map.of("replacement", resource));
            builder.addResourceSpec(spec, Row.class, Row.class, Row.class)
                    .addOrganizationalScopePolicy(spec, resource + "-scope", "resource.organizationId",
                            "subject.organizationUnitIds", List.of(mask), List.of());
        }
        var bundle = builder.build();
        var transport = bundle.localOpaTransport();
        var provider = new OpaAuthorizationProviderAdapter((instance, path, body) -> {
            if (DeterministicLocalOpaTransport.PATH_SEARCH_PREFLIGHT.equals(path)) {
                searches++;
            }
            return transport.postDataQuery(instance, path, body);
        });
        var masking = new DetachedDtoMaskingProcessor();
        var seam = new MetadataResourceAuthorizationSeam(provider, new FieldUseQueryGuard(),
                new DtoWriteIntentExtractor(), new FieldWriteAuthorizer(), masking, new ObligationBarrierCoordinator());
        support = new AuthzGovernedResourceServiceSupport(seam, masking);
        var caller = AuthzCallerContext.of("10", Map.of(
                "subject.principalId", "analyst", "subject.organizationUnitIds", List.of(1L)));
        interceptor = new AuthzResourceGovernanceInterceptor(support, () -> caller, null, bundle.resourceSpecs(), null, true);
    }

    @Test
    void nestedEntityAndBatchChecksUseTheirOwnProjectionAndRestoreCallerOnSuccessAndDenial() {
        interceptor.customizeFilterAccessScope(vacancies, ResourceFilterAccessScope.unrestricted());
        var outer = support.currentQueryScopeContext();
        assertEquals("vacancies", outer.dataScopePlan().resourceKey());

        interceptor.verifyEntityAccess(pensions, row, AccessMode.WRITE);
        assertSame(outer, support.currentQueryScopeContext());
        interceptor.verifyEntitiesAccess(pensions, List.of(row, row), AccessMode.WRITE);
        assertEquals(3, searches);
        assertSame(outer, support.currentQueryScopeContext());

        row.organizationId = 2L;
        assertThrows(SecurityException.class, () -> interceptor.verifyEntityAccess(pensions, row, AccessMode.WRITE));
        assertSame(outer, support.currentQueryScopeContext());
        row.organizationId = 1L;
        interceptor.verifyEntityAccess(vacancies, row, AccessMode.WRITE);
        assertEquals(4, searches);

        assertEquals("pensions", interceptor.decorateResponse(pensions, row, row, "read").reference);
        assertEquals("vacancies", interceptor.decorateResponse(vacancies, row, row, "read").reference);
        assertSame(outer, support.currentQueryScopeContext());
        assertEquals(5, searches);
    }

    @Test
    void transactionReusesScopeForBothLockChecksAndNonTransactionalCallsLeaveNoFrame() {
        TransactionSynchronizationManager.initSynchronization();
        try {
            interceptor.verifyEntityAccess(pensions, row, AccessMode.WRITE);
            interceptor.verifyEntityAccess(pensions, row, AccessMode.WRITE);
            assertEquals(1, searches);
        } finally {
            var callbacks = TransactionSynchronizationManager.getSynchronizations();
            TransactionSynchronizationManager.clearSynchronization();
            TransactionSynchronizationUtils.invokeAfterCompletion(callbacks, TransactionSynchronization.STATUS_COMMITTED);
        }
        assertFalse(support.hasActiveQueryContext());
        interceptor.verifyEntityAccess(pensions, row, AccessMode.WRITE);
        assertEquals(2, searches);
        assertFalse(support.hasActiveQueryContext());
    }

    @Test
    void nestedDecorationKeepsForeignMutationForItsOwnMaskedResponse() {
        interceptor.beforeMutation(vacancies, null, row, row);
        interceptor.afterMutationBeforeCommit(vacancies, null, row);
        assertEquals("pensions", interceptor.decorateResponse(pensions, row, row, "read").reference);
        assertTrue(support.hasActiveMutationContext());
        assertEquals("vacancies", interceptor.decorateResponse(vacancies, row, row, "update").reference);
        assertFalse(support.hasActiveMutationContext());
        assertEquals(1, searches);
        assertEquals("original", row.reference);
    }
}
