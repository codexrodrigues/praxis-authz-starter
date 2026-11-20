package org.praxisplatform.authz.controlplane.release;

import java.util.List;
import org.praxisplatform.authz.contracts.policy.AuthorizationPolicyDefinition;
import org.praxisplatform.authz.opa.governance.PolicyCandidateVerificationCorpusCase;

/** Host-owned expectations for both revisions of an approved policy change. */
@FunctionalInterface
public interface AccessPolicyVerificationCorpus {

    Cases forApprovedChange(AuthorizationPolicyDefinition policy, String approvedDefinitionHash);

    record Cases(List<PolicyCandidateVerificationCorpusCase> activation,
                 List<PolicyCandidateVerificationCorpusCase> restoration) {
        public Cases {
            activation = List.copyOf(activation);
            restoration = List.copyOf(restoration);
        }
    }
}
