package org.praxisplatform.authz.controlplane.release;

import org.springframework.boot.context.properties.ConfigurationProperties;

/** Identity of the operator scope and machine credential for one dedicated OPA bundle consumer. */
@ConfigurationProperties("praxis.authz.access-release")
public record AccessPolicyReleaseSettings(String tenantId, String environment, String opaEnvironmentKey, String bundleToken) {

    public AccessPolicyReleaseSettings {
        if (tenantId == null || tenantId.isBlank() || environment == null || environment.isBlank()
                || opaEnvironmentKey == null || opaEnvironmentKey.isBlank()
                || bundleToken == null || bundleToken.length() < 32) {
            throw new IllegalArgumentException("Access releases require a Config scope, OPA environment and a dedicated bundle credential");
        }
    }

    @Override
    public String toString() {
        return "AccessPolicyReleaseSettings[tenantId=" + tenantId + ", environment=" + environment + ", opaEnvironmentKey=" + opaEnvironmentKey + "]";
    }
}
