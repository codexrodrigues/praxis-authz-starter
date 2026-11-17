package org.praxisplatform.authz.agent;

import java.util.Objects;
import java.util.Optional;
import org.praxisplatform.authz.host.metadata.AuthzCallerContext;
import org.praxisplatform.authz.host.metadata.ThreadLocalAuthzCallerContextProvider;
import org.praxisplatform.config.ai.agent.spi.AgentThreadContextPropagator;

/**
 * Propaga de forma imutavel o {@link AuthzCallerContext} entre a thread HTTP e as threads worker
 * do assistente operacional, restaurando/limpando o {@code ThreadLocal} em bloco {@code close()}.
 */
public final class AuthzAgentThreadContextPropagator implements AgentThreadContextPropagator {

    private final ThreadLocalAuthzCallerContextProvider callerContextProvider;

    public AuthzAgentThreadContextPropagator(ThreadLocalAuthzCallerContextProvider callerContextProvider) {
        this.callerContextProvider = Objects.requireNonNull(
                callerContextProvider, "callerContextProvider is required");
    }

    @Override
    public Snapshot capture() {
        Optional<AuthzCallerContext> captured = callerContextProvider.currentCallerContextOptional();
        return () -> {
            Optional<AuthzCallerContext> previous = callerContextProvider.currentCallerContextOptional();
            if (captured.isPresent()) {
                callerContextProvider.setContext(captured.get());
            } else {
                callerContextProvider.clearContext();
            }
            return () -> {
                if (previous.isPresent()) {
                    callerContextProvider.setContext(previous.get());
                } else {
                    callerContextProvider.clearContext();
                }
            };
        };
    }
}
