package com.iacyber.gateway.filter;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Estrae il tenant_id dal JWT e lo propaga come header X-Tenant-ID
 * verso i servizi downstream. Blocca richieste senza tenant.
 */
@Component
public class TenantFilter implements GlobalFilter, Ordered {

    private static final String TENANT_CLAIM = "tenant_id";
    private static final String TENANT_HEADER = "X-Tenant-ID";

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        return exchange.getPrincipal()
            .filter(p -> p instanceof JwtAuthenticationToken)
            .cast(JwtAuthenticationToken.class)
            .flatMap(auth -> {
                Jwt jwt = auth.getToken();
                String tenantId = jwt.getClaimAsString(TENANT_CLAIM);
                if (tenantId == null || tenantId.isBlank()) {
                    exchange.getResponse().setStatusCode(HttpStatus.FORBIDDEN);
                    return exchange.getResponse().setComplete();
                }
                ServerWebExchange mutated = exchange.mutate()
                    .request(r -> r.header(TENANT_HEADER, tenantId))
                    .build();
                return chain.filter(mutated);
            })
            .switchIfEmpty(chain.filter(exchange));
    }

    @Override
    public int getOrder() {
        return -100;
    }
}
