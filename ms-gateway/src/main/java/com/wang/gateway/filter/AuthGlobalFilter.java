package com.wang.gateway.filter;

import com.wang.gateway.component.HandleException;
import com.wang.gateway.config.IgnoreUrlsConfig;
import org.apache.commons.lang.StringUtils;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.annotation.Resource;

public class AuthGlobalFilter implements GlobalFilter, Ordered {

    @Resource
    private HandleException handleException;

    @Resource
    private RestTemplate restTemplate;

    @Resource
    private IgnoreUrlsConfig ignoreUrlsConfig;

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        // 判断请求是否在白名单中
        AntPathMatcher pathMatcher = new AntPathMatcher();
        boolean flag = false;
        String path = exchange.getRequest().getURI().getPath();
        for (String pattern : ignoreUrlsConfig.getUrls()) {
            if (pathMatcher.match(pattern, path)) {
                flag = true;
                break;
            }
        }
        // 白名单放行
        if(flag){
            return chain.filter(exchange);
        }
        // 获取token
        String token = exchange.getRequest().getQueryParams().getFirst("access_token");
        // 判断是否为空
        if(StringUtils.isBlank(token)){
            return handleException.writeError(exchange, "请登录.");
        }
        // 发送远程请求，检验是否有效
        String checkTokenUrl = "http://ms-oauth2-server/oauth/check_token?token=".concat(token);
        try {
            // 发送远程请求，验证 token 是否有效
            ResponseEntity<String> entity = restTemplate.getForEntity(checkTokenUrl, String.class);
            // token 无效的业务逻辑处理
            if (entity.getStatusCode() != HttpStatus.OK) {
                return handleException.writeError(exchange, "Token was not recognised, token: ".concat(token));
            }
            if (StringUtils.isBlank(entity.getBody())) {
                return handleException.writeError(exchange, "this token is invalid: ".concat(token));
            }
        } catch (Exception e) {
            return handleException.writeError(exchange,
                    "Token was not recognised, token: ".concat(token));
        }
        // 放行
        return chain.filter(exchange);
    }

    @Override
    public int getOrder() {
        return 0;
    }
}
