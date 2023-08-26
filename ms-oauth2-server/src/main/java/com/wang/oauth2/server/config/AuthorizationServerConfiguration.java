package com.wang.oauth2.server.config;

import com.wang.commons.model.domain.SignInIdentity;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;

import javax.annotation.Resource;
import java.util.LinkedHashMap;


@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {

    @Resource
    private AuthenticationManager authenticationManager;
    @Autowired
    private ClientOAuth2DataConfiguration clientOAuth2DataConfiguration;
    @Resource
    private PasswordEncoder passwordEncoder;
    @Resource
    private UserDetailsService userService;
    @Resource
    private TokenStore redisTokenStore;

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        // 允许访问 Token 的公钥，默认 /oauth/token_key 是受保护的
        security.tokenKeyAccess("permitAll()")
                // 允许检查 Token 状态，默认 /oauth/check_token 是受保护的
                .checkTokenAccess("permitAll()");
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        // 客户端标识 id
        clients.inMemory().withClient(clientOAuth2DataConfiguration.getClientId())
                // 客户端安全码
                .secret(passwordEncoder.encode(clientOAuth2DataConfiguration.getSecret()))
                // 授权类型
                .authorizedGrantTypes(clientOAuth2DataConfiguration.getGrantTypes())
                // Token 有效时间
                .accessTokenValiditySeconds(clientOAuth2DataConfiguration.getTokenValidityTime())
                // 刷新 Token 的有效时间
                .refreshTokenValiditySeconds(clientOAuth2DataConfiguration.getRefreshTokenValidityTime())
                // 客户端访问范围
                .scopes(clientOAuth2DataConfiguration.getScopes());
    }

    /**
     * 配置授权以及令牌服务
     * @param endpoints
     * @throws Exception
     */
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        // 认证器
        endpoints.authenticationManager(authenticationManager)
                // 具体登录的方法
                .userDetailsService(userService)
                // token 存储的方式：内存、redis、数据库、jwt 等
                .tokenStore(redisTokenStore)
                // 令牌增强对象，增强返回的结果
                .tokenEnhancer((accessToken, authentication) -> {
                    // 获取登录用户的信息，然后设置
                    SignInIdentity signInIdentity = (SignInIdentity) authentication.getPrincipal();
                    LinkedHashMap<String, Object> map = new LinkedHashMap<>();
                    map.put("nickname", signInIdentity.getNickname());
                    map.put("avatarUrl", signInIdentity.getAvatarUrl());
                    DefaultOAuth2AccessToken token = (DefaultOAuth2AccessToken) accessToken;
                    token.setAdditionalInformation(map);
                    return token;
                });
    }
}
