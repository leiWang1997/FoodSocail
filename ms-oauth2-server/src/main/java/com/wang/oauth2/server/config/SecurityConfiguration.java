package com.wang.oauth2.server.config;

import cn.hutool.crypto.digest.DigestUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.provider.token.store.redis.RedisTokenStore;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    //redis连接工厂
    @Autowired
    private RedisConnectionFactory redisConnectionFactory;

    //初始化redistokenstore 用于将token存储至redis
    @Bean
    public RedisTokenStore redisTokenStore(){
        RedisTokenStore redisTokenStore = new RedisTokenStore(redisConnectionFactory);
        redisTokenStore.setPrefix("TOKEN:");
        return redisTokenStore;
    }
    //初始化密码编码器
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new PasswordEncoder() {
            /**
             * 加密
             * @param rawPassword 原始密码
             * @return
             */
            @Override
            public String encode(CharSequence rawPassword) {
                return DigestUtil.md5Hex(rawPassword.toString());
            }

            /**
             * 解密
             * @param rawPassword 原始密码
             * @param encodedPassword 加密密码
             * @return
             */
            @Override
            public boolean matches(CharSequence rawPassword, String encodedPassword) {
                return DigestUtil.md5Hex(rawPassword.toString()).equals(encodedPassword);
            }
        };
    }

    //初始化认证管理对象
    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    //放行和认证规则
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .authorizeRequests()
                .antMatchers("/Oauth/**", "/actuator/**")
                .permitAll()
                .and()
                .authorizeRequests()
                .anyRequest().authenticated();
    }
}
