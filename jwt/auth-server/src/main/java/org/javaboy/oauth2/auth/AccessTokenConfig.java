package org.javaboy.oauth2.auth;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

@Configuration
public class AccessTokenConfig {
    private String SIGNING_KEY = "javaboy";

    /**
     * 设置access_token为JWT
     *
     * @return
     */
    @Bean
    TokenStore tokenStore() {
        return new JwtTokenStore(jwtAccessTokenConverter());
    }

    /**
     * 将用户信息和 JWT 进行转换
     * 将用户信息转为 jwt 字符串，或者从 jwt 字符串提取出用户信息
     *
     * @return
     */
    @Bean
    JwtAccessTokenConverter jwtAccessTokenConverter() {
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
        converter.setSigningKey(SIGNING_KEY);
        return converter;
    }
}
