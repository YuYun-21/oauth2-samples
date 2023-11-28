package org.javaboy.oauth2.auth;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;

@Configuration
public class AccessTokenConfig {
    /**
     * 设置生成的Token存储方式
     *
     * @return
     */
    @Bean
    TokenStore tokenStore() {
        // 将Token存入内从中
        return new InMemoryTokenStore();
    }
}
