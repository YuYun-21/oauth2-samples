package org.javaboy.oauth2.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.InMemoryTokenStore;
import org.springframework.security.oauth2.provider.token.store.redis.RedisTokenStore;

@Configuration
public class AccessTokenConfig {
    @Autowired
    RedisConnectionFactory redisConnectionFactory;
    @Bean
    TokenStore tokenStore() {
        // 将 access_token 存到 redis 中
        return new RedisTokenStore(redisConnectionFactory);
    }
}
