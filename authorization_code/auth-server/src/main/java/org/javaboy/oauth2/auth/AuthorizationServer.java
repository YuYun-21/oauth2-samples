package org.javaboy.oauth2.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.InMemoryAuthorizationCodeServices;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;

import java.lang.ref.SoftReference;

/**
 * @作者 江南一点雨
 * @微信公众号 江南一点雨
 * @网站 http://www.itboyhub.com
 * @国际站 http://www.javaboy.org
 * @微信 a_java_boy
 * @GitHub https://github.com/lenve
 * @Gitee https://gitee.com/lenve
 */
@EnableAuthorizationServer
@Configuration
public class AuthorizationServer extends AuthorizationServerConfigurerAdapter {
    @Autowired
    TokenStore tokenStore;
    @Autowired
    ClientDetailsService clientDetailsService;

    @Bean
    AuthorizationServerTokenServices tokenServices() {
        DefaultTokenServices services = new DefaultTokenServices();
        services.setClientDetailsService(clientDetailsService);
        // Token 是否支持刷新
        services.setSupportRefreshToken(true);
        // Token 的存储位置
        services.setTokenStore(tokenStore);
        // Token 的有效期
        services.setAccessTokenValiditySeconds(60 * 60 * 2);
        // 刷新 Token 的有效期
        services.setRefreshTokenValiditySeconds(60 * 60 * 24 * 3);
        return services;
    }

    /**
     * 配置令牌端点的安全约束
     * 资源服务器收到Token之后，需要去校验Token的合法性，就会访问这个端点
     *
     * @param security 安全功能的Fluent配置程序
     * @throws Exception
     */
    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        // checkTokenAccess 一个Token校验的端点
        // permitAll() 设置为可以直接访问
        security.checkTokenAccess("permitAll()")
                .allowFormAuthenticationForClients();
    }

    /**
     * 配置校验客户端
     *
     * @param clients 客户端详细信息配置器
     * @throws Exception
     */
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory()
                // 客户端的id
                .withClient("javaboy")
                // secret
                .secret(new BCryptPasswordEncoder().encode("123"))
                // 资源id
                .resourceIds("res1")
                // 授权类型
                .authorizedGrantTypes("authorization_code", "refresh_token")
                // 授权范围
                .scopes("all")
                // 重定向uri
                .redirectUris("http://localhost:8082/index.html");
    }

    /**
     * 配置令牌的访问端点和令牌服务
     * 授权码是用来获取令牌的，使用一次就失效，令牌则是用来获取资源的
     *
     * @param endpoints 端点配置器
     * @throws Exception
     */
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        // 配置授权码的存储
        endpoints.authorizationCodeServices(authorizationCodeServices())
                // 配置令牌(access_token)的存储位置
                .tokenServices(tokenServices());
    }
    @Bean
    AuthorizationCodeServices authorizationCodeServices() {
        return new InMemoryAuthorizationCodeServices();
    }
}
