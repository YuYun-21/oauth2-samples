package org.javaboy.oauth2.auth;

import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.stereotype.Component;

import java.util.Map;

@Component
public class CustomAdditionalInformation implements TokenEnhancer {

    /**
     * 设置 JWT 生成的用户信息
     * @param accessToken 生成的JWT 当前访问令牌及其过期和刷新令牌
     * @param authentication 当前身份验证 包括客户端和用户详细信息
     * @return
     */
    @Override
    public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
        Map<String, Object> info = accessToken.getAdditionalInformation();
        info.put("author", "江南一点雨");
        ((DefaultOAuth2AccessToken) accessToken).setAdditionalInformation(info);
        return accessToken;
    }
}
