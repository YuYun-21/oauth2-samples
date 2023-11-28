package org.javaboy.authserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * 因为资源服务器和授权服务器在一起 使用 @Order 注解来提升 Spring Security 配置的优先级
 *
 * @author hyh
 */
@Configuration
@Order(1)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    /**
     * 配置加密解密工具
     *
     * @return
     */
    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * 静态资源免校验
     *
     * @param web
     * @throws Exception
     */
    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/login.html", "/css/**", "/js/**", "/images/**");
    }

    /**
     * 接口免校验
     *
     * @param http
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.requestMatchers()
                .antMatchers("/login")
                .antMatchers("/oauth/authorize")
                .and()
                .authorizeRequests().anyRequest().authenticated()
                .and()
                .formLogin()
                // 登录页面
                .loginPage("/login.html")
                // 登录接口
                .loginProcessingUrl("/login")
                .permitAll()
                .and()
                .csrf().disable();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("sang")
                .password(passwordEncoder().encode("123"))
                .roles("admin");
    }
}
