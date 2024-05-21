package com.token.config;

import com.token.filter.LoginFilter;
import com.token.filter.VerifyFilter;
import com.token.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * description :  SpringSecurity配置类
 *
 * @author kunlunrepo
 * date :  2024-05-21 14:30
 */
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SpringSecurityWebConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserService userService;

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * 指定认证对象的来源
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userService)
                .passwordEncoder(passwordEncoder());
    }

    /**
     * SpringSecurity配置
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf()
                .disable()
                .authorizeRequests()
                .antMatchers("/user/query").hasAnyRole("ADMIN") // 指定角色
                .anyRequest()
                .authenticated()
                .and()
                .addFilter(new LoginFilter(super.authenticationManager())) // 添加登录过滤器
                .addFilter(new VerifyFilter(super.authenticationManager())) // 添加验证过滤器
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS); // 设置session管理策略为无状态
    }
}
