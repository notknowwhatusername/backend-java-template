package com.object.config;

import com.auth0.jwt.JWT;
import com.object.entity.RestBean;
import com.object.entity.vo.response.AuthorizeVO;
import com.object.filter.JwtAuthorizeFilter;
import com.object.utils.JwtUtils;
import jakarta.annotation.Resource;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import java.io.IOException;

@Configuration
public class SecurityConfiguration {

    @Resource
    JwtUtils jwtUtils;
    @Resource
    JwtAuthorizeFilter filter;
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        //除了api auth后的请求都需要进行登录验证
        return http
                .authorizeHttpRequests(conf -> conf
                        .requestMatchers("/api/auth/**")
                        .permitAll()
                        .anyRequest()
                        .authenticated())
                //配置登录接口
                .formLogin(conf -> conf
                        .loginProcessingUrl("/api/auth/login")
                        //登陆成功回调
                        .successHandler(this::onAuthenticationSuccess)
                        //登陆失败回调
                        .failureHandler(this::onAuthenticationFailure)
                )
                //配置登出接口
                .logout(conf -> conf
                        .logoutUrl("/api/auth/logout")
                        //登出成功回调
                        .logoutSuccessHandler(this::onLogoutSuccess)
                )
                //关闭csrf
                .csrf(AbstractHttpConfigurer::disable)
                //不使用Session进行状态管理
                .sessionManagement(conf -> conf.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                //配置过滤器
                .addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class)

                .exceptionHandling(conf -> conf
                        //认证失败回调
                        .authenticationEntryPoint(this::onAuthenticationFailure)
                        //没有权限回调
                        .accessDeniedHandler(new AccessDeniedHandler() {
                            @Override
                            public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {

                            }
                        }))
                .build();
    }

    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication)
            throws IOException, ServletException {
        response.setContentType("application/json");
        response.setCharacterEncoding("utf-8");
        User user = (User) authentication.getPrincipal();
        String token = jwtUtils.createJwt(user, 1, "admin");
        AuthorizeVO authorizeVO = new AuthorizeVO();
        authorizeVO.setExpireTime(jwtUtils.expireTime());
        authorizeVO.setUsername("admin");
        authorizeVO.setRole("");
        authorizeVO.setToken(token);
        response.getWriter().write(RestBean.success(authorizeVO).asJsonString());
    }

    public void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response,
                                        AuthenticationException exception)
            throws IOException, ServletException {
        response.setContentType("application/json");
        response.setCharacterEncoding("utf-8");
        response.getWriter().write(RestBean.failure(40001, exception.getMessage()).asJsonString());
    }

    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        response.setContentType("application/json");
        response.setCharacterEncoding("utf-8");

        if(jwtUtils.invalidateJwt(request.getHeader("Authorize"))){
            response.getWriter().write(RestBean.success("退出成功").asJsonString());
        }else{
            response.getWriter().write(RestBean.success("退出失败").asJsonString());
        }
    }
}
