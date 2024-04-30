package com.example.injerecipe.security;

import com.example.injerecipe.filter.CustomJsonUsernamePasswordAuthenticationFilter;
import com.example.injerecipe.handler.LoginFailureHandler;
import com.example.injerecipe.handler.LoginSuccessHandler;
import com.example.injerecipe.jwt.JwtAuthenticationFilter;
import com.example.injerecipe.jwt.JwtAuthenticationProcessingFilter;
import com.example.injerecipe.oauth2.handler.MyAuthenticationFailureHandler;
import com.example.injerecipe.oauth2.handler.MyAuthenticationSuccessHandler;
import com.example.injerecipe.repository.MemberRepository;
import com.example.injerecipe.service.JwtService;
import com.example.injerecipe.service.LoginService;
import com.example.injerecipe.service.OAuthService;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final LoginService loginService;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final JwtService jwtService;
    private final MemberRepository memberRepository;
    private final ObjectMapper objectMapper;
    private final String[] allowedUrls = {"/v2/api-docs", "/swagger-resources", "/swagger-resources/**", "/configuration/ui", "/configuration/security", "/swagger-ui.html", "/webjars/**",
            "/v3/api-docs/**", "/swagger-ui/**", "/weather/get", "/openai/chat", "/upload", "/oauth/signUp", "/api/*", "/register", "/member/signUp", "/api/search/*", "/refrigerator/*", "/image/upload"};


    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                //.headers(headers -> headers.frameOptions().sameOrigin())	// H2 콘솔 사용을 위한 설정
                .authorizeHttpRequests(requests ->
                        requests.requestMatchers(allowedUrls).permitAll()
                                .requestMatchers("/admin/members", "/admin/admins").hasAuthority("ADMIN")// requestMatchers의 인자로 전달된 url은 모두에게 허용
                                //                .requestMatchers(PathRequest.toH2Console()).permitAll()	// H2 콘솔 접속은 모두에게 허용
                                .anyRequest().authenticated()	// 그 외의 모든 요청은 인증 필요
                )
                .sessionManagement(sessionManagement ->
                        sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )	// 세션을 사용하지 않으므로 STATELESS 설정
                .addFilterBefore(jwtAuthenticationFilter, BasicAuthenticationFilter.class);// 추가
        //.oauth2Login()
        //.defaultSuccessUrl("/oauth/loginInfo", true)// OAuth2 로그인 설정 시작
        //.userInfoEndpoint() // UserInfo 엔드포인트 설정
        //.userService(oAuthService) // 커스텀 OAuth2 사용자 서비스 설정
        //.and();
        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder());
        provider.setUserDetailsService(loginService);
        return new ProviderManager(provider);
    }

    @Bean
    public LoginSuccessHandler loginSuccessHandler() {
        return new LoginSuccessHandler(jwtService, memberRepository);
    }

    @Bean
    public LoginFailureHandler loginFailureHandler() {
        return new LoginFailureHandler();
    }


    @Bean
    public CustomJsonUsernamePasswordAuthenticationFilter customJsonUsernamePasswordAuthenticationFilter() {
        CustomJsonUsernamePasswordAuthenticationFilter customJsonUsernamePasswordLoginFilter
                = new CustomJsonUsernamePasswordAuthenticationFilter(objectMapper);
        customJsonUsernamePasswordLoginFilter.setAuthenticationManager(authenticationManager());
        customJsonUsernamePasswordLoginFilter.setAuthenticationSuccessHandler(loginSuccessHandler());
        customJsonUsernamePasswordLoginFilter.setAuthenticationFailureHandler(loginFailureHandler());
        return customJsonUsernamePasswordLoginFilter;
    }

    @Bean
    public JwtAuthenticationProcessingFilter jwtAuthenticationProcessingFilter() {
        JwtAuthenticationProcessingFilter jwtAuthenticationFilter =
                new JwtAuthenticationProcessingFilter(jwtService, memberRepository);
        return jwtAuthenticationFilter;
    }
}
