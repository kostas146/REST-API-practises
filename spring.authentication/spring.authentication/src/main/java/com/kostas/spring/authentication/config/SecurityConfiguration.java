package com.kostas.spring.authentication.config;

import jakarta.servlet.Filter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity//3.0
@RequiredArgsConstructor
public class SecurityConfiguration {
    private final JwtAuthenticationFilter jwtAuthFilter;
    private final AuthenticationProvider authenticationProvider;

    //configuring hhtp security
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception
    {
        http
                .csrf() // trick a user's web browser into sending unauthorized requests to another website that the user is logged in to.
                .disable() //JWT self-contained
                .authorizeHttpRequests() //whitelist
                .requestMatchers("/api/v1/auth/**")//application patterns
                .permitAll()
                .anyRequest()
                .authenticated() //visi kiti turi buti authenticated
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS) // statless, kad kai ateina requestas , bet kokiu atveju ji patikrintu
                .and()
                .authenticationProvider(authenticationProvider) // authetication providerbean
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class); // JWT FILTER checks everything and then sets seecurity context.
        return http.build();
    }
}
