package com.kostas.spring.authentication.config;

import com.kostas.spring.authentication.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration //ims visus beansus ir bandys implementint/injectint
@RequiredArgsConstructor // injectint ka nors
public class ApplicationConfig {

    private final UserRepository repository;
    @Bean
    public UserDetailsService userDetailsService(){
        return username -> repository.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("Useris nerastas"));
    }

    @Bean
    public PasswordEncoder passwordEncoder() //password encoder bean
    {
        return new BCryptPasswordEncoder();
    }
    @Bean
    public AuthenticationProvider authenticationProvider() {           // data access object, fetch,encode password etc.
        DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailsService());

        // provide password on encoder
        authenticationProvider.setPasswordEncoder(passwordEncoder());
        return authenticationProvider;

    }
@Bean
public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception
{
    return config.getAuthenticationManager();
}

}
