package tech.buildrun.springsecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    
    @Bean
    private SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated()) //todas as autenticaçoes devem ser autorizadas
            .csrf(csrf -> csrf.disable()) //desabilita o csrf
            .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults())) //configura o servidor de recursos para usar JWT
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)); //configura a politica de criação de sessão para STATELESS (nao guardar nadaem sessao)
        return http.build();
    }

}
