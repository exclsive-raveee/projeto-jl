package com.mballem.curso.security.config;

import org.springframework.boot.web.servlet.ServletListenerRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.session.HttpSessionEventPublisher;

import com.mballem.curso.security.domain.PerfilTipo;
import com.mballem.curso.security.service.UsuarioService;

@Configuration
@EnableMethodSecurity
@EnableWebSecurity
public class SecurityConfig {
	
	private static final String ADMIN = PerfilTipo.ADMIN.getDesc();
    private static final String MEDICO = PerfilTipo.MEDICO.getDesc();
    private static final String PACIENTE = PerfilTipo.PACIENTE.getDesc();
	 
	@Bean
	public SecurityFilterChain configure(HttpSecurity http) throws Exception {
		
		http.authorizeHttpRequests((authorize) -> authorize				
//			// acessos públicos liberados
//			.requestMatchers("/webjars/**", "/css/**", "/image/**", "/js/**").permitAll()
//			.requestMatchers("/", "/home", "/expired").permitAll()
//			.requestMatchers("/u/novo/cadastro", "/u/cadastro/realizado", "/u/cadastro/paciente/salvar").permitAll()
//			.requestMatchers("/u/confirmacao/cadastro").permitAll()
//			.requestMatchers("/u/p/**").permitAll()
//
//			// acessos privados admin
//			.requestMatchers("/u/editar/senha", "/u/confirmar/senha").permitAll()
//			.requestMatchers("/u/**").permitAll()
//
//			// acessos privados medicos
//			.requestMatchers("/medicos/especialidade/titulo/*").permitAll()
//			.requestMatchers("/medicos/dados", "/medicos/salvar", "/medicos/editar").permitAll()
//			.requestMatchers("/medicos/**").permitAll()
//
//			// acessos privados pacientes
//			.requestMatchers("/pacientes/**").permitAll()
//
//			// acessos privados especialidades
//			.requestMatchers("/especialidades/datatables/server/medico/*").permitAll()
//			.requestMatchers("/especialidades/titulo").permitAll()
//			.requestMatchers("/especialidades/**").permitAll()
//
			.anyRequest().permitAll()
		);
		return http.build();
	}
	
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	@Bean
	public AuthenticationManager authenticationManager(HttpSecurity http, 
													   PasswordEncoder passwordEncoder, 
													   UsuarioService userDetailsService) throws Exception {
		
		return http.getSharedObject(AuthenticationManagerBuilder.class)
				.userDetailsService(userDetailsService)
				.passwordEncoder(passwordEncoder)
				.and()
				.build();
	}
	
	@Bean
	public SessionAuthenticationStrategy sessionAuthStrategy() {
		return new RegisterSessionAuthenticationStrategy(sessionRegistry());
	}
	
	@Bean
	public SessionRegistry sessionRegistry() {
		return new SessionRegistryImpl();
	}

	@Bean
	public ServletListenerRegistrationBean<?> servletListenerRegistrationBean() {
		return new ServletListenerRegistrationBean<>( new HttpSessionEventPublisher() );
	}	
}
