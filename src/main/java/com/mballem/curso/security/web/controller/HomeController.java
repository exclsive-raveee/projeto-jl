package com.mballem.curso.security.web.controller;

import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.GetMapping;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;

@Controller
public class HomeController {

	// abrir pagina home
	@GetMapping({"/", "/home"})
	public String home(HttpServletResponse response) {
		return "home";
	}		


	// abrir pagina login
	@GetMapping({"/login"})
	public String login() {
		
		return "login";
	}	
	
	// login invalido
	@GetMapping({"/login-error"})
	public String loginError(ModelMap model, HttpServletRequest resp) {
		HttpSession session = resp.getSession();
		String lastException = String.valueOf(session.getAttribute("SPRING_SECURITY_LAST_EXCEPTION"));
		if (lastException.contains(SessionAuthenticationException.class.getName())) {
			model.addAttribute("alerta", "erro");
			model.addAttribute("titulo", "Acesso recusado!");
			model.addAttribute("texto", "Você já está logado em outro dispositivo.");
			model.addAttribute("subtexto", "Faça o logout ou espere sua sessão expirar.");
			return "login";
		}
		model.addAttribute("alerta", "erro");
		model.addAttribute("titulo", "Crendenciais inválidas!");
		model.addAttribute("texto", "Login ou senha incorretos, tente novamente.");
		model.addAttribute("subtexto", "Acesso permitido apenas para cadastros já ativados.");
		return "login";
	}	
	
	@GetMapping("/expired")
	public String sessaoExpirada(ModelMap model) {
		model.addAttribute("alerta", "erro");
		model.addAttribute("titulo", "Acesso recusado!");
		model.addAttribute("texto", "Sua sessão expirou.");
		model.addAttribute("subtexto", "Você logou em outro dispositivo");
		return "login";
	}	
	
	// acesso negado
	@GetMapping({"/acesso-negado"})
	public String acessoNegado(ModelMap model, HttpServletResponse resp) {
		model.addAttribute("status", resp.getStatus());
		model.addAttribute("error", "Acesso Negado");
		model.addAttribute("message", "Você não tem permissão para acesso a esta área ou ação.");
		return "error";
	}	
}
