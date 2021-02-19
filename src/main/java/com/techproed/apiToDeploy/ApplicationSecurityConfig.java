package com.techproed.apiToDeploy;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import com.techproed.apiToDeploy.auth.ApplicationUserService;
import com.techproed.apiToDeploy.jwt.JwtTokenVerifier;
import com.techproed.apiToDeploy.jwt.JwtUsernameAndPasswordAuthenticationFilter;
//import com.techproed.apiToDeploy.jwt.JwtUsernameAndPasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled=true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter{
	
	private final PasswordEncoder passwordEncoder;
	private final ApplicationUserService applicationUserService;
	@Autowired
	public ApplicationSecurityConfig(PasswordEncoder passwordEncoder, ApplicationUserService applicationUserService) {
		this.passwordEncoder = passwordEncoder;
		this.applicationUserService = applicationUserService;
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		
		http.
			csrf().disable().
			sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS).
			and().
			addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager())).
			addFilterAfter(new JwtTokenVerifier(), JwtUsernameAndPasswordAuthenticationFilter.class).
			authorizeRequests().
			antMatchers("/","index","/css/*","/js/*").permitAll().
			antMatchers("/api/**").hasRole(ApplicationUserRoles.STUDENT.name()).//Role-Based Auth
//			antMatchers("/api/**").hasRole(ApplicationUserRoles.TEACHER.name()).//Role-Based Auth
			
//			antMatchers(HttpMethod.POST, "/management/api/**").hasAuthority(ApplicationUserPermissions.TEACHER_WRITE.getPermission()).
//			antMatchers(HttpMethod.PUT, "/management/api/**").hasAuthority(ApplicationUserPermissions.TEACHER_WRITE.getPermission()).
//			antMatchers(HttpMethod.PATCH, "/management/api/**").hasAuthority(ApplicationUserPermissions.TEACHER_WRITE.getPermission()).
//			antMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(ApplicationUserPermissions.TEACHER_WRITE.getPermission()).
//			antMatchers(HttpMethod.GET, "/management/api/**").hasAnyRole(ApplicationUserRoles.TEACHER.name(), ApplicationUserRoles.STUDENT.name()).
			anyRequest().
			authenticated();
//			and().
//			//httpBasic();//For Basic Authentication
//			formLogin().//For form-based authentication
//				loginPage("/login").permitAll().
//				defaultSuccessUrl("/successPage", true).
//			and().
//			logout().
//				logoutUrl("/myLogout").
//				clearAuthentication(true).
//				invalidateHttpSession(true).
//				deleteCookies("JSESSIONID").
//				logoutSuccessUrl("/login");
		
	}

//	@Override
//	@Bean
//	protected UserDetailsService userDetailsService() {
//		
//		//To activate "roles based auth" open "roles", to activate "permission based auth" open "authorities"
//		
//		UserDetails suleyman = User.
//									builder().
//									username("salptekin").
//									password(passwordEncoder.encode("password12")).
//									//roles(ApplicationUserRoles.STUDENT.name()).
//									authorities(ApplicationUserRoles.STUDENT.getGrantedAuthorities()).
//									build();
//		
//		UserDetails teacher = User.
//									builder().
//									username("techproed").
//									password(passwordEncoder.encode("password1234")).
//									//roles(ApplicationUserRoles.TEACHER.name()).
//									authorities(ApplicationUserRoles.TEACHER.getGrantedAuthorities()).
//									build();
//		
//		return new InMemoryUserDetailsManager(suleyman, teacher);
//
//	}
	
	@Bean
	public DaoAuthenticationProvider daoAuthenticationProvider() {
		DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
		provider.setPasswordEncoder(passwordEncoder);
		provider.setUserDetailsService(applicationUserService);
		return provider;
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(daoAuthenticationProvider());
	}

}
