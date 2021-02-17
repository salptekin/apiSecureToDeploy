package com.techproed.apiToDeploy;

import java.util.concurrent.TimeUnit;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled=true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter{
	
	private final PasswordEncoder passwordEncoder;
	@Autowired
	public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
		this.passwordEncoder = passwordEncoder;
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		
		http.
			csrf().disable().
			authorizeRequests().
			antMatchers("/","index","/css/*","/js/*").permitAll().
//			antMatchers("/api/**").hasRole(ApplicationUserRoles.STUDENT.name()).//Role-Based Auth
//			antMatchers("/api/**").hasRole(ApplicationUserRoles.TEACHER.name()).//Role-Based Auth
			

//			antMatchers(HttpMethod.POST, "/management/api/**").hasAuthority(ApplicationUserPermissions.TEACHER_WRITE.getPermission()).
//			antMatchers(HttpMethod.PUT, "/management/api/**").hasAuthority(ApplicationUserPermissions.TEACHER_WRITE.getPermission()).
//			antMatchers(HttpMethod.PATCH, "/management/api/**").hasAuthority(ApplicationUserPermissions.TEACHER_WRITE.getPermission()).
//			antMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(ApplicationUserPermissions.TEACHER_WRITE.getPermission()).
//			antMatchers(HttpMethod.GET, "/management/api/**").hasAnyRole(ApplicationUserRoles.TEACHER.name(), ApplicationUserRoles.STUDENT.name()).
			anyRequest().
			authenticated().
			and().
			//httpBasic();//For Basic Authentication
			formLogin().
			loginPage("/login").permitAll().
			defaultSuccessUrl("/successPage", true).
			and().
			rememberMe().//This is for 2 weeks as default
			tokenValiditySeconds((int)TimeUnit.DAYS.toSeconds(10)).//This makes for 10 seconds
			key("typesomethingverysecure").//Spring boot will use this in HashCode
			and().
			logout().
				logoutUrl("/mylogout").
				logoutRequestMatcher(new AntPathRequestMatcher("/mylogout", "GET")).
				clearAuthentication(true).
				invalidateHttpSession(true).
				deleteCookies("JSESSIONID", "remember-me").
				logoutSuccessUrl("/login");
			
		
	}

	@Override
	@Bean
	protected UserDetailsService userDetailsService() {
		
		//To activate "roles based auth" open "roles", to activate "permission based auth" open "authorities"
		
		UserDetails suleyman = User.
									builder().
									username("salptekin").
									password(passwordEncoder.encode("password12")).
									//roles(ApplicationUserRoles.STUDENT.name()).
									authorities(ApplicationUserRoles.STUDENT.getGrantedAuthorities()).
									build();
		
		UserDetails teacher = User.
									builder().
									username("techproed").
									password(passwordEncoder.encode("password1234")).
									//roles(ApplicationUserRoles.TEACHER.name()).
									authorities(ApplicationUserRoles.TEACHER.getGrantedAuthorities()).
									build();
		
		return new InMemoryUserDetailsManager(suleyman, teacher);

	}

}
