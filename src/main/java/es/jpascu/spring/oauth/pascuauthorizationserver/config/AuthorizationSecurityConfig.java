package es.jpascu.spring.oauth.pascuauthorizationserver.config;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import es.jpascu.spring.oauth.pascuauthorizationserver.repository.service.ClientService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Configuration
@RequiredArgsConstructor
@Slf4j

public class AuthorizationSecurityConfig {

	
	private final PasswordEncoder passwordEncoder;
	private final ClientService clientService;

	@Bean 
	@Order(1)
	public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
			throws Exception {
		OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
		http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
			.oidc(Customizer.withDefaults());	// Enable OpenID Connect 1.0
		http
			// Redirect to the login page when not authenticated from the
			// authorization endpoint
			.exceptionHandling((exceptions) -> exceptions
				.defaultAuthenticationEntryPointFor(
					new LoginUrlAuthenticationEntryPoint("/login"),
					new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
				)
			)
			// Accept access tokens for User Info and/or Client Registration
			.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);

		return http.build();
	}
	

	@Bean 
	@Order(3)
	public SecurityFilterChain bdSecurityFilterChain(HttpSecurity http)
			throws Exception {
		/*http
			.authorizeHttpRequests((authorize) -> authorize.requestMatchers("/h2-console/**")
				.permitAll().anyRequest().permitAll());


        http.csrf(csrf -> csrf.ignoringRequestMatchers("/h2-console/**"));
        http.cors(cors -> cors.disable());
        http.headers(headers -> headers.frameOptions().disable());
		
		return http.build();*/
		http.csrf(csrf -> csrf.disable());

	    http.authorizeHttpRequests(authz -> authz
	            .requestMatchers(HttpMethod.POST, "/users").permitAll()
	            .requestMatchers(new AntPathRequestMatcher("/h2-console/**")).permitAll()
	            .anyRequest().authenticated())
	            .sessionManagement(session -> session
	                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

	    http.headers().frameOptions().disable();
	    return http.build();
	}

	@Bean 
	@Order(2)
	public SecurityFilterChain webSecurityFilterChain(HttpSecurity http)
			throws Exception {
		http
			.authorizeHttpRequests((authorize) -> authorize.requestMatchers("/auth/**", "/client/**")
				.permitAll().anyRequest().authenticated()
			)
			// Form login handles the redirect to the login page from the
			// authorization server filter chain
			.formLogin(Customizer.withDefaults());
		http.csrf().ignoringRequestMatchers("/auth/**","/client/**");
		
		return http.build();
	}
	


	/*
	 * @Bean public UserDetailsService userDetailsService() { UserDetails
	 * userDetails = User .withUsername("user") .password("{noop}user")
	 * .authorities("ROLE_USER") .build();
	 * 
	 * return new InMemoryUserDetailsManager(userDetails); }
	 */

	/*@Bean 
	public RegisteredClientRepository registeredClientRepository() {
		RegisteredClient oidcClient = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("client")
				.clientSecret(passwordEncoder.encode("secret"))
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.redirectUri("https://oauthdebugger.com/debug")
				.scope(OidcScopes.OPENID)
				.clientSettings(clientSettings())
				.build();

		return new InMemoryRegisteredClientRepository(oidcClient);
	}*/
	
	 @Bean
	    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer(){
	        return context -> {
	            Authentication principal = context.getPrincipal();
	            if(context.getTokenType().getValue().equals("id_token")){
	                context.getClaims().claim("token_type", "id token");
	            }
	            if(context.getTokenType().getValue().equals("access_token")){
	                context.getClaims().claim("token_type", "access token");
	                Set<String> roles = principal.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toSet());
	                context.getClaims().claim("roles", roles).claim("username", principal.getName());
	            }
	        };
	    }
	
	/*@Bean
	public ClientSettings clientSettings() {
		return ClientSettings.builder().requireProofKey(true).build() ;
	}*/
	
	@Bean
	public AuthorizationServerSettings authorizationServerSettings() {
		return AuthorizationServerSettings.builder().issuer("http://localhost:9000").build();
	}
	
	
	
	@Bean 
	public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
		return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
	}
	
	@Bean
	public JWKSource<SecurityContext> jwkSource() {
		RSAKey rsaKey = generateRSAKey();
		JWKSet jwkSet = new JWKSet(rsaKey);
		return (jwkSelector, securityConext) -> jwkSelector.select(jwkSet);
		
	}
	
	private  KeyPair generateKeyPair() { 
		KeyPair keyPair;
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			keyPair = keyPairGenerator.generateKeyPair();
		}
		catch (Exception ex) {
			throw new IllegalStateException(ex);
		}
		return keyPair;
	}

	private RSAKey generateRSAKey() {
		KeyPair keyPair = generateKeyPair();
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
		return new RSAKey.Builder(publicKey).privateKey(privateKey).keyID(UUID.randomUUID().toString()).build();
		
	}
}