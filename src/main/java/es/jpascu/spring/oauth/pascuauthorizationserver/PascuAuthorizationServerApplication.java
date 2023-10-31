package es.jpascu.spring.oauth.pascuauthorizationserver;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import es.jpascu.spring.oauth.pascuauthorizationserver.entity.Role;
import es.jpascu.spring.oauth.pascuauthorizationserver.enums.RoleName;
import es.jpascu.spring.oauth.pascuauthorizationserver.repository.RoleRepository;

@SpringBootApplication
public class PascuAuthorizationServerApplication /*implements CommandLineRunner */{

//	/*
//	 * @Autowired RoleRepository roleRepository;
//	 */
	
	public static void main(String[] args) {
		SpringApplication.run(PascuAuthorizationServerApplication.class, args);
	}

//	@Override
//	public void run(String... args) throws Exception {
//		Role adminRole = Role.builder().role(RoleName.ROLE_ADMIN).build();
//		Role userRole = Role.builder().role(RoleName.ROLE_USER).build();
//		
//		roleRepository.save(adminRole);
//		roleRepository.save(userRole);
//		
//		
//	}
	
	

}
