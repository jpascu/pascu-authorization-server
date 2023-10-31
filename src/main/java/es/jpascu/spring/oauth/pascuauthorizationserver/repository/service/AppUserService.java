package es.jpascu.spring.oauth.pascuauthorizationserver.repository.service;

import java.util.HashSet;
import java.util.Set;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import es.jpascu.spring.oauth.pascuauthorizationserver.dto.CreateAppUserDto;
import es.jpascu.spring.oauth.pascuauthorizationserver.dto.MessageDto;
import es.jpascu.spring.oauth.pascuauthorizationserver.entity.AppUser;
import es.jpascu.spring.oauth.pascuauthorizationserver.entity.Role;
import es.jpascu.spring.oauth.pascuauthorizationserver.enums.RoleName;
import es.jpascu.spring.oauth.pascuauthorizationserver.repository.AppUserRepository;
import es.jpascu.spring.oauth.pascuauthorizationserver.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@RequiredArgsConstructor
@Slf4j
public class AppUserService {

    private final AppUserRepository appUserRepository;
    private final RoleRepository repository;
    private final PasswordEncoder passwordEncoder;

    public MessageDto createUser(CreateAppUserDto dto){
        AppUser appUser = AppUser.builder()
                .username(dto.username())
                .password(passwordEncoder.encode(dto.password()))
                .build();
        Set<Role> roles = new HashSet<>();
        dto.roles().forEach(r -> {
            Role role = repository.findByRole(RoleName.valueOf(r))
                    .orElseThrow(()-> new RuntimeException("role not found"));
            roles.add(role);
        });
        appUser.setRoles(roles);
        appUserRepository.save(appUser);
        return new MessageDto("user " + appUser.getUsername() + " saved");
    }
}