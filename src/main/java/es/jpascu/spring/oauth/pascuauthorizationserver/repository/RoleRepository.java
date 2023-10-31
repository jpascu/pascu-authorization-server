package es.jpascu.spring.oauth.pascuauthorizationserver.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import es.jpascu.spring.oauth.pascuauthorizationserver.entity.Role;
import es.jpascu.spring.oauth.pascuauthorizationserver.enums.RoleName;

@Repository
public interface RoleRepository extends JpaRepository<Role, Integer> {

    Optional<Role> findByRole(RoleName roleName);
}