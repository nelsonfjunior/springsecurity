package tech.buildrun.springsecurity.repositories;

import org.springframework.data.jpa.repository.JpaRepository;

import tech.buildrun.springsecurity.models.Role;

public interface RoleRepository extends JpaRepository<Role, Long>{
    Role findByName(String name);
}
