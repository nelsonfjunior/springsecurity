package tech.buildrun.springsecurity.repositories;

import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;

import tech.buildrun.springsecurity.models.User;

public interface UserRepository extends JpaRepository<User, UUID>{   
}
