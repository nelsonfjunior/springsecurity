package tech.buildrun.springsecurity.controller;

import java.util.List;
import java.util.Set;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import jakarta.transaction.Transactional;
import tech.buildrun.springsecurity.controller.dto.CreateUserDto;
import tech.buildrun.springsecurity.models.Role;
import tech.buildrun.springsecurity.models.User;
import tech.buildrun.springsecurity.repositories.RoleRepository;
import tech.buildrun.springsecurity.repositories.UserRepository;

@RestController
public class UserController {
    
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final BCryptPasswordEncoder passwordEncoder;

    public UserController(UserRepository userRepository, RoleRepository roleRepository, BCryptPasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @PostMapping("/users")
    @Transactional
    public ResponseEntity<Void> newUser(@RequestBody CreateUserDto dto){
        var basicRole = roleRepository.findByName(Role.Values.BASIC.name());
        var userFromDb = userRepository.findByUsername(dto.username());

        if(userFromDb.isPresent()){
            throw new ResponseStatusException(HttpStatus.UNPROCESSABLE_ENTITY);
        }

        var user = new User();
        user.setUsername(dto.username());
        user.setPassword(passwordEncoder.encode(dto.password())); //senha ja criptografada
        user.setRoles(Set.of(basicRole)); //seta o role do usuario

        userRepository.save(user); //salva o usuario

        return ResponseEntity.ok().build();
    }

    @GetMapping("/users")
    @PreAuthorize("hasAuthority('SCOPE_ADMIN')")
    public ResponseEntity<List<User>> listUsers(){
        var users = userRepository.findAll();
        return ResponseEntity.ok(users);
    }
}
