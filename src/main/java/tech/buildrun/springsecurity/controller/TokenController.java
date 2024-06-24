package tech.buildrun.springsecurity.controller;

import java.time.Instant;

import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import tech.buildrun.springsecurity.controller.dto.LoginRequest;
import tech.buildrun.springsecurity.controller.dto.LoginResponse;
import tech.buildrun.springsecurity.repositories.UserRepository;

@RestController
public class TokenController {
    
    private final JwtEncoder jwtEncoder;

    private final UserRepository userRepository;

    private BCryptPasswordEncoder passwordEncoder;
    
    public TokenController(JwtEncoder jwtEncoder, UserRepository userRepository, BCryptPasswordEncoder passwordEncoder) {
        this.jwtEncoder = jwtEncoder;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@RequestBody LoginRequest loginRequest) {
        var user = userRepository.findByUsername(loginRequest.username());

        if(user.isEmpty() || !user.get().isLoginCorrect(loginRequest, passwordEncoder)){
            throw new BadCredentialsException("User or password invalid");
        }

        var now = Instant.now();
        var expiresIn = 300L; //5 minutos - 300 segundos

        var claims = JwtClaimsSet.builder()
            .issuer("my-backend") //quem emitiu o token
            .subject(user.get().getUserId().toString()) //quem é o dono do token
            .expiresAt(now.plusSeconds(expiresIn)) //quando o token expira(agora + 5 minutos)
            .issuedAt(now) //quando o token foi emitido(agora)
            .build(); //cria o objeto de claims

        var jwtValue = jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue(); //gera o token

        return ResponseEntity.ok(new LoginResponse(jwtValue, expiresIn));
    }


}
