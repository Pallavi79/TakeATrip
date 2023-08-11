package com.example.TakeATrip.service;

import com.example.TakeATrip.dto.AuthenticationResponse;
import com.example.TakeATrip.dto.LoginRequest;
import com.example.TakeATrip.model.Token;
import com.example.TakeATrip.model.TokenType;
import com.example.TakeATrip.model.User;
import com.example.TakeATrip.repository.TokenRepository;
import com.example.TakeATrip.repository.UserRepository;
import com.example.TakeATrip.security.JwtHelper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
public class AuthService {
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private PasswordEncoder passwordEncoder;
    @Autowired
    private AuthenticationManager manager;
    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private TokenRepository tokenRepository;

    @Autowired
    private JwtHelper helper;

    public List<User> getUsers(){
        return userRepository.findAll();
    }

    public User signup(User user){
        Optional<User> ExistingUser  =userRepository.findByEmail(user.getEmail());
        //if(ExistingUser.isPresent()){throw new BadCredentialsException("User already exists");};
        if(ExistingUser.isPresent()){
            throw new RuntimeException("Username already exists");
        }
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        user.setUserId(UUID.randomUUID().toString());
        return userRepository.save(user);
    }

    public ResponseEntity<AuthenticationResponse> login(LoginRequest request){
        this.doAuthenticate(request.getEmail(), request.getPassword());


        UserDetails userDetails = userDetailsService.loadUserByUsername(request.getEmail());
        String token = this.helper.generateToken(userDetails);
        revokeAllUserTokens((User)userDetails);
        saveUserToken((User)userDetails,token);

        AuthenticationResponse response = AuthenticationResponse.builder()
                .jwtToken(token)
                .username(userRepository.findByEmail(userDetails.getUsername()).get().getName())
                .userId(userRepository.findByEmail(userDetails.getUsername()).get().getUserId()).build();
        return new ResponseEntity<>(response, HttpStatus.OK);
    }
    private void revokeAllUserTokens(User user){
        var validUserTokens = tokenRepository.findValidTokenByUser(user);
        if(validUserTokens.isEmpty()) return;
        validUserTokens.forEach(t->{
            t.setExpired(true);
            t.setRevoked(true);
        });
        tokenRepository.saveAll(validUserTokens);
    }
    private void saveUserToken(User user, String token){
        var JwtToken = Token.builder()
                .user(user)
                .token(token)
                .tokenType(TokenType.BEARER)
                .revoked(false)
                .expired(false)
                .build();
        tokenRepository.save(JwtToken);

    }
    private void doAuthenticate(String email, String password) {

        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(email, password);
        try {
            manager.authenticate(authentication);
        } catch (BadCredentialsException e) {
            throw new BadCredentialsException(" Invalid Username or Password  !!");
        }

    }
}

