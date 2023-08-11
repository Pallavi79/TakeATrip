package com.example.TakeATrip.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class AppConfig {

    //FORM BASED LOGIN
//    @Bean
//    public UserDetailsService userDetailsService(){
//        UserDetails user = User.builder().username("Michela").password(passwordEncoder().encode("mike")).roles("ADMIN").build();
//        UserDetails user1 = User.builder().username("Ben").password(passwordEncoder().encode("ben")).roles("ADMIN").build();
//        return new InMemoryUserDetailsManager(user);
//    }
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }



}
