package com.example.TakeATrip.repository;

import com.example.TakeATrip.model.Token;
import com.example.TakeATrip.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface TokenRepository extends JpaRepository<Token,Integer> {

    List<Token> findValidTokenByUser(User user);

    Optional<Token> findByToken(String token);
}
