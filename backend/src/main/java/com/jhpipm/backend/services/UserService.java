package com.jhpipm.backend.services;

import com.jhpipm.backend.model.User;
import com.jhpipm.backend.repository.UserRepo;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class UserService {
    private final UserRepo userRepo;

    public UserService(UserRepo userRepo) {
        this.userRepo = userRepo;
    }

    public User addUser(User user) {
        return userRepo.save(user);
    }
    public List<User> findALLUsers(){
        return userRepo.findAll();
    }

    public Optional<User> findUserByUsername(String username){return userRepo.findByUsername(username);}

    public User updateUser(User user) {
        return userRepo.save(user);
    }

    public void deleteUser(Long id) {
        userRepo.deleteById(id);
    }

    public boolean usernameExist(String username){return userRepo.existsByUsername(username);}
}
