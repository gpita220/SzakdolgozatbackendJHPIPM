package com.jhpipm.backend.controller;

import com.jhpipm.backend.model.ERole;
import com.jhpipm.backend.model.Role;
import com.jhpipm.backend.model.User;
import com.jhpipm.backend.payload.request.SignUpRequest;
import com.jhpipm.backend.payload.response.MessageResponse;
import com.jhpipm.backend.repository.RoleRepo;
import com.jhpipm.backend.services.UserService;
import io.jsonwebtoken.io.Decoders;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.HttpStatus;

import java.util.*;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/user")
public class UserController {
    @Autowired
    UserService userService;
    @Autowired
    PasswordEncoder encoder;
    @Autowired
    RoleRepo roleRepository;


    @GetMapping("/all")
    public ResponseEntity<List<User>> getAllUsers(){
        List<User> users=userService.findALLUsers();
        return new ResponseEntity<>(users,HttpStatus.OK);
    }
    @GetMapping("/findByUsername")
    public ResponseEntity<Optional<User>> findUserByUsername(@RequestParam String username){
        Optional<User> newuser=userService.findUserByUsername(username);
        return new ResponseEntity<>(newuser,HttpStatus.OK);
    }

    @PutMapping("/update")
    public ResponseEntity<?> updateUser( @RequestBody SignUpRequest signUpRequest){

        User newuser=new User(
                signUpRequest.getId(),
                signUpRequest.getFirstName(),
                signUpRequest.getLastName(),
                signUpRequest.getSchool(),
                signUpRequest.getMajor(),
                signUpRequest.getEmail(),
                signUpRequest.getUsername(),
                encoder.encode(signUpRequest.getPassword()),
                signUpRequest.getPassword());


        Set<String> strRoles = signUpRequest.getRole();
        Set<Role> roles = new HashSet<>();

        if (strRoles == null) {
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(userRole);
        } else {
            strRoles.forEach(role -> {
                switch (role) {
                    case "admin":
                        Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(adminRole);
                        break;
                    default:
                        Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(userRole);
                }
            });
        }

        newuser.setRoles(roles);
        userService.updateUser(newuser);
        return new ResponseEntity<>(newuser, HttpStatus.OK);
    }


    @PostMapping("/add")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> addUser(@Valid @RequestBody SignUpRequest signUpRequest){
        if (userService.usernameExist(signUpRequest.getUsername())) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse("Error: Username is already taken!"));
        }
        User newuser=new User(
                signUpRequest.getFirstName(),
                signUpRequest.getLastName(),
                signUpRequest.getSchool(),
                signUpRequest.getMajor(),
                signUpRequest.getEmail(),
                signUpRequest.getUsername(),
                encoder.encode(signUpRequest.getPassword()),
                signUpRequest.getPassword());


        Set<String> strRoles = signUpRequest.getRole();
        Set<Role> roles = new HashSet<>();

        if (strRoles == null) {
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
            roles.add(userRole);
        } else {
            strRoles.forEach(role -> {
                switch (role) {
                    case "admin":
                        Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(adminRole);

                        break;
                    default:
                        Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                                .orElseThrow(() -> new RuntimeException("Error: Role is not found."));
                        roles.add(userRole);
                }
            });
        }

        newuser.setRoles(roles);
        userService.addUser(newuser);
        return new ResponseEntity<>(newuser,HttpStatus.CREATED);
    }

    @DeleteMapping("/delete")
    public ResponseEntity<?> deleteUser(@RequestParam Long id){
        userService.deleteUser(id);
        return new ResponseEntity<>("User successfully deleted!",HttpStatus.OK);
    }
}
