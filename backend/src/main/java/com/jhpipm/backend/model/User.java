package com.jhpipm.backend.model;

import com.jhpipm.backend.model.chapters.Test;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.HashSet;
import java.util.Set;

@Data
@Entity
@AllArgsConstructor
@NoArgsConstructor
@Table(	name = "users")
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    private String firstName;
    private String lastName;
    private String school;
    private String major;
    private String email;
    private String username;
    private String password;
    private String passwordDecoded;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(	name = "user_roles",
            joinColumns = @JoinColumn(name = "user_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id"))
    private Set<Role> roles = new HashSet<>();

    @OneToOne(cascade = CascadeType.ALL)
    @JoinColumn(name = "test_id")
    private Test test;
    public User(String firstName,String lastName,String school,String major,String email, String username,String password,String passwordDecoded){
        this.firstName=firstName;
        this.lastName=lastName;
        this.email=email;
        this.school=school;
        this.major=major;
        this.username=username;
        this.password=password;
        this.passwordDecoded=passwordDecoded;
    }
    public User(Integer id,String firstName,String lastName,String school,String major,String email, String username,String password,String passwordDecoded){
        this.id=id;
        this.firstName=firstName;
        this.lastName=lastName;
        this.email=email;
        this.school=school;
        this.major=major;
        this.username=username;
        this.password=password;
        this.passwordDecoded=passwordDecoded;
    }
    public Set<Role> getRoles() {
        return roles;
    }

    public void setRoles(Set<Role> roles) {
        this.roles = roles;
    }
}
