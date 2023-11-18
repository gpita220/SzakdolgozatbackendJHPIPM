package com.jhpipm.backend.payload.request;

import lombok.Data;
import java.util.Set;

@Data
public class SignUpRequest {
    private Integer id;
    private String username;

    private String firstName;

    private String lastName;

    private String school;

    private String major;

    private String email;

    private Set<String> role;

    private String password;

}
