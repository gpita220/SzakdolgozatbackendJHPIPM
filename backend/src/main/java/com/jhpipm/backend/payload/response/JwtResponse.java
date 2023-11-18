package com.jhpipm.backend.payload.response;

import com.jhpipm.backend.model.User;
import lombok.Data;
import lombok.Getter;

import java.util.List;
import java.util.Optional;

@Data
public class JwtResponse {
    private String token;
    private String type = "Bearer";
    @Getter
    private Long id;
    private String username;
    private List<String> roles;
    private Optional<User> user;
    private String pass;
    public JwtResponse(String accessToken, Long id, String username, List<String> roles, Optional<User> newuser, String pass) {
        this.token = accessToken;
        this.id = id;
        this.username = username;
        this.roles = roles;
        this.user=newuser;
        this.pass=pass;
    }
    public String getAccessToken() {
        return token;
    }

    public void setAccessToken(String accessToken) {
        this.token = accessToken;
    }

    public String getTokenType() {
        return type;
    }

    public void setTokenType(String tokenType) {
        this.type = tokenType;
    }

}
