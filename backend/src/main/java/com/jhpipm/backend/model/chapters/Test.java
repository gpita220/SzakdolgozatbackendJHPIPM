package com.jhpipm.backend.model.chapters;

import com.jhpipm.backend.model.User;
import jakarta.persistence.*;
import lombok.*;

@Data
@Entity
@AllArgsConstructor
@NoArgsConstructor
@Table(	name = "test")
public class Test {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    private Integer chapter1;
    private Integer chapter2;
    private Integer chapter3;
    private Integer chapter4;
    private Integer chapter5;
    private Integer chapter6;
    private Integer chapter7;
    private Integer chapter8;
    private Integer chapter9;
    private Integer chapter10;
    private Integer chapter11;
    private Integer chapter12;

    @OneToOne(mappedBy = "test")
    private User user;

}
