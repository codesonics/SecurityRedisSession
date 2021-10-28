package com.example.domain;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Table;

@Entity
@Table(name = "tbl_users")
@Getter
@Setter
@EqualsAndHashCode(of = "username")
public class UserEntity {

    @Id
    @GeneratedValue
    private Integer idx;

    private String username;

    private String password;
}
