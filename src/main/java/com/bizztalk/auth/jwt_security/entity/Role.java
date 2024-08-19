package com.bizztalk.auth.jwt_security.entity;
//
//import jakarta.persistence.Entity;
//import jakarta.persistence.GeneratedValue;
//import jakarta.persistence.Id;
//import lombok.AllArgsConstructor;
//import lombok.Builder;
//import lombok.Data;
//import lombok.NoArgsConstructor;
//
//@Data
//@AllArgsConstructor
//@NoArgsConstructor
//@Builder
//@Entity
//public class Role {
//
//    @Id
//    @GeneratedValue
//    private Integer id;
//    private String name;
//}
public enum Role {
    USER,
    ADMIN
}
