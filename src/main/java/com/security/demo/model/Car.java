package com.security.demo.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@NoArgsConstructor
@Data
public class Car {

    private Integer id;
    private String brand;
    private String model;
    private String createdByUsername;

}
