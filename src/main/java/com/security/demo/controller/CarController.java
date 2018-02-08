package com.security.demo.controller;

import com.security.demo.model.Car;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.util.HashSet;
import java.util.Set;

@RestController
@RequestMapping("/cars")
public class CarController {

    private static Set<Car> cars = new HashSet<>();

    @GetMapping("/get")
    public Set<Car> getAll() {
        return cars;
    }

    @PostMapping("/create")
    public Car create(@RequestBody Car car, Principal currentUser) {
        car.setId(cars.size() + 1);
        car.setCreatedByUsername(currentUser.getName());
        cars.add(car);
        return car;
    }

    @PreAuthorize(value = "hasRole('TEL_RAN')")
    @PutMapping("/update/{id}")
    public Car update(@PathVariable("id") Integer carId,
                      @RequestBody Car carToUpdate,
                      Principal currentUser) {
        Car car = cars
                .stream()
                .filter(c-> c.getId().equals(carId))
                .findFirst()
                .orElse(null);
        if (car != null) {
            cars.remove(car);
            car.setBrand(carToUpdate.getBrand());
            car.setModel(carToUpdate.getModel());
            car.setCreatedByUsername(currentUser.getName());
            cars.add(car);
        }

        return car;
    }

}
