package com.security.demo.configuration;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
@EnableWebSecurity
public class WebSecurityConfiguration
        extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("admin")
                .password("123456")
                .roles("ADMIN", "TEL_RAN")
                    .and()
                .withUser("reader")
                .password("qwerty123456")
                .roles("TEL_RAN")
                    .and()
                .withUser("guest")
                .password("qazwsx")
                .roles("ADMIN", "TEL_RAN");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .headers().frameOptions().disable()
                .and()
                .httpBasic()
                .and()
                .authorizeRequests()
                .antMatchers("/cars/get**").hasRole("TEL_RAN")
                .antMatchers("/cars/create**").hasRole("ADMIN")
        .antMatchers("/cars/update**").hasRole("ADMIN");
    }
}
