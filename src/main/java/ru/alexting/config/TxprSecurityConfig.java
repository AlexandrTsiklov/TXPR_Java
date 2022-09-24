package ru.alexting.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import ru.alexting.security.TxprAuthProvider;


@EnableWebSecurity
public class TxprSecurityConfig extends WebSecurityConfigurerAdapter {

    private final TxprAuthProvider txprAuthProvider;

    @Autowired
    public TxprSecurityConfig(TxprAuthProvider txprAuthProvider) {
        this.txprAuthProvider = txprAuthProvider;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
            .authorizeRequests()
            .antMatchers("/txpr/authorization", "/txpr/registration", "/error").permitAll()
            .antMatchers("/Images/**", "/CSS/**").permitAll()
            .anyRequest().authenticated()
            .and()
            .formLogin()
            .loginPage("/txpr/authorization")
            .loginProcessingUrl("/txpr/commit-authorization")
            .defaultSuccessUrl("/txpr/home", true)
            .failureUrl("/txpr/authorization?error") // error - get parameter,
            .and()
            .logout().logoutUrl("/txpr/logout").logoutSuccessUrl("/txpr/authorization");
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception{
        auth.authenticationProvider(txprAuthProvider);
    }
}
