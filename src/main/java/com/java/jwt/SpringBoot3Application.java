package com.java.jwt;

import com.java.jwt.dao.UserDao;
import com.java.jwt.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.crypto.password.PasswordEncoder;

@SpringBootApplication
public class SpringBoot3Application implements CommandLineRunner {

    @Autowired
    private UserDao userDao;

    @Autowired
    private PasswordEncoder encoder;

    public static void main(String[] args) {
        SpringApplication.run(SpringBoot3Application.class, args);
    }

    @Override
    public void run(String... args) throws Exception {
        User user1 = User.builder().id(1L).email("123@gmail.com").name("123").password(encoder.encode("123")).build();
        User user2 = User.builder().id(2L).email("1234@gmail.com").name("1234").password(encoder.encode("1234")).build();
        User user3 = User.builder().id(3L).email("12345@gmail.com").name("12345").password(encoder.encode("12345")).build();
        userDao.save(user1);
        userDao.save(user2);
        userDao.save(user3);
    }
}
