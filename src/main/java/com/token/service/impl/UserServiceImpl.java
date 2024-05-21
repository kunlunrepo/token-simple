package com.token.service.impl;

import com.token.domain.UserPojo;
import com.token.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

/**
 * description : 用户服务
 *
 * @author kunlunrepo
 * date :  2024-05-21 11:56
 */
@Service
@Slf4j
public class UserServiceImpl implements UserService {

    /**
     * 根据用户名查询用户信息
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserPojo userPojo = new UserPojo();
        if("zhang".equals(username)){
            userPojo.setUsername("zhang");
            userPojo.setPassword("$2a$10$hbMJRuxJoa6kWcfeT7cNPOGdoEXm5sdfSm5DQtp//2cmCF0MHO8b6");
            log.info("登录：用户={}",userPojo);
            return userPojo;
        }
        return userPojo;
    }



}
