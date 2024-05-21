package com.token.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * description : 用户
 *
 * @author kunlunrepo
 * date :  2024-05-21 14:38
 */
@RestController
@Slf4j
public class UserController {

    @PreAuthorize("hasAnyRole('ROLE_ADMIN')")
    @GetMapping("/query")
    public String query() {
        log.info("查询用户信息成功");
        return "查询用户信息成功";
    }

    @PreAuthorize("hasAnyRole('ROOT')")
    @GetMapping("/update")
    public String update() {
        log.info("修改用户信息成功");
        return "修改用户信息成功";
    }

    @GetMapping("/save")
    public String save()
    {
        log.info("保存用户信息成功");
        return "保存用户信息成功";
    }

}
