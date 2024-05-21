package com.token.filter;

import com.alibaba.fastjson.JSON;
import com.token.domain.UserPojo;
import com.token.utils.JWTUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.util.*;

/**
 * description : 登录过滤器
 *
 * @author kunlunrepo
 * date :  2024-05-21 12:09
 */
@Slf4j
public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    private AuthenticationManager authenticationManager;

    public LoginFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    /**
     * 认证
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        // 获取用户信息
        UserPojo user = null;
        try {
            user = JSON.parseObject(getJson(request), UserPojo.class);
            log.info("登录过滤器：用户={}", user);
        } catch (IOException e) {
            e.printStackTrace();
        }
        // 创建授权token
        UsernamePasswordAuthenticationToken authResult =
                new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());
        this.setDetails(request, authResult);
        log.info("登录过滤器：token={}", authResult);
        return authenticationManager.authenticate(authResult);
    }

    /**
     * 认证成功
     * 说明：生成token，保存在响应的header头中
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                            FilterChain chain, Authentication authResult) throws IOException, ServletException {
        // 用户名
        Map<String, String> map = new HashMap<>();
        map.put("username", authResult.getName());
        // 授权
        Collection<? extends GrantedAuthority> authorities = authResult.getAuthorities();
        List<String> list = new ArrayList<>();
        for (GrantedAuthority authority : authorities) {
            list.add(authority.getAuthority());
        }
        map.put("roles", JSON.toJSONString(list));
        // 创建token
        String token = JWTUtils.getToken(map);
        response.addHeader("Authorization", "Bearer" + token);
        response.setContentType("application/json;charset=UTF-8");
        response.setStatus(HttpServletResponse.SC_OK);
        // 响应
        PrintWriter out = response.getWriter();
        Map<String, Object> resultMap = new HashMap<>();
        resultMap.put("code", HttpServletResponse.SC_OK);
        resultMap.put("msg", "认证通过");
        out.write(JSON.toJSONString(resultMap));
        out.flush();
        out.close();
    }

    /**
     * 认证失败
     */
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        response.setContentType("application/json;charset=UTF-8");
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        // 响应
        PrintWriter out = response.getWriter();
        Map<String, Object> resultMap = new HashMap<>();
        resultMap.put("code", HttpServletResponse.SC_UNAUTHORIZED);
        resultMap.put("msg", "用户名或密码错误！");
        out.write(JSON.toJSONString(resultMap));
        out.flush();
        out.close();
    }

    /**
     * 从http请求中获取json数据字符串
     */
    public String getJson(HttpServletRequest request) throws IOException {
        BufferedReader streamReader = new BufferedReader( new InputStreamReader(request.getInputStream(), "UTF-8"));
        StringBuilder sb = new StringBuilder();
        String inputStr;
        while ((inputStr = streamReader.readLine()) != null) {
            sb.append(inputStr);
        }
        return sb.toString();
    }
}
