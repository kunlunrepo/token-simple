package com.token.filter;

import com.alibaba.fastjson.JSON;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.token.utils.JWTUtils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * description : 验证token过滤器
 *
 * @author kunlunrepo
 * date :  2024-05-21 14:18
 */
@Slf4j
public class VerifyFilter extends BasicAuthenticationFilter {

    public VerifyFilter(AuthenticationManager authenticationManager) {
        super(authenticationManager);
    }

    /**
     * 执行验证
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        // 获取token
        String header = request.getHeader("Authorization");
        if (header == null || !header.startsWith("Bearer")) {
            // token格式不正确
            chain.doFilter(request, response);
            response.setContentType("application/json;charset=UTF-8");
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            // 响应 (说明：经测试未正确返回响应)
            PrintWriter out = response.getWriter();
            Map<String, Object> resultMap = new HashMap<>();
            resultMap.put("code", HttpServletResponse.SC_FORBIDDEN);
            resultMap.put("msg", "请登录");
            out.write(new ObjectMapper().writeValueAsString(resultMap));
            log.info("token格式不正确");
            out.flush();
            out.close();
        } else {
            // token格式正确
            String token = header.replace("Bearer", "");
            // 验证token是否正确
            DecodedJWT verify = JWTUtils.verify(token);
            // 获取token中的用户名和角色
            String username = verify.getClaim("username").asString();
            String roleJSON = verify.getClaim("roles").asString();
            List<String> roleArray = JSON.parseArray(roleJSON, String.class);
            List<SimpleGrantedAuthority> list = new ArrayList<>();
            for (String s : roleArray) {
                list.add(new SimpleGrantedAuthority(s));
            }
            // 封装token
            UsernamePasswordAuthenticationToken authResult = new UsernamePasswordAuthenticationToken(username, null, list);
            // 将用户的信息放在session中
            SecurityContextHolder.getContext().setAuthentication(authResult);
            chain.doFilter(request, response);
        }
    }
}
