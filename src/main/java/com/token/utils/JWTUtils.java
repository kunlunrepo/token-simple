package com.token.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.util.Calendar;
import java.util.Map;

/**
 * description : JWT工具类
 *
 * @author kunlunrepo
 * date :  2024-05-21 11:41
 */
public class JWTUtils {

    // 秘钥
    private static final String SECRET = "123qwaszx";

    /**
     * 生成Token
     */
    public static String getToken(Map<String, String> map) {
        // token有效期 (默认7天)
        Calendar instance = Calendar.getInstance();
        instance.add(Calendar.DATE, 7);
        // 创建JWT (1.header 2.payload 3.state)
        JWTCreator.Builder builder = JWT.create();
        // payload设置
        map.forEach((k, v) -> builder.withClaim(k, v));
        // 生成token
        return builder
                .withExpiresAt(instance.getTime())
                .sign(Algorithm.HMAC256(SECRET));

    }

    /**
     * 验证Token
     */
    public static DecodedJWT verify(String token) {
        //
        DecodedJWT verify = null;
        try {
            verify = JWT.require(Algorithm.HMAC256(SECRET)).build().verify(token);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return verify;
    }

}
