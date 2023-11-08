package com.example.demo.pojo;

import com.github.glusk.caesar.Bytes;
import lombok.Data;

/**
 * @author Administrator
 * @date 2023/11/08
 */
@Data
public class AccountDTO {
    /**
     * 用户名，用户名据传不能带@否则会崩溃
     */
    String username;
    /**
     * 盐，该项可以使用Bytes.asArray()来获取对应字节流
     */
    Bytes salt;
    /**
     * 鉴权verifier，该项可以使用Bytes.asArray()来获取对应字节流
     */
    Bytes verifier;
    /**
     * 用户邮箱，没什么用。
     */
    String email;
}
