package com.example.demo.utils;

import com.example.demo.pojo.AccountDTO;
import com.github.glusk.caesar.Bytes;
import com.github.glusk.caesar.Hex;
import com.github.glusk.caesar.PlainText;
import com.github.glusk.caesar.hashing.ImmutableMessageDigest;
import com.github.glusk.srp6_variables.SRP6CustomIntegerVariable;
import com.github.glusk.srp6_variables.SRP6IntegerVariable;
import com.github.glusk.srp6_variables.SRP6PrivateKey;
import com.github.glusk.srp6_variables.SRP6Verifier;

import java.math.BigInteger;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Locale;

public class Calculate {
    public static final Hex wOWHex = new Hex("894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7");
    public static final ByteOrder byteOrder = ByteOrder.LITTLE_ENDIAN;
    public static final BigInteger g_Num = BigInteger.valueOf(7);


    /**
     * 用户SRP-6 for WOW生成类
     * @param username 用户名
     * @param password 密码
     * @param email 用户邮箱（其实没啥用）
     * @return {@link AccountDTO}
     * @throws NoSuchAlgorithmException
     */
    public AccountDTO getRegisterCalculate(String username, String password, String email) throws NoSuchAlgorithmException {
        //根据PHP源码获取的计算方式
        //使用SRP-6库进行设置
        //根据PHP版本，默认将用户名和密码均转大写
        username = username.toUpperCase(Locale.ROOT);
        password = password.toUpperCase(Locale.ROOT);
        //在PHP里取到的数组是大端序，需要以大端序进行读取，从而得到的和小端序读取的结果一致
        SRP6IntegerVariable N = new SRP6CustomIntegerVariable(wOWHex,ByteOrder.BIG_ENDIAN);
        //G，默认是7
        SRP6IntegerVariable g = new SRP6CustomIntegerVariable(g_Num);
        //Hash算法根据说明是SHA1
        ImmutableMessageDigest imd =
                new ImmutableMessageDigest(
                        MessageDigest.getInstance("SHA-1")
                );
        //设置随机盐
        SecureRandom rng = new SecureRandom();
        Bytes salt = Bytes.wrapped(rng.generateSeed(32));
        //转换需要的用户名
        Bytes bUserName = new PlainText(username);
        Bytes bPassword = new PlainText(password);
        //使用小端序列生成PrivateKey-x
        SRP6IntegerVariable x = new SRP6PrivateKey(imd, salt, bUserName, bPassword, byteOrder);
        //使用N,G,X共同生成V
        SRP6IntegerVariable v = new SRP6Verifier(N, g, x);
        //封装成AccountDao以方便传输
        Bytes vend = v.bytes(byteOrder);
        AccountDTO accountDTO = new AccountDTO();
        accountDTO.setEmail(email);
        accountDTO.setSalt(salt);
        accountDTO.setVerifier(vend);
        accountDTO.setUsername(username);
        //vend.asArray()转换字节数组
        return accountDTO;
    }
//
//    public static void main(String[] args) throws NoSuchAlgorithmException {
//        NewCalculate calculate = new NewCalculate();
//        AccountDTO dto = calculate.getRegisterCalculate("pinenut","pinenut","1");
//        System.out.println("Salt:" + dto.getSalt().asHexString());
//        System.out.println("Verifier:" + dto.getVerifier().asHexString());
//    }
}
