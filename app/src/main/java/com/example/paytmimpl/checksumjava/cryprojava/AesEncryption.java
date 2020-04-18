package com.example.paytmimpl.checksumjava.cryprojava;


import android.os.Build;

import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AesEncryption implements Encryption {
    private final byte[] ivParamBytes = new byte[]{64, 64, 64, 64, 38, 38, 38, 38, 35, 35, 35, 35, 36, 36, 36, 36};

    public AesEncryption() {
    }

    public String encrypt(String toEncrypt, String key) throws Exception {
        String encryptedValue = "";
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING", "SunJCE");
        cipher.init(1, new SecretKeySpec(key.getBytes(), "AES"), new IvParameterSpec(this.ivParamBytes));
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            encryptedValue = Base64.getEncoder().encodeToString(cipher.doFinal(toEncrypt.getBytes()));
        }
        else{
            encryptedValue = android.util.Base64.encodeToString(cipher.doFinal(toEncrypt.getBytes()), android.util.Base64.DEFAULT);
        }
        return encryptedValue;
    }

    public String decrypt(String toDecrypt, String key) throws Exception {
        String decryptedValue = "";
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING", "SunJCE");
        cipher.init(2, new SecretKeySpec(key.getBytes(), "AES"), new IvParameterSpec(this.ivParamBytes));
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            decryptedValue = new String(cipher.doFinal(Base64.getDecoder().decode(toDecrypt)));
        }
        else{
            decryptedValue = new String(cipher.doFinal(android.util.Base64.decode(toDecrypt, android.util.Base64.DEFAULT)));
        }
        return decryptedValue;
    }
}
