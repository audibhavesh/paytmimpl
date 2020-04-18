package com.example.paytmimpl.checksum.crypto

import android.os.Build
import java.util.*
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

public class AesEncryption : Encryption {
    private val ivParamBytes =
        byteArrayOf(64, 64, 64, 64, 38, 38, 38, 38, 35, 35, 35, 35, 36, 36, 36, 36)


    override fun encrypt(toEncrypt: String, key: String): String {
        var encryptedValue = ""
//        val cipher: Cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING", "SunJCE")
        val cipher: Cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING", "BC")
        cipher.init(1, SecretKeySpec(key.toByteArray(), "AES"), IvParameterSpec(ivParamBytes))
        encryptedValue = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Base64.getEncoder()
                .encodeToString(cipher.doFinal(toEncrypt.toByteArray()))
        } else {
            android.util.Base64.encodeToString(
                cipher.doFinal(toEncrypt.toByteArray()),
                android.util.Base64.DEFAULT
            )
        }
        return encryptedValue
    }


    override fun decrypt(toDecrypt: String, key: String): String {
        var decryptedValue = ""
//        val cipher: Cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING", "SunJCE")
        val cipher: Cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING", "BC")
        cipher.init(2, SecretKeySpec(key.toByteArray(), "AES"), IvParameterSpec(ivParamBytes))
        decryptedValue = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            String(cipher.doFinal(Base64.getDecoder().decode(toDecrypt)))
        } else {
            String(
                cipher.doFinal(
                    android.util.Base64.decode(
                        toDecrypt,
                        android.util.Base64.DEFAULT
                    )
                )
            )
        }
        return decryptedValue
    }
}
