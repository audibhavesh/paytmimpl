package com.example.paytmimpl.checksum.crypto

import okio.ByteString.decodeBase64
import org.apache.commons.codec.binary.Base64
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class AesEncryptionGAE : EncryptionGAE {
    private val ivParamBytes =
        byteArrayOf(64, 64, 64, 64, 38, 38, 38, 38, 35, 35, 35, 35, 36, 36, 36, 36)

    @Throws(Exception::class)
    override fun encryptGAE(toEncrypt: String, password: String): String {
        val key = password.toByteArray()
        val cipher: Cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING", "SunJCE")
        cipher.init(1, SecretKeySpec(key, "AES"), IvParameterSpec(ivParamBytes))
        return Base64.encodeBase64String(cipher.doFinal(toEncrypt.toByteArray()))
    }

    @Throws(Exception::class)
     override fun decryptGAE(toDecrypt: String, key: String): String {
        var decryptedValue = ""
        val cipher: Cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING", "SunJCE")
        cipher.init(2, SecretKeySpec(key.toByteArray(), "AES"), IvParameterSpec(ivParamBytes))
        decryptedValue = String(cipher.doFinal(Base64.decodeBase64(toDecrypt)))
        return decryptedValue
    }
}
