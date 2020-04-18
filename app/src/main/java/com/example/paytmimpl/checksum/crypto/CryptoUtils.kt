package com.example.paytmimpl.checksum.crypto

import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import java.util.*

object CryptoUtils {
    @Throws(Exception::class)
    fun getHashFromSHA(value: String): String {
        var hashValue = ""
        val messageDigest =
            MessageDigest.getInstance("SHA-256")
        hashValue = byteArray2Hex(messageDigest.digest(value.toByteArray()))
        return hashValue
    }

    private fun byteArray2Hex(hash: ByteArray): String {
        val formatter = Formatter()
        val var4 = hash.size
        for (var3 in 0 until var4) {
            val b = hash[var3]
            formatter.format("%02x", b)
        }
        return formatter.toString()
    }

    fun generateRandomString(length: Int): String {
        val ALPHA_NUM =
            "9876543210ZYXWVUTSRQPONMLKJIHGFEDCBAabcdefghijklmnopqrstuvwxyz!@#$&_"
        val sb = StringBuffer(length)
        for (i in 0 until length) {
            val ndx = (Math.random() * ALPHA_NUM.length.toDouble()).toInt()
            sb.append(ALPHA_NUM[ndx])
        }
        return sb.toString()
    }

    @Throws(SecurityException::class)
    fun getSHA256(value: String): String {
        var hashValue = ""
        return try {
            val messageDigest =
                MessageDigest.getInstance("SHA-256")
            hashValue = byteArray2Hex(messageDigest.digest(value.toByteArray()))
            hashValue
        } catch (var3: NoSuchAlgorithmException) {
            throw SecurityException(var3.message, var3)
        }
    }

    fun getLastNChars(inputString: String?, subStringLength: Int): String {
        return if (inputString != null && inputString.length > 0) {
            val length = inputString.length
            if (length <= subStringLength) {
                inputString
            } else {
                val startIndex = length - subStringLength
                inputString.substring(startIndex)
            }
        } else {
            ""
        }
    }
}
