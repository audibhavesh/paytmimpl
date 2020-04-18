package com.example.paytmimpl.checksum.crypto

interface EncryptionIBMJCE {
    @Throws(Exception::class)
    fun encryptIBMJCE(var1: String, var2: String): String

    @Throws(Exception::class)
    fun decryptIBMJCE(var1: String, var2: String): String
}
