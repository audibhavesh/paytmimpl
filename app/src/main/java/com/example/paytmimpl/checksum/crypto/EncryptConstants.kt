package com.example.paytmimpl.checksum.crypto

interface EncryptConstants {
    companion object {
        const val ALGTHM_TYPE_3DES = "DESede"
        const val ALGTHM_TYPE_HASH_SHA_256 = "SHA-256"
        const val ALGTHM_TYPE_AES = "AES"
        const val ALGTHM_CBC_PAD_AES = "AES/CBC/PKCS5PADDING"
        const val ALGTHM_PROVIDER_BC = "SunJCE"
        const val STR_COMMA = ","
        const val KEYSTORE_TYPE = "JCEKS"
        const val ALIAS_TYPE_AES = "ALIAS_AES"
        const val ALIAS_TYPE_3DES = "ALIAS_3DES"
        const val KEYSTORE_NOT_FOUND_MSG = "Not able to load or generate the KeyStore"
        const val ALGTHM_PROVIDER_JCE = "IBMJCE"
    }
}
