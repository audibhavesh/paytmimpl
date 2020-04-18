package com.example.paytmimpl.checksum

import com.example.paytmimpl.checksum.crypto.CryptoUtils.generateRandomString
import com.example.paytmimpl.checksum.crypto.CryptoUtils.getSHA256
import com.example.paytmimpl.checksum.crypto.EncryptionFactory.getEncryptionInstance
import com.example.paytmimpl.checksum.crypto.EncryptionFactory.getEncryptionInstanceGAE
import com.example.paytmimpl.checksum.crypto.EncryptionFactory.getEncryptionInstanceIBMJCE
import java.util.*


class CheckSumServiceHelper {

    @Throws(Exception::class)
    fun genrateRefundCheckSum(
        Key: String?,
        paramap: TreeMap<String?, String?>
    ): String {
        val response =
            checkSumServiceHelper.getRefundCheckSumString(paramap)
        var checkSumValue: String? = null
        return try {
            val encryption = getEncryptionInstance("AES")
            val randomNo = generateRandomString(4)
            response.append(randomNo)
            var checkSumHash = getSHA256(response.toString())
            checkSumHash = checkSumHash + randomNo
            checkSumValue = encryption.encrypt(checkSumHash, Key!!)
            if (checkSumValue != null) {
                checkSumValue = checkSumValue.replace("\r\n".toRegex(), "")
                checkSumValue = checkSumValue.replace("\r".toRegex(), "")
                checkSumValue = checkSumValue.replace("\n".toRegex(), "")
            }
            checkSumValue
        } catch (var8: SecurityException) {
            throw var8
        }
    }

    @Throws(Exception::class)
    fun genrateCheckSum(
        Key: String,
        paramap: TreeMap<String, String>
    ): String {
        val response =
            checkSumServiceHelper.getCheckSumString(paramap)
        var checkSumValue: String? = null
        return try {
            val encryption = getEncryptionInstance("AES")
            val randomNo = generateRandomString(4)
            response.append(randomNo)
            var checkSumHash = getSHA256(response.toString())
            checkSumHash = checkSumHash + randomNo
            checkSumValue = encryption.encrypt(checkSumHash, Key!!)
            if (checkSumValue != null) {
                checkSumValue = checkSumValue.replace("\r\n".toRegex(), "")
                checkSumValue = checkSumValue.replace("\r".toRegex(), "")
                checkSumValue = checkSumValue.replace("\n".toRegex(), "")
            }
            checkSumValue
        } catch (var8: SecurityException) {
            throw var8
        }
    }

    @Throws(Exception::class)
    fun genrateCheckSumGAE(
        Key: String?,
        paramap: TreeMap<String, String>
    ): String {
        val response =
            checkSumServiceHelper.getCheckSumString(paramap)
        var checkSumValue: String? = null
        return try {
            val encryption = getEncryptionInstanceGAE("AES")
            val randomNo = generateRandomString(4)
            response.append(randomNo)
            var checkSumHash = getSHA256(response.toString())
            checkSumHash += randomNo
            checkSumValue = encryption.encryptGAE(checkSumHash, Key!!)
            if (checkSumValue != null) {
                checkSumValue = checkSumValue.replace("\r\n".toRegex(), "")
                checkSumValue = checkSumValue.replace("\r".toRegex(), "")
                checkSumValue = checkSumValue.replace("\n".toRegex(), "")
            }
            checkSumValue
        } catch (var8: SecurityException) {
            throw var8
        }
    }

    @Throws(Exception::class)
    fun genrateRefundCheckSumGAE(
        Key: String?,
        paramap: TreeMap<String?, String?>
    ): String {
        val response =
            checkSumServiceHelper.getRefundCheckSumString(paramap)
        var checkSumValue: String? = null
        return try {
            val encryption = getEncryptionInstanceGAE("AES")
            val randomNo = generateRandomString(4)
            response.append(randomNo)
            var checkSumHash = getSHA256(response.toString())
            checkSumHash = checkSumHash + randomNo
            checkSumValue = encryption.encryptGAE(checkSumHash, Key!!)
            if (checkSumValue != null) {
                checkSumValue = checkSumValue.replace("\r\n".toRegex(), "")
                checkSumValue = checkSumValue.replace("\r".toRegex(), "")
                checkSumValue = checkSumValue.replace("\n".toRegex(), "")
            }
            checkSumValue
        } catch (var8: SecurityException) {
            throw var8
        }
    }

    @Throws(Exception::class)
    fun genrateCheckSumIBMJCE(
        Key: String?,
        paramap: TreeMap<String, String>
    ): String {
        val response =
            checkSumServiceHelper.getCheckSumString(paramap)
        var checkSumValue: String? = null
        return try {
            val encryption = getEncryptionInstanceIBMJCE("AES")
            val randomNo = generateRandomString(4)
            response.append(randomNo)
            var checkSumHash = getSHA256(response.toString())
            checkSumHash = checkSumHash + randomNo
            checkSumValue = encryption.encryptIBMJCE(checkSumHash, Key!!)
            if (checkSumValue != null) {
                checkSumValue = checkSumValue.replace("\r\n".toRegex(), "")
                checkSumValue = checkSumValue.replace("\r".toRegex(), "")
                checkSumValue = checkSumValue.replace("\n".toRegex(), "")
            }
            checkSumValue
        } catch (var8: SecurityException) {
            throw var8
        }
    }

    @Throws(Exception::class)
    fun genrateRefundCheckSumIBMJCE(
        Key: String?,
        paramap: TreeMap<String?, String?>
    ): String {
        val response =
            checkSumServiceHelper.getRefundCheckSumString(paramap)
        var checkSumValue: String? = null
        return try {
            val encryption = getEncryptionInstanceIBMJCE("AES")
            val randomNo = generateRandomString(4)
            response.append(randomNo)
            var checkSumHash = getSHA256(response.toString())
            checkSumHash = checkSumHash + randomNo
            checkSumValue = encryption.encryptIBMJCE(checkSumHash, Key!!)
            if (checkSumValue != null) {
                checkSumValue = checkSumValue.replace("\r\n".toRegex(), "")
                checkSumValue = checkSumValue.replace("\r".toRegex(), "")
                checkSumValue = checkSumValue.replace("\n".toRegex(), "")
            }
            checkSumValue
        } catch (var8: SecurityException) {
            throw var8
        }
    }

    @Throws(Exception::class)
    fun genrateCheckSumIBMJCEQueryStr(Key: String?, paramap: String): String {
        val response =
            checkSumServiceHelper.getCheckSumStringByQueryString(
                paramap
            )
        var checkSumValue: String? = null
        return try {
            val encryption = getEncryptionInstanceIBMJCE("AES")
            val randomNo = generateRandomString(4)
            response.append(randomNo)
            var checkSumHash = getSHA256(response.toString())
            checkSumHash = checkSumHash + randomNo
            checkSumValue = encryption.encryptIBMJCE(checkSumHash, Key!!)
            if (checkSumValue != null) {
                checkSumValue = checkSumValue.replace("\r\n".toRegex(), "")
                checkSumValue = checkSumValue.replace("\r".toRegex(), "")
                checkSumValue = checkSumValue.replace("\n".toRegex(), "")
            }
            checkSumValue
        } catch (var8: SecurityException) {
            throw var8
        }
    }

    @Throws(Exception::class)
    fun getCheckSumString(paramMap: TreeMap<String, String>): StringBuilder {
        val keys: Set<String?> = paramMap.keys
        val checkSumStringBuffer = StringBuilder("")
        val parameterSet: TreeSet<String> = TreeSet<String>()
        var var6: Iterator<*> = keys.iterator()
        var paramName: String
        while (var6.hasNext()) {
            paramName = var6.next() as String
            if (!"CHECKSUMHASH".equals(paramName, ignoreCase = true)) {
                parameterSet.add(paramName)
            }
        }
        var6 = parameterSet.iterator()
        while (var6.hasNext()) {
            paramName = var6.next()
            var value = paramMap[paramName]
            if (value == null || value.trim { it <= ' ' }.equals("NULL", ignoreCase = true)) {
                value = ""
            }
            if (!value.toLowerCase().contains("|") && !value.toLowerCase().contains("refund")) {
                checkSumStringBuffer.append(value).append("|")
            }
        }
        return checkSumStringBuffer
    }

    @Throws(Exception::class)
    fun getCheckSumStringForVerify(paramMap: TreeMap<String, String?>): StringBuilder {
        val keys: Set<String> = paramMap.keys
        val checkSumStringBuffer = StringBuilder("")
        val parameterSet: TreeSet<String> = TreeSet<String>()
        var var6: Iterator<*> = keys.iterator()
        var paramName: String
        while (var6.hasNext()) {
            paramName = var6.next() as String
            if (!"CHECKSUMHASH".equals(paramName, ignoreCase = true)) {
                parameterSet.add(paramName)
            }
        }
        var6 = parameterSet.iterator()
        while (var6.hasNext()) {
            paramName = var6.next() as String
            var value = paramMap[paramName]
            if (value == null || value.trim { it <= ' ' }.equals("NULL", ignoreCase = true)) {
                value = ""
            }
            if (!value.toLowerCase().contains("|")) {
                checkSumStringBuffer.append(value).append("|")
            }
        }
        return checkSumStringBuffer
    }

    @Throws(Exception::class)
    fun getRefundCheckSumString(paramMap: TreeMap<String?, String?>): StringBuilder {
        val keys: Set<String?> = paramMap.keys
        val checkSumStringBuffer = StringBuilder("")
        val parameterSet: TreeSet<String> = TreeSet<String>()
        var var6: Iterator<*> = keys.iterator()
        var paramName: String
        while (var6.hasNext()) {
            paramName = var6.next() as String
            if (!"CHECKSUMHASH".equals(paramName, ignoreCase = true)) {
                parameterSet.add(paramName)
            }
        }
        var6 = parameterSet.iterator()
        while (var6.hasNext()) {
            paramName = var6.next()
            var value = paramMap[paramName]
            if (value == null || value.trim { it <= ' ' }.equals("NULL", ignoreCase = true)) {
                value = ""
            }
            if (!value.toLowerCase().contains("|")) {
                checkSumStringBuffer.append(value).append("|")
            }
        }
        return checkSumStringBuffer
    }

    @Throws(Exception::class)
    fun getCheckSumStringByQueryString(paramString: String): StringBuilder {
        val paramMap: TreeMap<String, String> =
            TreeMap<String,String>()
        val params = paramString.split("&").toTypedArray()
        if (params != null && params.size > 0) {
            val var6 = params.size
            for (var5 in 0 until var6) {
                val param = params[var5]
                val keyValue = param.split("=").toTypedArray()
                if (keyValue != null) {
                    if (keyValue.size == 2) {
                        paramMap[keyValue[0]] = keyValue[1]
                    } else if (keyValue.size == 1) {
                        paramMap[keyValue[0]] = ""
                    }
                }
            }
        }
        val keys: Set<String?> = paramMap.keys
        val checkSumStringBuffer = StringBuilder("")
        val parameterSet: TreeSet<String> = TreeSet<String>()
        var var14: Iterator<*> = keys.iterator()
        var paramName: String
        while (var14.hasNext()) {
            paramName = var14.next() as String
            if (!"CHECKSUMHASH".equals(paramName, ignoreCase = true)) {
                parameterSet.add(paramName)
            }
        }
        var14 = parameterSet.iterator()
        while (var14.hasNext()) {
            paramName = var14.next()
            var value = paramMap[paramName]
            if (value == null || value.trim { it <= ' ' }.equals("NULL", ignoreCase = true)) {
                value = ""
            }
            if (!value.toLowerCase().contains("|") && !value.toLowerCase().contains("refund")) {
                checkSumStringBuffer.append(value).append("|")
            }
        }
        return checkSumStringBuffer
    }

    @Throws(Exception::class)
    fun genrateCheckSum(Key: String, paramap: String): String {
        val response = StringBuilder(paramap!!)
        response.append("|")
        var checkSumValue: String? = null
        return try {
            val encryption = getEncryptionInstance("AES")
            val randomNo = generateRandomString(4)
            response.append(randomNo)
            var checkSumHash = getSHA256(response.toString())
            checkSumHash = checkSumHash + randomNo
            checkSumValue = encryption.encrypt(checkSumHash, Key!!)
            if (checkSumValue != null) {
                checkSumValue = checkSumValue.replace("\r\n".toRegex(), "")
                checkSumValue = checkSumValue.replace("\r".toRegex(), "")
                checkSumValue = checkSumValue.replace("\n".toRegex(), "")
            }
            checkSumValue
        } catch (var8: SecurityException) {
            throw var8
        }
    }

    @Throws(Exception::class)
    fun getParamsMapFromEncParam(
        masterKey: String?,
        encParam: String?
    ): TreeMap<String, String>? {
        return try {
            if (masterKey != null && encParam != null) {
                val encryption = getEncryptionInstance("AES")
                val paramsString = encryption.decrypt(encParam, masterKey)
                if (paramsString != null) {
                    return getMapForRawData(paramsString)
                }
            }
            null
        } catch (var5: Exception) {
            throw var5
        }
    }

    @Throws(Exception::class)
    fun getDecryptedValue(masterKey: String?, decryptTo: String?): String {
        return try {
            val encryption = getEncryptionInstance("AES")
            encryption.decrypt(decryptTo!!, masterKey!!)
        } catch (var4: Exception) {
            throw var4
        }
    }

    private fun getMapForRawData(rawdata: String?): TreeMap<String, String>? {
        if (rawdata != null) {
            val resp: TreeMap<String, String> =
                TreeMap<String,String>()
            val params = rawdata.split("\\|").toTypedArray()
            if (params != null && params.size > 0) {
                val var6 = params.size
                for (var5 in 0 until var6) {
                    val param = params[var5]
                    val keyValue = param.split("=").toTypedArray()
                    if (keyValue != null) {
                        if (keyValue.size == 2) {
                            resp[keyValue[0]] = keyValue[1]
                        } else if (keyValue.size == 1) {
                            resp[keyValue[0]] = ""
                        }
                    }
                }
                return resp
            }
        }
        return null
    }

    @Throws(Exception::class)
    fun getEncryptedParam(
        masterKey: String?,
        paramMap: TreeMap<String?, String?>?
    ): String {
        val params = StringBuilder()
        return try {
            if (paramMap != null && paramMap.size > 0) {
                val var5: Iterator<*> = paramMap.entries.iterator()
                while (var5.hasNext()) {
                    val entry: Map.Entry<String, String> =
                        var5.next() as Map.Entry<String, String>
                    params.append(entry.key.trim { it <= ' ' }).append("=")
                        .append(entry.value.trim { it <= ' ' }).append("|")
                }
            }
            val encryption = getEncryptionInstance("AES")
            encryption.encrypt(params.toString(), masterKey!!)
        } catch (var6: Exception) {
            throw var6
        }
    }

    @Throws(Exception::class)
    fun verifycheckSum(
        masterKey: String?,
        paramap: TreeMap<String, String?>,
        responseCheckSumString: String?
    ): Boolean {
        var isValidChecksum = false
        val response =
            checkSumServiceHelper.getCheckSumStringForVerify(paramap)
        val encryption = getEncryptionInstance("AES")
        val responseCheckSumHash =
            encryption.decrypt(responseCheckSumString!!, masterKey!!)
        val randomStr =
            getLastNChars(responseCheckSumHash, 4)
        val payTmCheckSumHash =
            calculateRequestCheckSum(randomStr, response.toString())
        if (responseCheckSumHash != null && payTmCheckSumHash != null && responseCheckSumHash == payTmCheckSumHash) {
            isValidChecksum = true
        }
        return isValidChecksum
    }

    @Throws(Exception::class)
    fun verifycheckSum(
        masterKey: String?,
        paramap: String?,
        responseCheckSumString: String?
    ): Boolean {
        var isValidChecksum = false
        val encryption = getEncryptionInstance("AES")
        val response = StringBuilder(paramap!!)
        response.append("|")
        val responseCheckSumHash =
            encryption.decrypt(responseCheckSumString!!, masterKey!!)
        val randomStr =
            getLastNChars(responseCheckSumHash, 4)
        val payTmCheckSumHash =
            calculateRequestCheckSum(randomStr, response.toString())
        if (responseCheckSumHash != null && payTmCheckSumHash != null && responseCheckSumHash == payTmCheckSumHash) {
            isValidChecksum = true
        }
        return isValidChecksum
    }

    @Throws(Exception::class)
    fun verifycheckSumQueryStr(
        masterKey: String?,
        paramap: String,
        responseCheckSumString: String?
    ): Boolean {
        var isValidChecksum = false
        val response =
            checkSumServiceHelper.getCheckSumStringByQueryString(
                paramap
            )
        val encryption = getEncryptionInstance("AES")
        val responseCheckSumHash =
            encryption.decrypt(responseCheckSumString!!, masterKey!!)
        val randomStr =
            getLastNChars(responseCheckSumHash, 4)
        val payTmCheckSumHash =
            calculateRequestCheckSum(randomStr, response.toString())
        if (responseCheckSumHash != null && payTmCheckSumHash != null && responseCheckSumHash == payTmCheckSumHash) {
            isValidChecksum = true
        }
        return isValidChecksum
    }

    @Throws(Exception::class)
    fun verifycheckSumGAE(
        masterKey: String?,
        paramap: TreeMap<String, String>,
        responseCheckSumString: String?
    ): Boolean {
        var isValidChecksum = false
        val response =
            checkSumServiceHelper.getCheckSumString(paramap)
        val encryption = getEncryptionInstanceGAE("AES")
        val responseCheckSumHash =
            encryption.decryptGAE(responseCheckSumString!!, masterKey!!)
        val randomStr =
            getLastNChars(responseCheckSumHash, 4)
        val payTmCheckSumHash =
            calculateRequestCheckSum(randomStr, response.toString())
        if (responseCheckSumHash != null && payTmCheckSumHash != null && responseCheckSumHash == payTmCheckSumHash) {
            isValidChecksum = true
        }
        return isValidChecksum
    }

    @Throws(Exception::class)
    fun verifycheckSumIBMJCE(
        masterKey: String?,
        paramap: TreeMap<String, String>,
        responseCheckSumString: String?
    ): Boolean {
        var isValidChecksum = false
        val response =
            checkSumServiceHelper.getCheckSumString(paramap)
        val encryption = getEncryptionInstanceIBMJCE("AES")
        val responseCheckSumHash =
            encryption.decryptIBMJCE(responseCheckSumString!!, masterKey!!)
        val randomStr =
            getLastNChars(responseCheckSumHash, 4)
        val payTmCheckSumHash =
            calculateRequestCheckSum(randomStr, response.toString())
        if (responseCheckSumHash != null && payTmCheckSumHash != null && responseCheckSumHash == payTmCheckSumHash) {
            isValidChecksum = true
        }
        return isValidChecksum
    }

    @Throws(Exception::class)
    fun verifycheckSumIBMJCEQueryStr(
        masterKey: String?,
        paramap: String,
        responseCheckSumString: String?
    ): Boolean {
        var isValidChecksum = false
        val response =
            checkSumServiceHelper.getCheckSumStringByQueryString(
                paramap
            )
        val encryption = getEncryptionInstanceIBMJCE("AES")
        val responseCheckSumHash =
            encryption.decryptIBMJCE(responseCheckSumString!!, masterKey!!)
        val randomStr =
            getLastNChars(responseCheckSumHash, 4)
        val payTmCheckSumHash =
            calculateRequestCheckSum(randomStr, response.toString())
        if (responseCheckSumHash != null && payTmCheckSumHash != null && responseCheckSumHash == payTmCheckSumHash) {
            isValidChecksum = true
        }
        return isValidChecksum
    }

    @Throws(Exception::class)
    private fun calculateRequestCheckSum(
        randomStr: String,
        checkSumString: String
    ): String {
        var checkSumHash = getSHA256(checkSumString + randomStr)
        checkSumHash = checkSumHash + randomStr
        return checkSumHash
    }

    companion object {
        val checkSumServiceHelper = CheckSumServiceHelper()
        val version: String
            get() = "3.0"

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

        @Throws(Exception::class)
        fun Encrypt(toEncrypt: String?, key: String?): String {
            val encryption = getEncryptionInstance("AES")
            return encryption.encrypt(toEncrypt!!, key!!)
        }

        @Throws(Exception::class)
        fun Decrypt(toDecrypt: String?, key: String?): String {
            val encryption = getEncryptionInstance("AES")
            return encryption.decrypt(toDecrypt!!, key!!)
        }
    }
}
