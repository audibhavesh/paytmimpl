package com.example.paytmimpl.checksumjava;

import com.example.paytmimpl.checksumjava.cryprojava.CryptoUtils;
import com.example.paytmimpl.checksumjava.cryprojava.Encryption;
import com.example.paytmimpl.checksumjava.cryprojava.EncryptionFactory;
import com.example.paytmimpl.checksumjava.cryprojava.EncryptionGAE;
import com.example.paytmimpl.checksumjava.cryprojava.EncryptionIBMJCE;

import java.util.Iterator;
import java.util.Map.Entry;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;

public class CheckSumServiceHelper {
    private static final CheckSumServiceHelper checkSumServiceHelper = new CheckSumServiceHelper();

    private CheckSumServiceHelper() {
    }

    public static String getVersion() {
        return "3.0";
    }

    public static CheckSumServiceHelper getCheckSumServiceHelper() {
        return checkSumServiceHelper;
    }

    public String genrateRefundCheckSum(String Key, TreeMap<String, String> paramap) throws Exception {
        StringBuilder response = checkSumServiceHelper.getRefundCheckSumString(paramap);
        String checkSumValue = null;

        try {
            Encryption encryption = EncryptionFactory.getEncryptionInstance("AES");
            String randomNo = CryptoUtils.generateRandomString(4);
            response.append(randomNo);
            String checkSumHash = CryptoUtils.getSHA256(response.toString());
            checkSumHash = checkSumHash.concat(randomNo);
            checkSumValue = encryption.encrypt(checkSumHash, Key);
            if (checkSumValue != null) {
                checkSumValue = checkSumValue.replaceAll("\r\n", "");
                checkSumValue = checkSumValue.replaceAll("\r", "");
                checkSumValue = checkSumValue.replaceAll("\n", "");
            }

            return checkSumValue;
        } catch (SecurityException var8) {
            throw var8;
        }
    }

    public String genrateCheckSum(String Key, TreeMap<String, String> paramap) throws Exception {
        StringBuilder response = checkSumServiceHelper.getCheckSumString(paramap);
        String checkSumValue = null;

        try {
            Encryption encryption = EncryptionFactory.getEncryptionInstance("AES");
            String randomNo = CryptoUtils.generateRandomString(4);
            response.append(randomNo);
            String checkSumHash = CryptoUtils.getSHA256(response.toString());
            checkSumHash = checkSumHash.concat(randomNo);
            checkSumValue = encryption.encrypt(checkSumHash, Key);
            if (checkSumValue != null) {
                checkSumValue = checkSumValue.replaceAll("\r\n", "");
                checkSumValue = checkSumValue.replaceAll("\r", "");
                checkSumValue = checkSumValue.replaceAll("\n", "");
            }

            return checkSumValue;
        } catch (SecurityException var8) {
            throw var8;
        }
    }

    public String genrateCheckSumGAE(String Key, TreeMap<String, String> paramap) throws Exception {
        StringBuilder response = checkSumServiceHelper.getCheckSumString(paramap);
        String checkSumValue = null;

        try {
            EncryptionGAE encryption = EncryptionFactory.getEncryptionInstanceGAE("AES");
            String randomNo = CryptoUtils.generateRandomString(4);
            response.append(randomNo);
            String checkSumHash = CryptoUtils.getSHA256(response.toString());
            checkSumHash = checkSumHash.concat(randomNo);
            checkSumValue = encryption.encryptGAE(checkSumHash, Key);
            if (checkSumValue != null) {
                checkSumValue = checkSumValue.replaceAll("\r\n", "");
                checkSumValue = checkSumValue.replaceAll("\r", "");
                checkSumValue = checkSumValue.replaceAll("\n", "");
            }

            return checkSumValue;
        } catch (SecurityException var8) {
            throw var8;
        }
    }

    public String genrateRefundCheckSumGAE(String Key, TreeMap<String, String> paramap) throws Exception {
        StringBuilder response = checkSumServiceHelper.getRefundCheckSumString(paramap);
        String checkSumValue = null;

        try {
            EncryptionGAE encryption = EncryptionFactory.getEncryptionInstanceGAE("AES");
            String randomNo = CryptoUtils.generateRandomString(4);
            response.append(randomNo);
            String checkSumHash = CryptoUtils.getSHA256(response.toString());
            checkSumHash = checkSumHash.concat(randomNo);
            checkSumValue = encryption.encryptGAE(checkSumHash, Key);
            if (checkSumValue != null) {
                checkSumValue = checkSumValue.replaceAll("\r\n", "");
                checkSumValue = checkSumValue.replaceAll("\r", "");
                checkSumValue = checkSumValue.replaceAll("\n", "");
            }

            return checkSumValue;
        } catch (SecurityException var8) {
            throw var8;
        }
    }

    public String genrateCheckSumIBMJCE(String Key, TreeMap<String, String> paramap) throws Exception {
        StringBuilder response = checkSumServiceHelper.getCheckSumString(paramap);
        String checkSumValue = null;

        try {
            EncryptionIBMJCE encryption = EncryptionFactory.getEncryptionInstanceIBMJCE("AES");
            String randomNo = CryptoUtils.generateRandomString(4);
            response.append(randomNo);
            String checkSumHash = CryptoUtils.getSHA256(response.toString());
            checkSumHash = checkSumHash.concat(randomNo);
            checkSumValue = encryption.encryptIBMJCE(checkSumHash, Key);
            if (checkSumValue != null) {
                checkSumValue = checkSumValue.replaceAll("\r\n", "");
                checkSumValue = checkSumValue.replaceAll("\r", "");
                checkSumValue = checkSumValue.replaceAll("\n", "");
            }

            return checkSumValue;
        } catch (SecurityException var8) {
            throw var8;
        }
    }

    public String genrateRefundCheckSumIBMJCE(String Key, TreeMap<String, String> paramap) throws Exception {
        StringBuilder response = checkSumServiceHelper.getRefundCheckSumString(paramap);
        String checkSumValue = null;

        try {
            EncryptionIBMJCE encryption = EncryptionFactory.getEncryptionInstanceIBMJCE("AES");
            String randomNo = CryptoUtils.generateRandomString(4);
            response.append(randomNo);
            String checkSumHash = CryptoUtils.getSHA256(response.toString());
            checkSumHash = checkSumHash.concat(randomNo);
            checkSumValue = encryption.encryptIBMJCE(checkSumHash, Key);
            if (checkSumValue != null) {
                checkSumValue = checkSumValue.replaceAll("\r\n", "");
                checkSumValue = checkSumValue.replaceAll("\r", "");
                checkSumValue = checkSumValue.replaceAll("\n", "");
            }

            return checkSumValue;
        } catch (SecurityException var8) {
            throw var8;
        }
    }

    public String genrateCheckSumIBMJCEQueryStr(String Key, String paramap) throws Exception {
        StringBuilder response = checkSumServiceHelper.getCheckSumStringByQueryString(paramap);
        String checkSumValue = null;

        try {
            EncryptionIBMJCE encryption = EncryptionFactory.getEncryptionInstanceIBMJCE("AES");
            String randomNo = CryptoUtils.generateRandomString(4);
            response.append(randomNo);
            String checkSumHash = CryptoUtils.getSHA256(response.toString());
            checkSumHash = checkSumHash.concat(randomNo);
            checkSumValue = encryption.encryptIBMJCE(checkSumHash, Key);
            if (checkSumValue != null) {
                checkSumValue = checkSumValue.replaceAll("\r\n", "");
                checkSumValue = checkSumValue.replaceAll("\r", "");
                checkSumValue = checkSumValue.replaceAll("\n", "");
            }

            return checkSumValue;
        } catch (SecurityException var8) {
            throw var8;
        }
    }

    public StringBuilder getCheckSumString(TreeMap<String, String> paramMap) throws Exception {
        Set<String> keys = paramMap.keySet();
        StringBuilder checkSumStringBuffer = new StringBuilder("");
        TreeSet<String> parameterSet = new TreeSet();
        Iterator var6 = keys.iterator();

        String paramName;
        while (var6.hasNext()) {
            paramName = (String) var6.next();
            if (!"CHECKSUMHASH".equalsIgnoreCase(paramName)) {
                parameterSet.add(paramName);
            }
        }

        var6 = parameterSet.iterator();

        while (var6.hasNext()) {
            paramName = (String) var6.next();
            String value = (String) paramMap.get(paramName);
            if (value == null || value.trim().equalsIgnoreCase("NULL")) {
                value = "";
            }

            if (!value.toLowerCase().contains("|") && !value.toLowerCase().contains("refund")) {
                checkSumStringBuffer.append(value).append("|");
            }
        }

        return checkSumStringBuffer;
    }

    public StringBuilder getCheckSumStringForVerify(TreeMap<String, String> paramMap) throws Exception {
        Set<String> keys = paramMap.keySet();
        StringBuilder checkSumStringBuffer = new StringBuilder("");
        TreeSet<String> parameterSet = new TreeSet();
        Iterator var6 = keys.iterator();

        String paramName;
        while (var6.hasNext()) {
            paramName = (String) var6.next();
            if (!"CHECKSUMHASH".equalsIgnoreCase(paramName)) {
                parameterSet.add(paramName);
            }
        }

        var6 = parameterSet.iterator();

        while (var6.hasNext()) {
            paramName = (String) var6.next();
            String value = (String) paramMap.get(paramName);
            if (value == null || value.trim().equalsIgnoreCase("NULL")) {
                value = "";
            }

            if (!value.toLowerCase().contains("|")) {
                checkSumStringBuffer.append(value).append("|");
            }
        }

        return checkSumStringBuffer;
    }

    public StringBuilder getRefundCheckSumString(TreeMap<String, String> paramMap) throws Exception {
        Set<String> keys = paramMap.keySet();
        StringBuilder checkSumStringBuffer = new StringBuilder("");
        TreeSet<String> parameterSet = new TreeSet();
        Iterator var6 = keys.iterator();

        String paramName;
        while (var6.hasNext()) {
            paramName = (String) var6.next();
            if (!"CHECKSUMHASH".equalsIgnoreCase(paramName)) {
                parameterSet.add(paramName);
            }
        }

        var6 = parameterSet.iterator();

        while (var6.hasNext()) {
            paramName = (String) var6.next();
            String value = (String) paramMap.get(paramName);
            if (value == null || value.trim().equalsIgnoreCase("NULL")) {
                value = "";
            }

            if (!value.toLowerCase().contains("|")) {
                checkSumStringBuffer.append(value).append("|");
            }
        }

        return checkSumStringBuffer;
    }

    public StringBuilder getCheckSumStringByQueryString(String paramString) throws Exception {
        TreeMap<String, String> paramMap = new TreeMap();
        String[] params = paramString.split("&");
        if (params != null && params.length > 0) {
            String[] var7 = params;
            int var6 = params.length;

            for (int var5 = 0; var5 < var6; ++var5) {
                String param = var7[var5];
                String[] keyValue = param.split("=");
                if (keyValue != null) {
                    if (keyValue.length == 2) {
                        paramMap.put(keyValue[0], keyValue[1]);
                    } else if (keyValue.length == 1) {
                        paramMap.put(keyValue[0], "");
                    }
                }
            }
        }

        Set<String> keys = paramMap.keySet();
        StringBuilder checkSumStringBuffer = new StringBuilder("");
        TreeSet<String> parameterSet = new TreeSet();
        Iterator var14 = keys.iterator();

        String paramName;
        while (var14.hasNext()) {
            paramName = (String) var14.next();
            if (!"CHECKSUMHASH".equalsIgnoreCase(paramName)) {
                parameterSet.add(paramName);
            }
        }

        var14 = parameterSet.iterator();

        while (var14.hasNext()) {
            paramName = (String) var14.next();
            String value = (String) paramMap.get(paramName);
            if (value == null || value.trim().equalsIgnoreCase("NULL")) {
                value = "";
            }

            if (!value.toLowerCase().contains("|") && !value.toLowerCase().contains("refund")) {
                checkSumStringBuffer.append(value).append("|");
            }
        }

        return checkSumStringBuffer;
    }

    public String genrateCheckSum(String Key, String paramap) throws Exception {
        StringBuilder response = new StringBuilder(paramap);
        response.append("|");
        String checkSumValue = null;

        try {
            Encryption encryption = EncryptionFactory.getEncryptionInstance("AES");
            String randomNo = CryptoUtils.generateRandomString(4);
            response.append(randomNo);
            String checkSumHash = CryptoUtils.getSHA256(response.toString());
            checkSumHash = checkSumHash.concat(randomNo);
            checkSumValue = encryption.encrypt(checkSumHash, Key);
            if (checkSumValue != null) {
                checkSumValue = checkSumValue.replaceAll("\r\n", "");
                checkSumValue = checkSumValue.replaceAll("\r", "");
                checkSumValue = checkSumValue.replaceAll("\n", "");
            }

            return checkSumValue;
        } catch (SecurityException var8) {
            throw var8;
        }
    }

    public TreeMap<String, String> getParamsMapFromEncParam(String masterKey, String encParam) throws Exception {
        try {
            if (masterKey != null && encParam != null) {
                Encryption encryption = EncryptionFactory.getEncryptionInstance("AES");
                String paramsString = encryption.decrypt(encParam, masterKey);
                if (paramsString != null) {
                    return this.getMapForRawData(paramsString);
                }
            }

            return null;
        } catch (Exception var5) {
            throw var5;
        }
    }

    public String getDecryptedValue(String masterKey, String decryptTo) throws Exception {
        try {
            Encryption encryption = EncryptionFactory.getEncryptionInstance("AES");
            return encryption.decrypt(decryptTo, masterKey);
        } catch (Exception var4) {
            throw var4;
        }
    }

    private TreeMap<String, String> getMapForRawData(String rawdata) {
        if (rawdata != null) {
            TreeMap<String, String> resp = new TreeMap();
            String[] params = rawdata.split("\\|");
            if (params != null && params.length > 0) {
                String[] var7 = params;
                int var6 = params.length;

                for (int var5 = 0; var5 < var6; ++var5) {
                    String param = var7[var5];
                    String[] keyValue = param.split("=");
                    if (keyValue != null) {
                        if (keyValue.length == 2) {
                            resp.put(keyValue[0], keyValue[1]);
                        } else if (keyValue.length == 1) {
                            resp.put(keyValue[0], "");
                        }
                    }
                }

                return resp;
            }
        }

        return null;
    }

    public String getEncryptedParam(String masterKey, TreeMap<String, String> paramMap) throws Exception {
        StringBuilder params = new StringBuilder();

        try {
            if (paramMap != null && paramMap.size() > 0) {
                Iterator var5 = paramMap.entrySet().iterator();

                while (var5.hasNext()) {
                    Entry<String, String> entry = (Entry) var5.next();
                    params.append(((String) entry.getKey()).trim()).append("=").append(((String) entry.getValue()).trim()).append("|");
                }
            }

            Encryption encryption = EncryptionFactory.getEncryptionInstance("AES");
            return encryption.encrypt(params.toString(), masterKey);
        } catch (Exception var6) {
            throw var6;
        }
    }

    public boolean verifycheckSum(String masterKey, TreeMap<String, String> paramap, String responseCheckSumString) throws Exception {
        boolean isValidChecksum = false;
        StringBuilder response = checkSumServiceHelper.getCheckSumStringForVerify(paramap);
        Encryption encryption = EncryptionFactory.getEncryptionInstance("AES");
        String responseCheckSumHash = encryption.decrypt(responseCheckSumString, masterKey);
        String randomStr = getLastNChars(responseCheckSumHash, 4);
        String payTmCheckSumHash = this.calculateRequestCheckSum(randomStr, response.toString());
        if (responseCheckSumHash != null && payTmCheckSumHash != null && responseCheckSumHash.equals(payTmCheckSumHash)) {
            isValidChecksum = true;
        }

        return isValidChecksum;
    }

    public boolean verifycheckSum(String masterKey, String paramap, String responseCheckSumString) throws Exception {
        boolean isValidChecksum = false;
        Encryption encryption = EncryptionFactory.getEncryptionInstance("AES");
        StringBuilder response = new StringBuilder(paramap);
        response.append("|");
        String responseCheckSumHash = encryption.decrypt(responseCheckSumString, masterKey);
        String randomStr = getLastNChars(responseCheckSumHash, 4);
        String payTmCheckSumHash = this.calculateRequestCheckSum(randomStr, response.toString());
        if (responseCheckSumHash != null && payTmCheckSumHash != null && responseCheckSumHash.equals(payTmCheckSumHash)) {
            isValidChecksum = true;
        }

        return isValidChecksum;
    }

    public boolean verifycheckSumQueryStr(String masterKey, String paramap, String responseCheckSumString) throws Exception {
        boolean isValidChecksum = false;
        StringBuilder response = checkSumServiceHelper.getCheckSumStringByQueryString(paramap);
        Encryption encryption = EncryptionFactory.getEncryptionInstance("AES");
        String responseCheckSumHash = encryption.decrypt(responseCheckSumString, masterKey);
        String randomStr = getLastNChars(responseCheckSumHash, 4);
        String payTmCheckSumHash = this.calculateRequestCheckSum(randomStr, response.toString());
        if (responseCheckSumHash != null && payTmCheckSumHash != null && responseCheckSumHash.equals(payTmCheckSumHash)) {
            isValidChecksum = true;
        }

        return isValidChecksum;
    }

    public boolean verifycheckSumGAE(String masterKey, TreeMap<String, String> paramap, String responseCheckSumString) throws Exception {
        boolean isValidChecksum = false;
        StringBuilder response = checkSumServiceHelper.getCheckSumString(paramap);
        EncryptionGAE encryption = EncryptionFactory.getEncryptionInstanceGAE("AES");
        String responseCheckSumHash = encryption.decryptGAE(responseCheckSumString, masterKey);
        String randomStr = getLastNChars(responseCheckSumHash, 4);
        String payTmCheckSumHash = this.calculateRequestCheckSum(randomStr, response.toString());
        if (responseCheckSumHash != null && payTmCheckSumHash != null && responseCheckSumHash.equals(payTmCheckSumHash)) {
            isValidChecksum = true;
        }

        return isValidChecksum;
    }

    public boolean verifycheckSumIBMJCE(String masterKey, TreeMap<String, String> paramap, String responseCheckSumString) throws Exception {
        boolean isValidChecksum = false;
        StringBuilder response = checkSumServiceHelper.getCheckSumString(paramap);
        EncryptionIBMJCE encryption = EncryptionFactory.getEncryptionInstanceIBMJCE("AES");
        String responseCheckSumHash = encryption.decryptIBMJCE(responseCheckSumString, masterKey);
        String randomStr = getLastNChars(responseCheckSumHash, 4);
        String payTmCheckSumHash = this.calculateRequestCheckSum(randomStr, response.toString());
        if (responseCheckSumHash != null && payTmCheckSumHash != null && responseCheckSumHash.equals(payTmCheckSumHash)) {
            isValidChecksum = true;
        }

        return isValidChecksum;
    }

    public boolean verifycheckSumIBMJCEQueryStr(String masterKey, String paramap, String responseCheckSumString) throws Exception {
        boolean isValidChecksum = false;
        StringBuilder response = checkSumServiceHelper.getCheckSumStringByQueryString(paramap);
        EncryptionIBMJCE encryption = EncryptionFactory.getEncryptionInstanceIBMJCE("AES");
        String responseCheckSumHash = encryption.decryptIBMJCE(responseCheckSumString, masterKey);
        String randomStr = getLastNChars(responseCheckSumHash, 4);
        String payTmCheckSumHash = this.calculateRequestCheckSum(randomStr, response.toString());
        if (responseCheckSumHash != null && payTmCheckSumHash != null && responseCheckSumHash.equals(payTmCheckSumHash)) {
            isValidChecksum = true;
        }

        return isValidChecksum;
    }

    private String calculateRequestCheckSum(String randomStr, String checkSumString) throws Exception {
        String checkSumHash = CryptoUtils.getSHA256(checkSumString.concat(randomStr));
        checkSumHash = checkSumHash.concat(randomStr);
        return checkSumHash;
    }

    public static String getLastNChars(String inputString, int subStringLength) {
        if (inputString != null && inputString.length() > 0) {
            int length = inputString.length();
            if (length <= subStringLength) {
                return inputString;
            } else {
                int startIndex = length - subStringLength;
                return inputString.substring(startIndex);
            }
        } else {
            return "";
        }
    }

    public static String Encrypt(String toEncrypt, String key) throws Exception {
        Encryption encryption = EncryptionFactory.getEncryptionInstance("AES");
        return encryption.encrypt(toEncrypt, key);
    }

    public static String Decrypt(String toDecrypt, String key) throws Exception {
        Encryption encryption = EncryptionFactory.getEncryptionInstance("AES");
        return encryption.decrypt(toDecrypt, key);
    }
}
