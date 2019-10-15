package com.datek.cryptoeasecb.Helper
import java.nio.charset.StandardCharsets
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec
import kotlin.experimental.and


object Crypto {
    private val _hexArray = "0123456789ABCDEF".toCharArray()
    private val _key = "ZYWXVUTSRQPONMLK"
    fun BytesToHexStrArray(bytes: ByteArray): String {
        val hexChars = CharArray(bytes.size * 2)
        for (j in bytes.indices) {
            val v = bytes[j] and 0xFF.toByte()
            val bHigh = (v.toInt().ushr(4) and 0x0f)
            val bLow = (v and 0x0F).toInt()
            hexChars[(j * 2)] = _hexArray[bHigh]
            hexChars[(j * 2) + 1] = _hexArray[bLow]
        }
        return String(hexChars)
    }

    fun HexStringToByteArray(strText: String): ByteArray {
        val retByte = ByteArray(strText.length / 2)
        for (i in retByte.indices) {
            val index = i * 2
            val v = Integer.parseInt(strText.substring(index, index + 2), 16)
            retByte[i] = v.toByte()
        }
        return retByte
    }

    fun Cryptograph(strText: String): ByteArray {
        try {
            val encryptionKey = _key.toByteArray(StandardCharsets.UTF_8)
            val plainText = strText.toByteArray(StandardCharsets.UTF_8)
            val advancedEncryptionStandard = AdvancedEncryptionStandard(encryptionKey)
            return advancedEncryptionStandard.encrypt(plainText)
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return "error ".toByteArray()
    }

    fun Decryptograph(strText: ByteArray): String {
        try {
            val encryptionKey = _key.toByteArray(StandardCharsets.UTF_8)
            val advancedEncryptionStandard =    AdvancedEncryptionStandard(encryptionKey)
            val decryptedCipherText =    advancedEncryptionStandard.decrypt(strText)
            return String(decryptedCipherText)
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return "error"
    }
}

internal class AdvancedEncryptionStandard(private val key: ByteArray) {
    /**
     * Encrypts que explicam o texto
     *
     * @param plainText 
     */
    @Throws(Exception::class)
    fun encrypt(plainText: ByteArray): ByteArray {
        val secretKey = SecretKeySpec(key, ALGORITHM)
        val cipher = Cipher.getInstance(ALGORITHM)
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        return cipher.doFinal(plainText)
    }

    /**
     * Descrever o que vier de byte em array
     *
     * @param cipherText O dado para descriptação
     */
    @Throws(Exception::class)
    fun decrypt(cipherText: ByteArray): ByteArray {
        val secretKey = SecretKeySpec(key, ALGORITHM)
        val cipher = Cipher.getInstance(ALGORITHM)
        cipher.init(Cipher.DECRYPT_MODE, secretKey)
        return cipher.doFinal(cipherText)
    }

    companion object {
        private val ALGORITHM = "AES/ECB/NOPADDING"
    }
}
