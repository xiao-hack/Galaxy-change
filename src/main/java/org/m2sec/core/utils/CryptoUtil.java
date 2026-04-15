package org.m2sec.core.utils;

import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.RC4Engine;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.math.ec.ECPoint;
import org.m2sec.core.common.Constants;
import org.m2sec.core.common.XXTEATools;
import org.m2sec.core.enums.SymmetricKeyMode;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Map;

/**
 * @author: outlaws-bai
 * @date: 2024/6/21 20:23
 * @description:
 */
public class CryptoUtil {

    public static final String ALGORITHM_DES = "DES";
    public static final String ALGORITHM_DES_DEFAULT_TRANSFORMATION = "DES/ECB/PKCS5Padding";
    public static final String ALGORITHM_DES3 = "DESede";
    public static final String ALGORITHM_DES3_DEFAULT_TRANSFORMATION = "DESede/ECB/PKCS5Padding";
    public static final String ALGORITHM_AES = "AES";
    public static final String ALGORITHM_AES_DEFAULT_TRANSFORMATION = "AES/ECB/PKCS5Padding";
    public static final String ALGORITHM_RSA = "RSA";
    public static final String ALGORITHM_EC = "EC";
    public static final String ALGORITHM_SM2 = "SM2";
    public static final String ALGORITHM_SM4 = "SM4";
    public static final String ALGORITHM_SM4_DEFAULT_TRANSFORMATION = "SM4/ECB/PKCS5Padding";

    public static final String ALGORITHM_XXTEA = "XXTEA";

    public static byte[] desEncrypt(
            String transformation, Object data, Object secret, Map<String, Object> params) {
        return symmetricKeyEncrypt(
                transformation,
                data,
                secret,
                params,
                ALGORITHM_DES,
                ALGORITHM_DES_DEFAULT_TRANSFORMATION);
    }

    public static byte[] desDecrypt(
            String transformation, Object data, Object secret, Map<String, Object> params) {
        return symmetricKeyDecrypt(
                transformation,
                data,
                secret,
                params,
                ALGORITHM_DES,
                ALGORITHM_DES_DEFAULT_TRANSFORMATION);
    }

    public static byte[] des3Encrypt(
            String transformation, Object data, Object secret, Map<String, Object> params) {
        return symmetricKeyEncrypt(
                transformation,
                data,
                secret,
                params,
                ALGORITHM_DES3,
                ALGORITHM_DES3_DEFAULT_TRANSFORMATION);
    }

    public static byte[] des3Decrypt(
            String transformation, Object data, Object secret, Map<String, Object> params) {
        return symmetricKeyDecrypt(
                transformation,
                data,
                secret,
                params,
                ALGORITHM_DES3,
                ALGORITHM_DES3_DEFAULT_TRANSFORMATION);
    }

    public static byte[] aesEncrypt(
            String transformation, Object data, Object secret, Map<String, Object> params) {
        return symmetricKeyEncrypt(
                transformation,
                data,
                secret,
                params,
                ALGORITHM_AES,
                ALGORITHM_AES_DEFAULT_TRANSFORMATION);
    }

    public static byte[] aesDecrypt(
            String transformation, Object data, Object secret, Map<String, Object> params) {
        return symmetricKeyDecrypt(
                transformation,
                data,
                secret,
                params,
                ALGORITHM_AES,
                ALGORITHM_AES_DEFAULT_TRANSFORMATION);
    }

    public static byte[] rc4Encrypt(Object data, Object key) {
        return rc4Crypt(toJavaBytes(data), toJavaBytes(key), true);
    }

    public static byte[] rc4Decrypt(Object data, Object key) {
        return rc4Crypt(toJavaBytes(data), toJavaBytes(key), false);
    }

    private static byte[] rc4Crypt(byte[] data, byte[] key, boolean encrypt) {
        try {
            RC4Engine rc4Engine = new RC4Engine();
            KeyParameter keyParam = new KeyParameter(key);
            rc4Engine.init(encrypt, keyParam);

            byte[] output = new byte[data.length];
            rc4Engine.processBytes(data, 0, data.length, output, 0);
            return output;
        } catch (Exception e) {
            throw new RuntimeException("RC4 processing error", e);
        }
    }

    public static byte[] rsaEncrypt(byte[] data, byte[] publicKey) {
        return rsaEncrypt(ALGORITHM_RSA, data, publicKey);
    }

    public static byte[] rsaDecrypt(byte[] data, byte[] privateKey) {
        return rsaDecrypt(ALGORITHM_RSA, data, privateKey);
    }

    public static byte[] rsaEncrypt(String transformation, byte[] data, byte[] publicKey) {
        try {
            PublicKey pubKey =
                    KeyFactory.getInstance(ALGORITHM_RSA)
                            .generatePublic(new X509EncodedKeySpec(publicKey));
            Cipher cipher = Cipher.getInstance(transformation, Constants.CRYPTO_PROVIDER);
            cipher.init(Cipher.ENCRYPT_MODE, pubKey);

            int keyLen = ((RSAPublicKey) pubKey).getModulus().bitLength() / 8;
            // 计算最大明文分块长度
            int maxBlockSize = keyLen - 11; // 默认 PKCS1Padding 占用 11 字节
            String transUpper = transformation.toUpperCase();
            if (transUpper.contains("NOPADDING")) {
                maxBlockSize = keyLen;
            } else if (transUpper.contains("OAEP")) {
                maxBlockSize = keyLen - 42; // OAEPPadding 占用较多空间
            }

            ByteArrayOutputStream out = new ByteArrayOutputStream();
            int offSet = 0;
            while (data.length - offSet > 0) {
                byte[] cache;
                if (data.length - offSet > maxBlockSize) {
                    cache = cipher.doFinal(data, offSet, maxBlockSize);
                } else {
                    cache = cipher.doFinal(data, offSet, data.length - offSet);
                }
                out.write(cache, 0, cache.length);
                offSet += maxBlockSize;
            }
            return out.toByteArray();
        } catch (InvalidKeySpecException
                | NoSuchPaddingException
                | NoSuchAlgorithmException
                | IllegalBlockSizeException
                | BadPaddingException
                | InvalidKeyException
                | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] rsaDecrypt(String transformation, byte[] data, byte[] privateKey) {
        try {
            PrivateKey priKey =
                    KeyFactory.getInstance(ALGORITHM_RSA)
                            .generatePrivate(new PKCS8EncodedKeySpec(privateKey));
            Cipher cipher = Cipher.getInstance(transformation, Constants.CRYPTO_PROVIDER);
            cipher.init(Cipher.DECRYPT_MODE, priKey);

            int keyLen = ((RSAPrivateKey) priKey).getModulus().bitLength() / 8;
            // RSA 密文分块长度固定为密钥长度
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            int offSet = 0;
            while (data.length - offSet > 0) {
                byte[] cache;
                if (data.length - offSet > keyLen) {
                    cache = cipher.doFinal(data, offSet, keyLen);
                } else {
                    cache = cipher.doFinal(data, offSet, data.length - offSet);
                }
                out.write(cache, 0, cache.length);
                offSet += keyLen;
            }
            return out.toByteArray();
        } catch (InvalidKeySpecException
                | NoSuchPaddingException
                | NoSuchAlgorithmException
                | IllegalBlockSizeException
                | BadPaddingException
                | InvalidKeyException
                | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] sm2Encrypt(Object data, Object publicKey) {
        return sm2Crypt(toJavaBytes(data), toJavaBytes(publicKey), "c1c2c3", true);
    }

    public static byte[] sm2Decrypt(Object data, Object privateKey) {
        return sm2Crypt(toJavaBytes(data), toJavaBytes(privateKey), "c1c2c3", false);
    }

    public static byte[] sm2Encrypt(String mode, Object data, Object publicKey) {
        return sm2Crypt(toJavaBytes(data), toJavaBytes(publicKey), mode, true);
    }

    public static byte[] sm2Decrypt(String mode, Object data, Object privateKey) {
        return sm2Crypt(toJavaBytes(data), toJavaBytes(privateKey), mode, false);
    }

    private static byte[] sm2Crypt(byte[] data, byte[] key, String modeString, boolean isEncrypt) {
        try {
            SM2Engine.Mode mode =
                    (modeString != null && modeString.equalsIgnoreCase(SM2Engine.Mode.C1C3C2.name()))
                            ? SM2Engine.Mode.C1C3C2
                            : SM2Engine.Mode.C1C2C3;

            if (!isEncrypt && data.length > 0) {
                // 1. 处理 ASN.1 (DER)
                if (data[0] == 0x30) {
                    data = transformSm2Ciphertext(data, mode);
                }
                // 2. 如果是 128 字节原始格式，通常对应 32 字节明文。无论首字节是什么，都应补齐 0x04 前缀。
                // 即使首字节恰好是 0x04，它也极大概率是 X 坐标的一部分，而不是 SM2 标记位。
                else if (data.length == 128) {
                    data = ByteUtil.concatenateByteArrays(new byte[] {0x04}, data);
                }
                // 3. 特征判断：对于非 128 字节的数据，如果不带合法前缀，则补齐 0x04
                else if (data[0] != 0x04 && data[0] != 0x02 && data[0] != 0x03) {
                    data = ByteUtil.concatenateByteArrays(new byte[] {0x04}, data);
                }
            }

            CipherParameters param = getSm2CipherParameters(key, isEncrypt);
            SM2Engine sm2Engine = new SM2Engine(mode);
            sm2Engine.init(isEncrypt, param);
            return sm2Engine.processBlock(data, 0, data.length);
        } catch (Exception e) {
            throw new RuntimeException(
                    "SM2 operation failed (Data Length: "
                            + (data == null ? 0 : data.length)
                            + ", First Byte: "
                            + (data != null && data.length > 0
                                    ? String.format("0x%02x", data[0])
                                    : "none")
                            + "): "
                            + e.getMessage(),
                    e);
        }
    }

    private static byte[] transformSm2Ciphertext(byte[] data, SM2Engine.Mode mode) {
        try {
            org.bouncycastle.asn1.ASN1Sequence seq =
                    org.bouncycastle.asn1.ASN1Sequence.getInstance(data);
            org.bouncycastle.asn1.ASN1Integer x =
                    org.bouncycastle.asn1.ASN1Integer.getInstance(seq.getObjectAt(0));
            org.bouncycastle.asn1.ASN1Integer y =
                    org.bouncycastle.asn1.ASN1Integer.getInstance(seq.getObjectAt(1));
            byte[] c3, c2;
            if (mode == SM2Engine.Mode.C1C3C2) {
                c3 = org.bouncycastle.asn1.ASN1OctetString.getInstance(seq.getObjectAt(2)).getOctets();
                c2 = org.bouncycastle.asn1.ASN1OctetString.getInstance(seq.getObjectAt(3)).getOctets();
            } else {
                c2 = org.bouncycastle.asn1.ASN1OctetString.getInstance(seq.getObjectAt(2)).getOctets();
                c3 = org.bouncycastle.asn1.ASN1OctetString.getInstance(seq.getObjectAt(3)).getOctets();
            }

            // 关键：强制将 X 和 Y 转换为 32 字节，处理 BigInteger 可能产生的 33 字节问题
            byte[] xBuf = fixSize(x.getValue().toByteArray(), 32);
            byte[] yBuf = fixSize(y.getValue().toByteArray(), 32);

            if (mode == SM2Engine.Mode.C1C3C2) {
                return ByteUtil.concatenateByteArrays(new byte[] {0x04}, xBuf, yBuf, c3, c2);
            } else {
                return ByteUtil.concatenateByteArrays(new byte[] {0x04}, xBuf, yBuf, c2, c3);
            }
        } catch (Exception e) {
            return data;
        }
    }

    private static byte[] fixSize(byte[] data, int size) {
        if (data.length == size) return data;
        byte[] result = new byte[size];
        if (data.length > size) {
            System.arraycopy(data, data.length - size, result, 0, size);
        } else {
            System.arraycopy(data, 0, result, size - data.length, data.length);
        }
        return result;
    }

    private static CipherParameters getSm2CipherParameters(byte[] key, boolean isEncrypt) {
        CipherParameters param;
        try {
            if (isEncrypt) {
                if (key.length == 64 || key.length == 65) {
                    if (key.length == 64)
                        key = ByteUtil.concatenateByteArrays(new byte[] {0x04}, key);
                    X9ECParameters sm2ECParameters = GMNamedCurves.getByName("sm2p256v1");
                    ECDomainParameters domainParameters =
                            new ECDomainParameters(
                                    sm2ECParameters.getCurve(),
                                    sm2ECParameters.getG(),
                                    sm2ECParameters.getN());
                    ECPoint pukPoint = sm2ECParameters.getCurve().decodePoint(key);
                    param =
                            new ParametersWithRandom(
                                    new ECPublicKeyParameters(pukPoint, domainParameters),
                                    new SecureRandom());
                }
                //                else if (key.length ==) { // 待补充
                //
                //                }
                else if (key.length == 91) {
                    KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM_EC);
                    X509EncodedKeySpec keySpec = new X509EncodedKeySpec(key);
                    BCECPublicKey publicKey = (BCECPublicKey) keyFactory.generatePublic(keySpec);
                    ECPoint q = publicKey.getQ();
                    ECDomainParameters domainParameters =
                            new ECDomainParameters(
                                    publicKey.getParameters().getCurve(),
                                    publicKey.getParameters().getG(),
                                    publicKey.getParameters().getN(),
                                    publicKey.getParameters().getH());
                    param =
                            new ParametersWithRandom(
                                    new ECPublicKeyParameters(q, domainParameters),
                                    new SecureRandom());
                } else {
                    throw new InvalidParameterException(
                            "Unknown public key, please try extracting the original "
                                    + "public key from it and then try again.");
                }
            } else {
                if (key.length == 32 || key.length == 33) {
                    if (key.length == 33) key = ByteUtil.removePrefixIfExists(key, (byte) 0x04);
                    X9ECParameters sm2ECParameters = GMNamedCurves.getByName("sm2p256v1");
                    ECDomainParameters domainParameters =
                            new ECDomainParameters(
                                    sm2ECParameters.getCurve(),
                                    sm2ECParameters.getG(),
                                    sm2ECParameters.getN());
                    param = new ECPrivateKeyParameters(new BigInteger(1, key), domainParameters);
                } else if (key.length == 121) {
                    key = ByteUtil.subBytes(key, 7, 7 + 32);
                    param = getSm2CipherParameters(key, false);
                } else if (key.length == 150) {
                    BCECPrivateKey priKey =
                            (BCECPrivateKey)
                                    KeyFactory.getInstance(ALGORITHM_EC)
                                            .generatePrivate(new PKCS8EncodedKeySpec(key));
                    BigInteger d = priKey.getD();
                    ECDomainParameters domainParameters =
                            new ECDomainParameters(
                                    priKey.getParameters().getCurve(),
                                    priKey.getParameters().getG(),
                                    priKey.getParameters().getN(),
                                    priKey.getParameters().getH());
                    param = new ECPrivateKeyParameters(d, domainParameters);
                } else {
                    throw new InvalidParameterException(
                            "Unknown private key, please try extracting the original "
                                    + "private key from it and then try again.");
                }
            }
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
        return param;
    }

    public static byte[] teaEncrypt(String transformation, Object data, Object secret) {
        byte[] dataBytes = toJavaBytes(data);
        byte[] secretBytes = toJavaBytes(secret);
        if (transformation != null
                && !transformation.isBlank()
                && transformation.equalsIgnoreCase(ALGORITHM_XXTEA))
            return XXTEATools.encrypt(dataBytes, secretBytes);
        return symmetricKeyEncrypt(
                transformation, dataBytes, secretBytes, null, transformation, transformation);
    }

    public static byte[] teaDecrypt(String transformation, Object data, Object secret) {
        byte[] dataBytes = toJavaBytes(data);
        byte[] secretBytes = toJavaBytes(secret);
        if (transformation != null
                && !transformation.isBlank()
                && transformation.equalsIgnoreCase(ALGORITHM_XXTEA))
            return XXTEATools.decrypt(dataBytes, secretBytes);
        return symmetricKeyDecrypt(
                transformation, dataBytes, secretBytes, null, transformation, transformation);
    }

    public static byte[] sm4Encrypt(
            String transformation, Object data, Object secret, Map<String, Object> params) {
        return symmetricKeyEncrypt(
                transformation,
                data,
                secret,
                params,
                ALGORITHM_SM4,
                ALGORITHM_SM4_DEFAULT_TRANSFORMATION);
    }

    public static byte[] sm4Decrypt(
            String transformation, Object data, Object secret, Map<String, Object> params) {
        return symmetricKeyDecrypt(
                transformation,
                data,
                secret,
                params,
                ALGORITHM_SM4,
                ALGORITHM_SM4_DEFAULT_TRANSFORMATION);
    }

    private static byte[] symmetricKeyEncrypt(
            String transformation,
            Object data,
            Object secret,
            Map<String, Object> params,
            String algorithm,
            String algorithmDefaultTransformation) {
        byte[] dataBytes = toJavaBytes(data);
        byte[] secretBytes = toJavaBytes(secret);
        try {
            String finalTransformation =
                    transformation != null && !algorithm.equals(transformation)
                            ? transformation
                            : algorithmDefaultTransformation;
            Cipher cipher = Cipher.getInstance(finalTransformation, Constants.CRYPTO_PROVIDER);
            SecretKeySpec keySpec = new SecretKeySpec(secretBytes, algorithm);
            AlgorithmParameterSpec paramSpec =
                    getSymmetricKeyEncryptParameterSpec(finalTransformation, params);
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, paramSpec);
            return cipher.doFinal(dataBytes);
        } catch (NoSuchAlgorithmException
                | NoSuchPaddingException
                | InvalidAlgorithmParameterException
                | IllegalBlockSizeException
                | BadPaddingException
                | InvalidKeyException
                | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] symmetricKeyDecrypt(
            String transformation,
            Object data,
            Object secret,
            Map<String, Object> params,
            String algorithm,
            String algorithmDefaultTransformation) {
        byte[] dataBytes = toJavaBytes(data);
        byte[] secretBytes = toJavaBytes(secret);
        try {
            String finalTransformation =
                    transformation != null && !algorithm.equals(transformation)
                            ? transformation
                            : algorithmDefaultTransformation;
            Cipher cipher = Cipher.getInstance(finalTransformation, Constants.CRYPTO_PROVIDER);
            SecretKeySpec keySpec = new SecretKeySpec(secretBytes, algorithm);
            AlgorithmParameterSpec paramSpec =
                    getSymmetricKeyEncryptParameterSpec(finalTransformation, params);
            cipher.init(Cipher.DECRYPT_MODE, keySpec, paramSpec);
            return cipher.doFinal(dataBytes);
        } catch (NoSuchAlgorithmException
                | NoSuchPaddingException
                | InvalidAlgorithmParameterException
                | IllegalBlockSizeException
                | BadPaddingException
                | InvalidKeyException
                | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
    }

    private static AlgorithmParameterSpec getSymmetricKeyEncryptParameterSpec(
            String transformation, Map<String, Object> params) {
        if (!transformation.contains("/")) return null;

        String[] parts = transformation.split("/");
        if (parts.length < 2) return null;

        String modeStr = parts[1];
        SymmetricKeyMode symmetricKeyMode = SymmetricKeyMode.valueOf(modeStr);

        switch (symmetricKeyMode) {
            case ECB:
                return null;
            case CBC:
            case CFB:
            case OFB:
            case CTR:
                // 这些模式都使用IV参数
                return new IvParameterSpec(getSymmetricKeyEncryptIv(params));
            case GCM:
                byte[] ivBytes = getSymmetricKeyEncryptIv(params);
                Integer tLen = (Integer) params.get("tLen");
                tLen = tLen == null ? 128 : tLen;
                return new GCMParameterSpec(tLen, ivBytes);
            default:
                throw new IllegalArgumentException("Unsupported mode: " + modeStr);
        }
    }

    private static byte[] getSymmetricKeyEncryptIv(Map<String, Object> params) {
        if (params == null) {
            throw new IllegalArgumentException("IV parameter is required for this mode");
        }
        Object ivObj = params.get("iv");
        if (ivObj == null) {
            throw new IllegalArgumentException("IV parameter is required for this mode");
        }
        return toJavaBytes(ivObj);
    }

    private static byte[] toJavaBytes(Object data) {
        if (data == null) return null;
        if (data instanceof byte[]) return (byte[]) data;
        if (data instanceof String) return ((String) data).getBytes(java.nio.charset.StandardCharsets.UTF_8);
        if (data instanceof java.util.Collection) {
            java.util.Collection<?> col = (java.util.Collection<?>) data;
            byte[] bytes = new byte[col.size()];
            int i = 0;
            for (Object item : col) {
                if (item instanceof Number) {
                    bytes[i++] = ((Number) item).byteValue();
                }
            }
            return bytes;
        }
        if (data.getClass().isArray()) {
            int length = java.lang.reflect.Array.getLength(data);
            byte[] bytes = new byte[length];
            for (int i = 0; i < length; i++) {
                Object item = java.lang.reflect.Array.get(data, i);
                if (item instanceof Number) {
                    bytes[i] = ((Number) item).byteValue();
                }
            }
            return bytes;
        }
        throw new IllegalArgumentException("Unsupported data type for byte array conversion: " + data.getClass().getName());
    }
}