package com.ximalaya;

import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.linux.android.dvm.array.ByteArray;

import javax.crypto.Cipher;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class JniEnvironment extends AbstractJni {

    @Override
    public DvmObject<?> callStaticObjectMethod(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArgs) {
        switch (signature) {
            case "java/security/KeyFactory->getInstance(Ljava/lang/String;)Ljava/security/KeyFactory;":
                try {
                    DvmObject<String> stringDvmObject = varArgs.getObjectArg(0);
                    KeyFactory instance = KeyFactory.getInstance(stringDvmObject.getValue());
                    return dvmClass.newObject(instance);
                } catch (Exception e) {
                    throw new IllegalStateException("KeyFactory.getInstance failed", e);
                }
            case "android/util/Base64->decode(Ljava/lang/String;I)[B":
                DvmObject<String> arg0 = varArgs.getObjectArg(0);
                byte[] decode = Base64.getMimeDecoder().decode(arg0.getValue());
                return new ByteArray(vm, decode);
            case "javax/crypto/Cipher->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;":
                try {
                    String str = (String) varArgs.getObjectArg(0).getValue();
                    Cipher cipher = Cipher.getInstance(str);
                    return dvmClass.newObject(cipher);
                } catch (Exception e) {
                    throw new RuntimeException("Cipher.getInstance failed", e);
                }
            case "android/util/Base64->encodeToString([BI)Ljava/lang/String;": {
                byte[] bytes = (byte[]) varArgs.getObjectArg(0).getValue();
                int flags = varArgs.getIntArg(1);
                Base64.Encoder encoder = (flags & 8) != 0
                        ? Base64.getUrlEncoder() : Base64.getEncoder();
                if ((flags & 1) != 0) {
                    encoder = encoder.withoutPadding();
                }
                String s = encoder.encodeToString(bytes);
                if ((flags & 2) == 0 && !s.isEmpty()) {
                    String newline = (flags & 4) != 0 ? "\r\n" : "\n";
                    StringBuilder wrapped = new StringBuilder();
                    for (int i = 0; i < s.length(); i += 76) {
                        wrapped.append(s, i, Math.min(i + 76, s.length())).append(newline);
                    }
                    s = wrapped.toString();
                }
                return new StringObject(vm, s);
            }
            case "java/security/MessageDigest->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;":
                try {
                    String str = (String) varArgs.getObjectArg(0).getValue();
                    MessageDigest instance = MessageDigest.getInstance(str);
                    return dvmClass.newObject(instance);
                } catch (NoSuchAlgorithmException e) {
                    throw new RuntimeException("java/security/MessageDigest->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;" + e);
                }
            case "java/lang/Integer->toHexString(I)Ljava/lang/String;":
                int intArg1 = varArgs.getIntArg(0);
                String hexString = Integer.toHexString(intArg1);
                return new StringObject(vm, hexString);
        }
        return super.callStaticObjectMethod(vm, dvmClass, signature, varArgs);
    }


    @Override
    public DvmObject<?> newObject(BaseVM vm, DvmClass dvmClass, String signature, VarArg varArg) {
        switch (signature) {
            case "java/security/spec/X509EncodedKeySpec-><init>([B)V":
                ByteArray byteArray = varArg.getObjectArg(0);
                return dvmClass.newObject(new X509EncodedKeySpec(byteArray.getValue()));
            case "java/io/ByteArrayOutputStream-><init>()V":
                ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
                return dvmClass.newObject(byteArrayOutputStream);
            case "java/lang/StringBuilder-><init>()V":
                return dvmClass.newObject(new StringBuilder());
        }
        return super.newObject(vm, dvmClass, signature, varArg);
    }

    @Override
    public DvmObject<?> callObjectMethod(BaseVM vm, DvmObject<?> dvmObject, String signature, VarArg varArg) {
        switch (signature) {
            case "java/security/KeyFactory->generatePublic(Ljava/security/spec/KeySpec;)Ljava/security/PublicKey;":
                try {
                    KeySpec keySpec = (KeySpec) varArg.getObjectArg(0).getValue();
                    KeyFactory keyFactory = (KeyFactory) dvmObject.getValue();
                    PublicKey publicKey = keyFactory.generatePublic(keySpec);
                    return vm.resolveClass("java/security/PublicKey").newObject(publicKey);
                } catch (InvalidKeySpecException e) {
                    throw new RuntimeException("KeyFactory->generatePublic failed " + e);
                }
            case "java/security/PublicKey->getModulus()Ljava/math/BigInteger;":
                // 实际值是 RSA 公钥；getModulus 来自 RSAPublicKey 继承的 RSAKey。
                RSAPublicKey publicKey = (RSAPublicKey) dvmObject.getValue();
                BigInteger modulus = publicKey.getModulus();
                return vm.resolveClass("java/math/BigInteger").newObject(modulus);

            case "javax/crypto/Cipher->doFinal([BII)[B":
                try {
                    byte[] byteArray = (byte[]) varArg.getObjectArg(0).getValue();
                    int intArg1 = varArg.getIntArg(1);
                    int intArg2 = varArg.getIntArg(2);
                    Cipher cipher = (Cipher) dvmObject.getValue();
                    return new ByteArray(vm, cipher.doFinal(byteArray, intArg1, intArg2));
                } catch (Exception e) {
                    throw new RuntimeException("javax/crypto/Cipher->doFinal([BII)[B fail" + e);
                }
            case "java/io/ByteArrayOutputStream->toByteArray()[B":
                ByteArrayOutputStream byteArrayOutputStream = (ByteArrayOutputStream) dvmObject.getValue();
                byte[] byteArray = byteArrayOutputStream.toByteArray();
                return new ByteArray(vm, byteArray);
            case "java/lang/String->toUpperCase()Ljava/lang/String;":
                String string = (String) dvmObject.getValue();
                String upperCase = string.toUpperCase();
                return new StringObject(vm, upperCase);

            case "java/security/MessageDigest->digest()[B":
                MessageDigest messageDigest = (MessageDigest) dvmObject.getValue();
                byte[] digest = messageDigest.digest();
                return new ByteArray(vm, digest);

            case "java/lang/StringBuilder->append(Ljava/lang/String;)Ljava/lang/StringBuilder;":
                String string1 = (String) varArg.getObjectArg(0).getValue();
                StringBuilder sb = (StringBuilder) dvmObject.getValue();
                sb.append(string1);
                return dvmObject;

            case "java/lang/StringBuilder->append(I)Ljava/lang/StringBuilder;":
                int intArg = varArg.getIntArg(0);
                StringBuilder sb1 = (StringBuilder) dvmObject.getValue();
                sb1.append(intArg);
                return dvmObject;

            case "java/lang/StringBuilder->toString()Ljava/lang/String;":
                StringBuilder sb2 = (StringBuilder) dvmObject.getValue();
                return new StringObject(vm, sb2.toString());

        }
        return super.callObjectMethod(vm, dvmObject, signature, varArg);
    }

    @Override
    public int callIntMethod(BaseVM vm, DvmObject<?> dvmObject, String signature, VarArg varArg) {
        switch (signature) {
            case "java/math/BigInteger->bitLength()I":
                BigInteger bigInteger = (BigInteger) dvmObject.getValue();
                return bigInteger.bitLength();
            case "java/lang/String->length()I":
                String value = (String) dvmObject.getValue();
                return value.length();
        }
        return super.callIntMethod(vm, dvmObject, signature, varArg);
    }

    @Override
    public void callVoidMethod(BaseVM vm, DvmObject<?> dvmObject, String signature, VarArg varArg) {
        switch (signature) {
            case "javax/crypto/Cipher->init(ILjava/security/Key;)V":
                try {
                    int intArg = varArg.getIntArg(0);
                    Key key = (Key) varArg.getObjectArg(1).getValue();
                    Cipher cipher = (Cipher) dvmObject.getValue();
                    cipher.init(intArg, key);
                    return;
                } catch (Exception e) {
                    throw new RuntimeException("Cipher->init(ILjava/security/Key;)V" + e);
                }
            case "java/io/ByteArrayOutputStream->write([B)V":
                try {
                    byte[] bytes = (byte[]) varArg.getObjectArg(0).getValue();
                    ByteArrayOutputStream byteArrayOutputStream = (ByteArrayOutputStream) dvmObject.getValue();
                    byteArrayOutputStream.write(bytes);
                    return;
                } catch (IOException e) {
                    throw new RuntimeException("java/io/ByteArrayOutputStream->write([B)V fail" + e);
                }
            case "java/io/ByteArrayOutputStream->close()V":
                try {
                    ByteArrayOutputStream byteArrayOutputStream = (ByteArrayOutputStream) dvmObject.getValue();
                    byteArrayOutputStream.close();
                    return;
                } catch (IOException e) {
                    throw new RuntimeException("java/io/ByteArrayOutputStream->close()V" + e);
                }

            case "java/security/MessageDigest->update([B)V":
                byte[] bytes = (byte[]) varArg.getObjectArg(0).getValue();
                MessageDigest messageDigest = (MessageDigest) dvmObject.getValue();
                messageDigest.update(bytes);
                return;

        }
        super.callVoidMethod(vm, dvmObject, signature, varArg);
    }
}
