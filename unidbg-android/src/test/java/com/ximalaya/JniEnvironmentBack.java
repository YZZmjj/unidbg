package com.ximalaya;

import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.linux.android.dvm.array.ByteArray;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Locale;

public class JniEnvironmentBack extends AbstractJni {


    @Override
    public DvmObject<?> callStaticObjectMethod(BaseVM vm, DvmClass dvmClass,
                                               String signature, VarArg args) {
        if ("java/lang/Integer->toHexString(I)Ljava/lang/String;".equals(signature)) {
            return new StringObject(vm, Integer.toHexString(args.getIntArg(0)));
        }
        if ("java/security/KeyFactory->getInstance(Ljava/lang/String;)Ljava/security/KeyFactory;"
                .equals(signature)) {
            StringObject algorithm = args.getObjectArg(0);
            try {
                return dvmClass.newObject(KeyFactory.getInstance(algorithm.getValue()));
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException(e);
            }
        }
        if ("android/util/Base64->decode(Ljava/lang/String;I)[B".equals(signature)) {
            StringObject encoded = args.getObjectArg(0);
            return new ByteArray(vm, Base64.getMimeDecoder().decode(encoded.getValue()));
        }
        if ("android/util/Base64->encodeToString([BI)Ljava/lang/String;".equals(signature)) {
            ByteArray bytes = args.getObjectArg(0);
            int flags = args.getIntArg(1);
            if (flags != 0) {
                throw new UnsupportedOperationException("Base64 flags=" + flags);
            }
            String encoded = Base64.getMimeEncoder(76, new byte[]{'\n'})
                    .encodeToString(bytes.getValue()) + "\n";
            return new StringObject(vm, encoded);
        }
        if ("javax/crypto/Cipher->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;"
                .equals(signature)) {
            StringObject transformation = args.getObjectArg(0);
            try {
                return dvmClass.newObject(Cipher.getInstance(transformation.getValue()));
            } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
                throw new IllegalStateException(e);
            }
        }
        if ("java/security/MessageDigest->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;"
                .equals(signature)) {
            StringObject algorithm = args.getObjectArg(0);
            try {
                return dvmClass.newObject(MessageDigest.getInstance(algorithm.getValue()));
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException(e);
            }
        }
        return super.callStaticObjectMethod(vm, dvmClass, signature, args);
    }

    @Override
    public DvmObject<?> newObject(BaseVM vm, DvmClass dvmClass,
                                  String signature, VarArg args) {
        if ("java/lang/StringBuilder-><init>()V".equals(signature)) {
            return dvmClass.newObject(new StringBuilder());
        }
        if ("java/io/ByteArrayOutputStream-><init>()V".equals(signature)) {
            return dvmClass.newObject(new ByteArrayOutputStream());
        }
        if ("java/security/spec/X509EncodedKeySpec-><init>([B)V".equals(signature)) {
            ByteArray encoded = args.getObjectArg(0);
            return dvmClass.newObject(new X509EncodedKeySpec(encoded.getValue()));
        }
        return super.newObject(vm, dvmClass, signature, args);
    }

    @Override
    public DvmObject<?> callObjectMethod(BaseVM vm, DvmObject<?> receiver,
                                         String signature, VarArg args) {
        if ("java/security/MessageDigest->digest()[B".equals(signature)) {
            return new ByteArray(vm, ((MessageDigest) receiver.getValue()).digest());
        }
        if ("java/lang/StringBuilder->append(Ljava/lang/String;)Ljava/lang/StringBuilder;"
                .equals(signature)) {
            StringBuilder builder = (StringBuilder) receiver.getValue();
            StringObject value = args.getObjectArg(0);
            builder.append(value.getValue());
            return receiver;
        }
        if ("java/lang/StringBuilder->append(I)Ljava/lang/StringBuilder;".equals(signature)) {
            ((StringBuilder) receiver.getValue()).append(args.getIntArg(0));
            return receiver;
        }
        if ("java/lang/StringBuilder->toString()Ljava/lang/String;".equals(signature)) {
            return new StringObject(vm, receiver.getValue().toString());
        }
        if ("java/lang/String->toUpperCase()Ljava/lang/String;".equals(signature)) {
            StringObject value = (StringObject) receiver;
            return new StringObject(vm, value.getValue().toUpperCase(Locale.ROOT));
        }
        if ("java/io/ByteArrayOutputStream->toByteArray()[B".equals(signature)) {
            ByteArrayOutputStream stream = (ByteArrayOutputStream) receiver.getValue();
            return new ByteArray(vm, stream.toByteArray());
        }
        if ("javax/crypto/Cipher->doFinal([BII)[B".equals(signature)) {
            Cipher cipher = (Cipher) receiver.getValue();
            ByteArray input = args.getObjectArg(0);
            try {
                return new ByteArray(vm, cipher.doFinal(input.getValue(),
                        args.getIntArg(1), args.getIntArg(2)));
            } catch (IllegalBlockSizeException | BadPaddingException e) {
                throw new IllegalStateException(e);
            }
        }
        if ("java/security/KeyFactory->generatePublic(Ljava/security/spec/KeySpec;)Ljava/security/PublicKey;"
                .equals(signature)) {
            KeyFactory factory = (KeyFactory) receiver.getValue();
            DvmObject<?> spec = args.getObjectArg(0);
            try {
                return vm.resolveClass("java/security/PublicKey").newObject(
                        factory.generatePublic((X509EncodedKeySpec) spec.getValue()));
            } catch (InvalidKeySpecException e) {
                throw new IllegalStateException(e);
            }
        }
        if ("java/security/PublicKey->getModulus()Ljava/math/BigInteger;".equals(signature)) {
            RSAPublicKey key = (RSAPublicKey) receiver.getValue();
            return vm.resolveClass("java/math/BigInteger").newObject(key.getModulus());
        }
        return super.callObjectMethod(vm, receiver, signature, args);
    }

    @Override
    public int callIntMethod(BaseVM vm, DvmObject<?> receiver,
                             String signature, VarArg args) {
        if ("java/lang/String->length()I".equals(signature)) {
            return ((StringObject) receiver).getValue().length();
        }
        if ("java/math/BigInteger->bitLength()I".equals(signature)) {
            return ((BigInteger) receiver.getValue()).bitLength();
        }
        return super.callIntMethod(vm, receiver, signature, args);
    }

    @Override
    public void callVoidMethod(BaseVM vm, DvmObject<?> receiver,
                               String signature, VarArg args) {
        if ("java/security/MessageDigest->update([B)V".equals(signature)) {
            MessageDigest digest = (MessageDigest) receiver.getValue();
            ByteArray bytes = args.getObjectArg(0);
            digest.update(bytes.getValue());
            return;
        }
        if ("java/io/ByteArrayOutputStream->write([B)V".equals(signature)) {
            ByteArrayOutputStream stream = (ByteArrayOutputStream) receiver.getValue();
            ByteArray bytes = args.getObjectArg(0);
            stream.write(bytes.getValue(), 0, bytes.getValue().length);
            return;
        }
        if ("java/io/ByteArrayOutputStream->close()V".equals(signature)) {
            return;
        }
        if ("javax/crypto/Cipher->init(ILjava/security/Key;)V".equals(signature)) {
            Cipher cipher = (Cipher) receiver.getValue();
            DvmObject<?> key = args.getObjectArg(1);
            try {
                cipher.init(args.getIntArg(0), (Key) key.getValue());
            } catch (InvalidKeyException e) {
                throw new IllegalStateException(e);
            }
            return;
        }
        super.callVoidMethod(vm, receiver, signature, args);
    }
}
