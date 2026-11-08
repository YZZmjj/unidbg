package com.ximalaya;

import com.alibaba.fastjson.util.IOUtils;
import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.debugger.Debugger;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.virtualmodule.android.AndroidModule;
import com.github.unidbg.virtualmodule.android.JniGraphics;
import com.xStudyDemo.TestIOResolver;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.PrintStream;

/**
 * Created with IntelliJ IDEA.
 * Author: pp
 * Date: 2026/10/03/12:32
 * Description:
 * ximalaya , first app
 */
public class LoginEncryptUtil extends AbstractJni {
    static private AndroidEmulator emulator;
    private final VM vm;
    static private Module module = null;
    static private Memory memory = null;
    final boolean logging;
    public LoginEncryptUtil(boolean logging) {
        this.logging = logging;
        System.out.println("工作目录：" + System.getProperty("user.dir"));
        emulator = AndroidEmulatorBuilder.for32Bit()
                .setProcessName("com.ximalaya.ting.android")
              //  .setRootDir(new File("target/rootfs"))   // 模拟手机文件的根路径
                .addBackendFactory(new Unicorn2Factory(true))  // 处理器类型
                .build();
        // 设置执行多少条指令切换一次线程
        emulator.getBackend().registerEmuCountHook(10000);
        // 开启日志
        emulator.getSyscallHandler().setVerbose(true);
        // 开启线程调度器
        emulator.getSyscallHandler().setEnableThreadDispatcher(true);
        memory = emulator.getMemory();// 模拟器的内存操作接口
        memory.setLibraryResolver(new AndroidResolver(23)); // 设置系统类库解
        // 创建虚拟机并指定APK文件
        vm = emulator.createDalvikVM(new File(System.getProperty("user.dir"), "unidbg-android/src/test/java/com/ximalaya/ximalaya.apk")); // 9.5.13.3
        // 设置是否打印Jni调用细节
        if(logging) {
            vm.setVerbose(true);
        }
        // 补jni方法
        vm.setJni(new JniEnvironment());//
        // 使用虚拟模块
        new JniGraphics(emulator, vm).register(memory);
        new AndroidModule(emulator, vm).register(memory);
        // 重定义IO
        emulator.getSyscallHandler().addIOResolver(new TestIOResolver());
        // 加载so
        DalvikModule dm = vm.loadLibrary(
                new File(System.getProperty("user.dir"), "unidbg-android/src/test/resources/ximalaya/liblogin_encrypt.so"), true);
        // 加载好的liblogin_encrypt对应为一个模块
        module = dm.getModule();
        // 手动执行JNI_OnLoad函数
        dm.callJNI_OnLoad(emulator);
    }

    // 追踪汇编指令
    static void traceCode() {
        String traceFile = "unidbg-android/src/test/java/com/ximalaya/traceCode.log"; // 输出的路径
        PrintStream traceStream = null; // 打印流
        try {
            traceStream = new PrintStream(new FileOutputStream(traceFile), true);
        } catch (FileNotFoundException e) {
            throw new RuntimeException(e);
        }        // traceCode 对代码进行监控
        emulator.traceCode(module.base, module.base + module.size).setRedirect(traceStream);
    }

    void traceDebugger() {
        Debugger attach = emulator.attach();
    }

    public void destroy() {
        IOUtils.close(emulator);
        if (logging) {
            System.out.println("destroy");
        }
    }

    public String accountOrPwdEncrypt(String accountOrPwd) {
        // 找到类型
        DvmClass loginEncryptUtil = vm.resolveClass("com/ximalaya/ting/android/loginservice/LoginEncryptUtil");
        // 非静态方法先创建实例
        DvmObject<?> receiver = loginEncryptUtil.newObject(null);
        StringObject encryptResult = receiver.callJniMethodObject(emulator,
                "wwXLkDFrOu(Ljava/lang/String;)Ljava/lang/String;",
                new StringObject(vm, accountOrPwd));
        if (encryptResult == null) {
            throw new IllegalStateException("wwXLkDFrOu returned null");
        }
        return encryptResult.getValue();
    }

    public String signatureEncrypt(String originalStr) {
        // 找到类型
        DvmClass loginEncryptUtil = vm.resolveClass("com/ximalaya/ting/android/loginservice/LoginEncryptUtil");
        // 非静态方法先创建实例
        DvmObject<?> receiver = loginEncryptUtil.newObject(null);

        //构建Context
        DvmClass contextClass = vm.resolveClass("android/content/Context");
        DvmClass wrapperClass  = vm.resolveClass("android/content/ContextWrapper", contextClass);
        DvmObject<?> context = vm.resolveClass("android/app/Application", wrapperClass).newObject(null);


        StringObject encryptResult = receiver.callJniMethodObject(emulator,
                "aXGGIioVBB(Landroid/content/Context;ZLjava/lang/String;)Ljava/lang/String;",
                context,false , originalStr);
        if (encryptResult == null) {
            throw new IllegalStateException("aXGGIioVBB returned null");
        }
        return encryptResult.getValue();
    }

    public static void main(String[] args) {
        LoginEncryptUtil loginEncryptUtil = new LoginEncryptUtil(true);
        String encrypted = loginEncryptUtil.accountOrPwdEncrypt("13812341234");
        System.err.println("accountOrPwdEncrypt------------>" + encrypted);

        String signature = loginEncryptUtil.signatureEncrypt("account=cjwQf0K6vTcRFiz3X9XUYQtB0Zn74KP94lmTf5TweOSiq7CNmgNtj6hlmvUf6zwUsmQAH9Mri2Jp\nbvICbotcDIAoDrvVwnmbnMme2JNksoUIV4vmmPS5jY0ruJ92LLFyJn100IgwmD9rDca60PM074a/\nVrwKc5LKBuqQD85rzdk=\n&fdsOtp={\"captcha_id\":\"3723312ce42a04b5c0b40e605a882037\",\"lot_number\":\"8a28e7b59a554ae6871a23266744f94c\",\"pass_token\":\"744b49a08e9cf8964a19800247de7799ffa8da7175086b950145b9ce3250d1ae\",\"gen_time\":\"1791270596\",\"captcha_output\":\"2Z76G2CapbcJxb3z0NRv6KrwAlogYdssi3VDWvYtMmS2NWXjMcT2Po57cKJnfd-xIgNr6L-WdKlMfwC8ULBpBdmJ_JmrGZSXlrKpoMhwSHiBCoAbEovRICaBq5B9bcdm_bDrRlk1pinB2x5yIirsqB3lYzAW1tKB9NwZgWVz6xmC9AHCFF9TTqW5moJjo5MQaQkhJ1QVk0rCD_QFen9qi6vj0nhpgKRtLixVQ6Hc_ahHOAX9hWVsiNPYzWS1VDKExyfGWOC4ErbD3y8Lq2fJSA0kCtjCFLOu8OnddKcie3ElJQUQdLv5qQ_Uo4I3Iivx_X7w8zobSspquBz5UlJLCd-wBdOwrq-WgS1urX7m2dAj_SpndgyCtUTAVhsh3kQEAz3dx9Rtnkd8Ci1_RBHYYnKBu0IL9yxoTnNHlpGm7TWJp1PwaxvRnItSm9ucfwOaaP6hI0qJYkSnBmWeMf_5zd3gSvPWBybKCe2yy7vloMxEofHTf8xCPdNnW74D0y8hjPwP5z0MUseoBgecCWzQ_FCNpMnvmIC6iHEhezUUqEE=\"}&nonce=0-634287F591C735db3cc8f158dae59349533489aad04abb6602099c8140fe05&password=VbCRChIi2vKxuB70FjeH7PK/4xennTnykz5QWXbcZMSrn3s944atdtCeoyQ67+nb7lbv4OH8N69i\nxwf1CZpo67oPcG98P4w4wee7iw45T+2nOUQ899ZLfZaB2ooaiWs2i0t0RAJBLJahFwml7jtCzhWp\nEkOftIAkg1gPfeD0U5k=\n&");
        System.err.println("signatureEncrypt------------>" + signature);
        loginEncryptUtil.destroy();
    }

    public static String bytesToHex(byte[] bytes) {
        if (bytes == null) {
            return null;
        }
        StringBuilder hexString = new StringBuilder(2 * bytes.length);
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

}
