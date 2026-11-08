package com.ximalaya;

import com.github.unidbg.Emulator;
import com.github.unidbg.file.FileResult;
import com.github.unidbg.file.IOResolver;
import com.github.unidbg.linux.file.ByteArrayFileIO;

public class TestIOResolver implements IOResolver {
    @Override
    public FileResult resolve(Emulator emulator, String pathname, int oflags) {
        if ("/proc/self/maps".equals(pathname)) {
            System.out.println("IoResolve ------->proc/self/maps");
            return FileResult.success(new ByteArrayFileIO(oflags, pathname, "myIoResolver".getBytes()));
            //return FileResult.success(new SimpleFileIO(oflags, new File("xxx"), pathname));
        }
        return null;
    }
}