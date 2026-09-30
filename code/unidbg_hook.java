// unidbg_hook.java —— 转译环境下用 unidbg 仿真 ARM so（可复用模板）
// 后端必须用 Unicorn2（Dynarmic 不支持 hook_add_new(CodeHook)）
import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.CodeHook;
import com.github.unidbg.arm.backend.UnHook;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.memory.Memory;
import java.io.File;

public class unidbg_hook extends AbstractJni {

    // 改成你的 so 路径
    private static final String SO = "libtarget.so";

    private final AndroidEmulator emulator;
    private final VM vm;
    private Module module;

    public static void main(String[] args) throws Exception { new unidbg_hook().run(); }

    // 补环境(桩): 库缺的 Java 方法按需 override，否则抛 UnsupportedOperationException
    @Override
    public DvmObject<?> callStaticObjectMethodV(BaseVM vm, DvmClass c, String sig, VaList vaList) {
        if (sig.startsWith("aegon/chrome/base/JNIUtils->getSplitClassLoader")) {
            return vm.resolveClass("java/lang/ClassLoader").newObject(null);
        }
        return super.callStaticObjectMethodV(vm, c, sig, vaList);
    }

    private unidbg_hook() throws Exception {
        emulator = AndroidEmulatorBuilder.for64Bit()
                .setProcessName("com.example.app")
                .addBackendFactory(new Unicorn2Factory(true))   // 必须 Unicorn2
                .build();
        Memory memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));
        vm = emulator.createDalvikVM();
        vm.setJni(this);
        vm.setVerbose(false);
        DalvikModule dm = vm.loadLibrary(new File(SO), true);
        module = dm.getModule();
        System.out.println("base=0x" + Long.toHexString(module.base));
    }

    // hook 内部函数: 按 IDA 里的 base+offset
    private void hook(String name, long off) {
        long a = module.base + off;
        emulator.getBackend().hook_add_new(new CodeHook() {
            public void hook(Backend b, long addr, int size, Object u) { System.out.println("CALL " + name); }
            public void onAttach(UnHook u) {}
            public void detach() {}
        }, a, a, null);
    }

    private void run() throws Exception {
        hook("myTargetFn", 0x569510L);                          // 换成你的偏移
        vm.getDalvikModule().callJNI_OnLoad(emulator);
        DvmClass cls = vm.resolveClass("com/example/app/Native");
        Object r = cls.callStaticJniMethodObject(emulator, "getVersion()Ljava/lang/String;");
        System.out.println("ret = " + r);
        emulator.close();
    }
}
