# 实战经验：Frida 魔改 · 转译(Houdini) · Java · Native · SVC

> 以某短视频 App(arm64) 为贯穿案例 · 环境 **MuMu(x86_64 + Houdini 转译)** + **魔改(nosuke) Frida**
> 定位：一张"什么场景用什么招"的实战地图 + 可复用片段 + 踩坑。

---

## 0. 总览：分层决策表

| 场景 | 所在层 | 能不能 hook | 用什么 |
|---|---|---|---|
| **x86_64 系统库导出**(libc/libssl) | x86_64 原生 | ✅ **最稳** | Frida `Interceptor.attach` |
| **Java 业务/网络/签名入口** | ART(**x86_64 原生**) | ✅ 有 Java 桥就能 | Frida `Java.use` |
| **app 自带 ARM so 的逻辑** | ARM64(转译) | ❌ 原始页 hook 不触发 | **hook 它调用的 x86_64 边界** / **unidbg 仿真** |
| 反检测(native 裸 syscall) | raw `svc #0` | libc hook 无效 | **hook `svc` / syscall 引擎** |
| 反检测(Frida 特征) | — | — | **魔改 Frida(nosuke)** |

> 铁律：**转译环境里，ARM 库一律"从 x86 边界观察 / 上探 Java 层 / 仿真",别硬 hook 原始页。**

---

## 1. Frida 魔改（反检测）与**连接铁律**

- **正确版 = nosuke 反检测 Frida**，端口 **31337**（非默认 27042）。
- **★ 连接铁律（血泪）**：
  1. **attach 前必重启 server**：`killall nsv11; sleep 1; nohup .../nsv11 -D &` → `ss -tlnp | grep 31337` 确认 LISTEN。否则 `Failed to attach: timed out while waiting for stop`。
  2. **用 PID 不用名字**：`frida -H host:port -p <pid>`。
  3. **前台检查**（后台冻结时 hook 无意义）：`dumpsys activity activities | grep topResumedActivity`。
  4. **端口转发**：`adb forward tcp:31337 tcp:31337`（每次连都做）。
- **★ 时序窗口法（与 TP 共存）**：TP 周期(15~30s)扫代码完整性 → **attach + 装 hook，≤12s 取数立即 detach**。
  - 安全分级：读内存/枚举模块 ✅；hook ≤12s ✅；**hook 30s+ ❌死**；改 libc 入口 ❌死；**spawn(-f) ❌崩**（houdini 不兼容）。
  - 回调**全程 try-catch + 打印 cap + fd 过滤**（异常刷屏/数据爆炸 = 暴露）。

---

## 2. 转译(Houdini) 环境的铁律（必背）

x86_64 模拟器跑 ARM app = **两个 zygote**：主(原生) + `zygote_secondary`(转译)。

**三连定性**：
```sh
xxd -l 20 libxxx.so        # 第18字节 b7=aarch64(转译) / 3e=x86_64(原生)
grep houdini /proc/<pid>/maps
grep libxxx /proc/<pid>/maps
```
**铁律**：
1. **ARM so 在 `0x4000xxxxxxxx` 区**，段多为 `r--p`；**Frida `enumerateModules()`/`findModuleByName` 看不到** → 走 `/proc/self/maps` + `ptr(addr)`。
2. **inline hook ARM 原始页 = 不触发** —— 跑的是 Houdini **译出的 x86_64 缓存**。
   → 实测：某 so 120 个 JNI 按 `base+偏移` 全 attach，**0 触发**。
3. **ART 是 x86_64 原生** → **Java 层 hook 不受转译影响**（转译环境的"逃生口"，前提是有 Java 桥，见 §3）。
4. 性能：ARM 走 Houdini 慢 5–20×。
5. `/proc/<pid>/mem` 读需 `setenforce 0`；`mksh` 的 `$(( ))` 是 **32 位**（算 dump skip 用 Python 算十进制）。

---

## 2.5 转译调用图

```
执行路径:
ARM app (libxxx.so, aarch64)
   |  调用
   v
Houdini 翻译器 (libhoudini.so)
   |  即时翻译
   v
x86_64 翻译缓存 (匿名 rwxp)   <-- 实际在这执行, Frida 看不到
   |  执行
   v
x86_64 系统库 (libc/libssl) --> syscall --> Kernel

Java / ART (x86_64 原生) --JNI--> Houdini 翻译器
```
```
hook 决策:
要 hook 的目标
  +-- 在 Java 层 ? --是--> Java.use                        ✅(x86_64 原生; 需 Java 桥)
  +-- 否, 在 ARM so
        +-- 能上探 Java / 有 native 接口 ? --能--> Frida 调 Java / 纯 JNI 直调   ✅
        +-- 不能
              +-- 要跑 native 逻辑 ? --要--> unidbg 仿真                       ✅
              +-- 只观察副作用 ----------> hook 它调的 x86_64 libc            ✅
```
> 完整版（含稳定性分级 / SVC 拦截 / 一条龙）见 [`调用图.md`](调用图.md)。

---

## 3. Java 层：**先确认有没有 Java 桥**（大坑！）

**★ 关键：魔改/官方 frida 在 Android 12+ 可能没有 Java bridge** —— `Java.perform` 报 `ReferenceError: Java is not defined`（`registerFrameworkNatives` 被删）。
- 有的 frida 构建**有桥** → `Java.use` 可用。
- 有的（如某 nosuke 版）**无桥** → 只能**纯 JNI 直调**。

**判断**：先跑 `frida -H ... -p PID -e "console.log(typeof Java)"` —— `undefined` = 无桥。

**有桥** → 直接用（全明文抓包）：
```js
// 请求: okhttp -> Cronet 的桥
Java.use('com.kuaishou.aegon.okhttp.CronetInterceptor').intercept.implementation
  = function(chain){ log(chain.request().url()); return this.intercept(chain); };
// 响应体明文(非破坏): peekBody
Java.use('okhttp3.RealCall')['getResponseWithInterceptorChain'].overload().implementation
  = function(){ var r=this.getResponseWithInterceptorChain();
      console.log(r.code()+' '+r.request().url());
      console.log(r.peekBody(32768).string());   // ★ 复制, 不消费
      return r; };
```

**无桥** → **纯 JNI 直调**：`JNI_GetCreatedJavaVMs`→`AttachCurrentThread`→app ClassLoader `loadClass`→调方法。

**通用坑**：
- **别全方法 hook 带 native 回调的类**（某 Cronet request 类 29 方法全 hook → 参数个数不对 → **SIGSEGV 崩**）。
- 初始化期方法（如 `getVersionString`）**attach 时已调完** → 改 **"Frida 直接调"**。
- **Frida 17 API**：`Module.findExportByName('libc.so','openat')` → 用 `Module.findGlobalExportByName('openat')` 或 `Process.getModuleByName(m).getExportByName(f)`。

---

## 4. ★ frida hook .so 的"最稳法"：只信 x86_64 边界库

**排序（实测）**：
| 目标 | 稳不稳 | 说明 |
|---|---|---|
| **x86_64 libc/libssl/系统库导出** | ✅ **最稳** | `Interceptor.attach` 必触发，app 存活 |
| app 自带 x86_64 so | ✅ 稳 | 在模块表内 |
| **ARM 转译库(0x4000 区)** | ❌ **无效** | 0 触发（跑翻译缓存） |
| 观察 ARM 库"起了什么作用" | ✅ 变通 | **hook 它调用的 x86_64 libc**（ARM→x86 libc）：`write/connect/openat` |

**实测**：`x86 modules=352 / ARM libs(maps /arm64/)=109`；hook `libc.so!write/!connect/!openat` + `libssl.so!SSL_write` → **稳触发 + app 存活**。

**6 条模板**：① attach 不 spawn ② 魔改 frida + 必要时重启 server ③ Frida17 取导出用 `getExportByName` ④ 回调 try-catch + cap ⑤ 只 hook 目标 + ≤12s ⑥ 需 Java 层用 **CLI**(`frida -H .. -l x.js`, Python `create_script` 无桥)。

---

## 5. Native 层：转译下怎么搞定（unidbg 拟真）

**案例（Cronet 7MB so）**：加载 + JNI_OnLoad + **调 native 拿真值**。
**流程**：`Frida 探路(圈定入口) → unidbg 拟真(跑 native) → Frida 验证(比对)`。

**复现要点**：
1. **后端用 Unicorn2**（`new Unicorn2Factory(true)`）—— **Dynarmic 的 `hook_add_new(CodeHook)` 直接抛 `UnsupportedOperationException`**。
2. **补环境(桩)**：库缺 Java 方法抛 `UnsupportedOperationException` → `AbstractJni` 子类 override 补。本次只需 1 庄：`JNIUtils->getSplitClassLoader`。
3. **调 native**：`vm.resolveClass("com/kuaishou/aegon/Aegon").callStaticJniMethodObject(emulator,"nativeGetVersionString()Ljava/lang/String;")`。
4. **hook native**：
   ```java
   emulator.getBackend().hook_add_new(new CodeHook(){
     public void hook(Backend b,long a,int s,Object u){ ... }
     public void onAttach(UnHook u){} public void detach(){}
   }, module.base+off, module.base+off, null);
   ```
5. maven 根 pom 常设 `maven.test.skip=true` → 须 `-Dmaven.test.skip=false`；`install` 须 `-Dgpg.skip=true`。

**成果**：`nativeGetVersionString()="4.50.1"`(unidbg) == `"4.50.1"`(真机) ✅；`nativeSetKProxyConfig*` 调通，native 日志 `Set KProxy server: %s 0x%x`。

---

## 6. SVC：绕过 libc 的裸系统调用

**问题**：加固 so 自带 `x_*` syscall 引擎（`x___ptrace`/`x_process_vm_readv`/`x_memfd_create`…），**不经 libc** → **Frida hook libc 的 `ptrace`/`vm_readv` 无效**。

**判据**：数 `.text` 内联 `svc` 条数（0=全 libc；>0=有绕过）；看是否有**自定义 syscall 引擎导出**。

**拦截**：① **hook `svc #0` 指令**（Stalker/patch svc）② **hook 那套 `x_*` 导出封装**。

---

## 7. 内存大杀器：`dd if=/proc/PID/mem`（转译/SELinux 下也能读）

- **问题**：Android 15 上 `readByteArray` 常 `Permission denied`（SELinux 拦 `process_vm_readv`）。
- **解法**：`setenforce 0` + `dd if=/proc/PID/mem`：
  ```bash
  su -c 'setenforce 0; getenforce'                 # Permissive
  # skip = 虚拟地址 // 4096 ; count = 字节数 // 4096
  dd if=/proc/$PID/mem of=out bs=4096 skip=<addr//4096> count=<size//4096>
  head -c 8 out | xxd                               # 验证 magic
  ```
- **★ 血泪坑**：`mksh` 的 `$(( ))` **32 位** → `$((0x7bdb71558000/4096))` 被截断。**用 Python 算十进制**再传。
- **策略**：先 Frida `Memory.scanSync` **定位地址**（搜结构特征，别搜字符串），再 **dd 拉数据**。

---

## 8. 案例一条龙（把七块串起来）

```
① Frida 探路(Java): 命中 30 次 → 网络入口在 Cronet
② 发现 native: 网络 so = Cronet(BoringSSL/QUIC); ARM 转译 → Frida hook 不触发
③ 静态(IDA): 按字符串 xref 定位 KProxy 重写 / HPKP pin / 证书校验入口
④ unidbg 拟真: 加载 so + JNI_OnLoad + 调 native 拿版本串
⑤ Frida 验证: 真机值 == unidbg 值 → 拟真可信
⑥ SVC: 加固 so 自带 x_* syscall 引擎(反调试/反 hook), 需 hook svc
```

---

## 9. 踩坑清单

| 坑 | 现象 | 对策 |
|---|---|---|
| 转译 hook ARM | `onEnter` 永不触发 | hook x86_64 边界 / 上探 Java / unidbg |
| Frida 看不到 ARM so | `findModuleByName=null` | 读 `/proc/self/maps` + `ptr(addr)` |
| **Java 桥缺失** | `Java is not defined` | 换带桥 frida / **纯 JNI 直调** |
| 全方法 hook native 回调类 | SIGSEGV 崩 | 只 hook 确认的方法 |
| server 状态残留 | attach timed out | 重启 server |
| 后台冻结 | hook 无输出 | `monkey LAUNCHER` 切前台 |
| spawn 崩 | houdini 不兼容 | 用 attach |
| Dynarmic code hook | `UnsupportedOperationException` | 换 **Unicorn2** |
| peekBody 误用 | 响应被吃掉 | `Response.peekBody(n)` |
| `/proc/mem` 读不了 | I/O error | `setenforce 0` |
| dump skip 错位 | 垃圾 | mksh `$(( ))` 32 位 → Python 算十进制 |
| Frida17 API | `findExportByName is not a function` | `findGlobalExportByName` |
| maven | install 失败/test 不编 | `-Dgpg.skip=true` / `-Dmaven.test.skip=false` |

---

## 10. 速查

```sh
# 转译定性
xxd -l 20 lib.so ; grep houdini /proc/<pid>/maps ; grep lib.so /proc/<pid>/maps
# 魔改 frida (attach, 脚本走 CLI, Java 桥最稳)
adb forward tcp:31337 tcp:31337
frida -H 127.0.0.1:31337 -p <PID> -l script.js
# 有没有 Java 桥
frida -H ... -p <PID> -e "console.log(typeof Java)"
# 内存 dump
su -c 'setenforce 0'; dd if=/proc/<PID>/mem of=out bs=4096 skip=<addr//4096> count=<size//4096>
# unidbg 拟真
mvnw -o -pl unidbg-android -Dgpg.skip=true -Dmaven.test.skip=false test-compile exec:java \
     -Dexec.mainClass=... -Dexec.classpathScope=test
```
