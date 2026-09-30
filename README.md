# fenxijiyantop1-转译

> 逆向分析经验 · 第 1 篇「转译」
> 场景：**x86_64 模拟器跑 ARM app（Houdini 转译）**下的 Frida / Java / Native / SVC 实战。
> 案例：某短视频 App（arm64）网络层。

---

## 目录
- [`实战经验_frida魔改_转译_java_native_svc.md`](实战经验_frida魔改_转译_java_native_svc.md) —— 主文（含 §2.5 调用图）
- [`调用图.md`](调用图.md) —— **转译调用图全集**（执行路径 / hook 决策 / 稳定性分级 / SVC / 一条龙）
- [`code/`](code/) —— 可复用脚本

## 工程文件 `code/`
| 文件 | 说明 |
|---|---|
| `transpute_check.sh` | 转译三连定性（xxd / maps / houdini / 前台） |
| `maps_enum.js` | 转译下读 `/proc/self/maps` 枚举 so（Frida 模块表看不到 ARM so） |
| `stable_so_hook.js` | **最稳法**：只 hook x86_64 libc 边界（write/connect/openat） |
| `okhttp_body_capture.js` | Java 层请求+响应体明文（`peekBody` 非破坏） |
| `unidbg_hook.java` | unidbg 仿真 ARM so（Unicorn2 + 补桩 + 调 JNI + hook 内部函数） |

## 一句话
> 转译环境里：**只信 x86_64 边界库**；ARM 库**别硬 hook**，要么「从 x86 libc 边界观察」、要么「上探 Java 层」、要么「unidbg 仿真」。
