// stable_so_hook.js —— frida hook .so 的"最稳法"：只信 x86_64 边界库
//   ARM 转译库别硬 hook; 用 hook 它调用的 x86_64 libc 来观察
// 用法: frida -H host:port -p PID -l stable_so_hook.js
function getExport(name) {
  var M = Process.getModuleByName('libc.so');
  var p = M.getExportByName(name);
  if (p) return p;
  if (Module.findGlobalExportByName) return Module.findGlobalExportByName(name);
  return Module.findExportByName('libc.so', name);
}
function safeStr(p) { try { return p.isNull() ? null : p.readCString(); } catch (e) { return null; } }

// 1) write (x86_64 libc 必触发; ARM 库的数据最终也经这里)
(function () {
  var f = getExport('write'); if (!f) return; var c = 0;
  Interceptor.attach(f, {
    onEnter: function (a) { this.fd = a[0].toInt32(); this.n = a[2].toInt32(); },
    onLeave: function (r) { if (c++ < 200 && this.fd > 2) console.log('[write] fd=' + this.fd + ' len=' + this.n); }
  });
})();
// 2) connect (网络目标)
(function () {
  var f = getExport('connect'); if (!f) return; var c = 0;
  Interceptor.attach(f, {
    onEnter: function (a) { this.sa = a[1]; },
    onLeave: function (r) {
      if (c++ >= 100) return;
      try { var fam = this.sa.readU16(); if (fam === 2) { var port = (this.sa.add(2).readU8() << 8) | this.sa.add(3).readU8(); console.log('[connect] port=' + port); } } catch (e) {}
    }
  });
})();
// 3) openat (读了什么文件)
(function () {
  var f = getExport('openat'); if (!f) return; var c = 0;
  Interceptor.attach(f, {
    onEnter: function (a) { this.p = safeStr(a[1]); },
    onLeave: function (r) { if (c++ < 200 && this.p) console.log('[openat] ' + this.p + ' = ' + r); }
  });
})();
console.log('[STABLE] armed (x86_64 libc: write/connect/openat)');
