// okhttp_body_capture.js —— Java 层"请求 + 响应体明文"抓取（非破坏，不吃响应）
//   关键: Response.peekBody(n) 返回副本, 不像 string() 会消费流
// 用法: frida -H host:port -p PID -l okhttp_body_capture.js
Java.perform(function () {
  function short(s, n){ return (s||'').replace(/[^\x20-\x7e\n]/g,'.').slice(0, n||300); }

  // 1) 请求（okhttp → Cronet 的拦截器，按需改类名）
  try {
    var CI = Java.use('com.kuaishou.aegon.okhttp.CronetInterceptor');
    CI.intercept.implementation = function (chain) {
      try { var u = chain.request().url().toString(); if (u.indexOf('/rest/') >= 0) console.log('[REQ] ' + chain.request().method() + ' ' + u.split('?')[0]); } catch (e) {}
      return this.intercept(chain);
    };
  } catch (e) {}

  // 2) 响应体明文（peekBody = 非破坏）
  var RC = Java.use('okhttp3.RealCall');
  var ms = RC.class.getDeclaredMethods(), tgt = null;
  for (var i=0;i<ms.length;i++) if (ms[i].getName().indexOf('getResponseWithInterceptorChain')>=0) tgt = ms[i].getName();
  RC[tgt].overload().implementation = function () {
    var r = this[tgt]();
    try { var u = r.request().url().toString();
      if (u.indexOf('/rest/') >= 0) console.log('[RESP] ' + r.code() + ' ' + u.split('?')[0] + ' | ' + short(r.peekBody(32768).string(), 260));
    } catch (e) {}
    return r;
  };
  console.log('[CAP] armed');
});
