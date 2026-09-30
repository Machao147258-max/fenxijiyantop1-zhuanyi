// maps_enum.js —— 转译环境下枚举加载的 so（Frida 模块表看不到 ARM so，只能读 /proc/self/maps）
// 用法: frida -H host:port -p PID -l maps_enum.js
function log(s){ console.log(s); }
var f = new File('/proc/self/maps', 'r');
var line, seen = {}, n = 0;
while ((line = f.readLine()) !== null) {
  var i = line.indexOf('/');
  if (i < 0) continue;
  var path = line.slice(i).trim();
  if (path.indexOf('.so') < 0) continue;
  if (path.indexOf('/data/') >= 0 || path.indexOf('houdini') >= 0) {   // 只看 app 自己的 so + 转译层
    if (!seen[path]) { seen[path] = 1; n++; log('[SO] ' + path); }
  }
}
f.close();
log('[SO] total = ' + n);
