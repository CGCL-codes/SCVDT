function f0() {
    var v0 = Object.create(Object.prototype);
    var v1 = new WeakMap();
    v1.set(v0, {});
    Object.keys(v0);
    v0.aaa = 'bbb';
    WScript.Echo('Pass');
}
f0();
