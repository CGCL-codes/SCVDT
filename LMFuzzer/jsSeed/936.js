function f0() {
    var v0 = { a: 1 };
    delete v0.a;
    v0['b'] = 10;
    v0['c'] = 20;
    v0['constructor'] = undefined;
    v0;
}
;
var v0 = {};
f0.call(v0);
WScript.Echo('pass');
