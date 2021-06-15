function f0() {
    var v0 = function (argArr2) {
        if (v1 ? argArr2.pop() : WScript.Echo('false')) {
        }
    };
    var v1 = true;
    v0([1]);
    v1 = false;
    v0(1);
}
;
f0();
f0();
