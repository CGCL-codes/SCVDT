function f0() {
    var v0 = function (v1) {
        v1 = {};
        v1.prop0 = v1;
        v1.prop0;
    };
    v0();
}
f0();
f0();
f0();
f0();
WScript.Echo('PASSED');
