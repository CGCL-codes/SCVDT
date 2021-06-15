function f0() {
    var v0 = [];
    var v1 = function () {
        var v2 = v0, v3;
        if (!v2.length)
            return;
        v0 = [];
    };
    v1();
}
f0();
WScript.Echo('Pass');
