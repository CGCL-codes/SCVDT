var v0;
function f0(param) {
    v0 = function () {
        return param;
    };
}
f0('test1');
WScript.Echo(v0());
f0('test2');
WScript.Echo(v0());
