var v0;
function f0(param) {
    var v1 = function () {
        return param;
    };
    eval('escape = nested');
}
f0('test1');
WScript.Echo(v0());
f0('test2');
WScript.Echo(v0());
