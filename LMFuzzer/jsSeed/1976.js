var v0;
function f0(param) {
    v0 = [
        1,
        function () {
            return param;
        },
        2
    ];
}
f0('test1');
WScript.Echo(v0[1]());
f0('test2');
WScript.Echo(v0[1]());
