var v0;
function f0(param) {
    v0 = {
        x: 1,
        y: function () {
            return param;
        }
    };
}
f0('test1');
WScript.Echo(v0.y());
f0('test2');
WScript.Echo(v0.y());
