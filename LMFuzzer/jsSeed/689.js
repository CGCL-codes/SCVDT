var v0 = [
    3.3,
    2.2,
    1
];
Array.prototype[4] = 10;
function f0() {
    v0.sort(function () {
        return -1;
    });
    WScript.Echo(v0);
}
f0();
