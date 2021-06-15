var v0 = [
    1,
    2.2,
    3.3
];
Array.prototype[4] = 10;
function f0() {
    WScript.Echo(v0.shift());
    WScript.Echo(v0.unshift(100, 101, 103));
}
f0();
