function f0(v) {
    WScript.Echo(v + '');
}
Error.x = 10;
f0(RangeError.x === 10);
