function f0(x, y) {
    return new v0(x, y);
}
f0(1, 2);
f0(2, 3);
v0 = function (x, y) {
    WScript.Echo('arg: ' + x + ', ' + y);
};
f0(3, 4);
f0(5, 6);
