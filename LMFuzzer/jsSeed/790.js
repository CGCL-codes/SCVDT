var v0 = {
    get x() {
        return 2;
    }
};
function f0(y) {
    if (y == 0)
        return;
    v0.x;
    f0(--y);
}
f0(4);
WScript.Echo('PASSED');
