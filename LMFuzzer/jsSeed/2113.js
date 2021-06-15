function f0() {
    var v0 = 0;
    while (false)
        v0 = v0 * 2;
}
function f1(func) {
    for (var v1 = 0; v1 < 11000; v1++)
        func();
}
for (var v2 = 0; v2 < 50; v2++)
    f1(f0);
