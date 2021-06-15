var v0 = 0;
try {
    (function f(i) {
        v0 = i;
        if (i == 100000)
            return;
        f(i + 1);
    }(1));
} catch (e) {
}
if (v0 == 100000)
    assertEq(v0, 'fail');
