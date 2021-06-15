f0(true, new Boolean(true), false, 0);
function f0(x, y, expect, i) {
    v0 = x === y;
    if (i < 100)
        f0(y.environment !== Set.environment, true, false, i + 1);
}
