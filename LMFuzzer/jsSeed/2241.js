function f0(x, y) {
    return x == y;
}
f0(1.1, 2.2);
for (var v0 = 0; v0 < 5; v0++)
    f0(1, Symbol());
