function f0(s) {
    return arguments[s];
}
for (var v0 = 0; v0 < 10; ++v0)
    assertEq(f0(String(v0 + 1), 0, 1, 2, 3, 4, 5, 6, 7, 8, 9), v0);
