function f0() {
    var v0 = '[0';
    for (var v1 = 0; v1 < 128 << 10; v1++) {
        v0 += ',0';
    }
    v0 += ']';
    return eval(v0);
}
var v2 = f0();
v2[17] = 42;
