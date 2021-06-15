function f0() {
    var v0 = 'switch(x) {\n';
    for (var v1 = -1; v1 < 4; v1++) {
        v0 += v1 >= 0 ? v0 : 'default:\n';
    }
}
f0();
