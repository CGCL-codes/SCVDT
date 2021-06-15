var v0 = 0, v1 = 0;
function f0() {
    for (v0 = 0; v0 < 50; ++v0)
        if ((v0 & 1) == 1)
            ++v1;
    return [
        v0,
        v1
    ].join(',');
}
f0();
