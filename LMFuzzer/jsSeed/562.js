function f0() {
    var v0 = [1.5];
    return Math.cos(Math.sqrt(Math.abs(Math.sin(v0[0]) * 5 / 4.5))) % 3.5;
}
noInline(f0);
for (var v1 = 0; v1 < 100000; ++v1)
    f0();
