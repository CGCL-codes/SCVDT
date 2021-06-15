function f0(string) {
    var v0;
    for (var v1 = 0; v1 < 10000000; ++v1) {
        if (string)
            v0++;
    }
    return v0;
}
v2 = f0('hurr im a string');
