function* f0() {
    for (var v0 = 0; v0 < 3; ++v0) {
        yield v0;
    }
}
f0().next();
