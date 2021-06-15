function f0(e) {
    return '' + e;
}
function f1() {
    do {
        yield;
    } while ({}(v0 = arguments));
}
v1 = f1();
try {
    for (a in v1);
} catch (e) {
    print('' + f0(e));
}
gc();
