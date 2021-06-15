function f0() {
}
f0();
try {
    f0();
    throw 1;
} catch (e) {
    f0();
} finally {
    f0();
}
f0();
