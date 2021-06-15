function f0(a) {
    f0(a + 1);
}
Error.__defineGetter__('stackTraceLimit', function () {
});
try {
    f0(0);
} catch (e) {
}
