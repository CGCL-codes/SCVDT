function f0() {
    new f0();
}
try {
    f0();
} catch (e) {
    WScript.Echo(e);
}
