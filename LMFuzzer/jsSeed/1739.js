function f0() {
    try {
        v0 = new Uint8ClampedArray();
        v0[-29] = Object(Symbol());
        v0;
        v0;
    } catch (e) {
        WScript.Echo(e.message);
    }
}
f0();
f0();
