function f0() {
    var v0 = 'a';
    for (var v1 = 0; v1 < 10; v1++) {
        v0 += v1;
    }
    var v2 = 'blahblahblah' + v0 + 'blahblahblah';
    v0 += 'Z';
    WScript.Echo(v2);
}
f0();
f0();
