function f0() {
    var v0 = /blah/;
    WScript.Echo('blah: ' + v0.blah);
    v0.blah = 1;
    WScript.Echo('blah: ' + v0.blah);
}
f0();
f0();
