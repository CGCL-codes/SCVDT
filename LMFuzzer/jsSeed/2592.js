var v0 = new ArrayBuffer(512 * 1024);
var v1 = new Uint8Array(v0);
function f0() {
    return v1[4660];
}
f0();
f0();
f0();
detachArrayBuffer(v0);
f0();
