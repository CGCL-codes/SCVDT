function f0() {
    var v0 = new SharedArrayBuffer(4096);
    var v1 = new Int32Array(v0);
    var v2 = new Int8Array(v0);
    gc();
}
if (this.SharedArrayBuffer)
    f0();
