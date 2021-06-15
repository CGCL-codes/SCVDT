try {
    v0 = new ArrayBuffer(76);
    v1 = new Uint32Array(v0);
    uneval();
    v2 = new Uint8Array(v0);
    v2.set(v1);
} catch (e) {
}
