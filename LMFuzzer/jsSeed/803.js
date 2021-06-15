try {
    var v0 = new ArrayBuffer(2147483647);
} catch (e) {
    assertTrue(e instanceof RangeError);
}
