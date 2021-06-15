var v0 = Array(50000).join('(') + 'a' + Array(50000).join(')');
var v1 = RegExp(v0);
try {
    v1.test('\x80');
    assertUnreachable();
} catch (e) {
}
gc();
