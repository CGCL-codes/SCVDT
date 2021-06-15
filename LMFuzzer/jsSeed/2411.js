var v0 = /a[^b]c/.test('abc');
if (v0) {
    $ERROR('#1: /a[^b]c/.test("abc") === false');
}
