var v0 = /b{8,}c/.test('aaabbbbcccddeeeefffff');
if (v0) {
    $ERROR('#1: /b{8,}c/.test("aaabbbbcccddeeeefffff") === false');
}
