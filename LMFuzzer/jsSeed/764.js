var v0 = /b{42,93}c/.test('aaabbbbcccddeeeefffff');
if (v0) {
    $ERROR('#1: /b{42,93}c/.test("aaabbbbcccddeeeefffff") === false');
}
