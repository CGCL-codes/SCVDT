var v0 = /^..^e/.test('ab\ncde');
if (v0) {
    $ERROR('#1: /^..^e/.test("ab\\ncde") === false');
}
