var v0 = /ab|cd|ef/.test('AEKFCD');
if (v0) {
    $ERROR('#1: /ab|cd|ef/.test("AEKFCD") === false');
}
