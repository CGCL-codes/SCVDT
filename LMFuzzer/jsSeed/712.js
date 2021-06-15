var v0 = /\b(\w+) \2\b/.test('do you listen the the band');
if (v0) {
    $ERROR('#1: /\\b(\\w+) \\2\\b/.test("do you listen the the band") === false');
}
