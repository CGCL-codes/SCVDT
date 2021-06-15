var v0 = /\d{2,4}/.test('the 7 movie');
if (v0) {
    $ERROR('#1: /\\d{2,4}/.test("the 7 movie") === false');
}
