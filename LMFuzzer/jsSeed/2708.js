var v0 = /\d{3}|[a-z]{4}/.test('2, 12 and 23 AND 0.00.1');
if (v0) {
    $ERROR('#1: /\\d{3}|[a-z]{4}/.test("2, 12 and 23 AND 0.00.1") === false');
}
