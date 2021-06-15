var v0 = /(\.(?!com|org)|\/)/.test('ah.com');
if (v0) {
    $ERROR('#1: /(\\.(?!com|org)|\\/)/.test("ah.com") === false');
}
