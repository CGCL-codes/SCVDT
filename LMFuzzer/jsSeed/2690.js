var v0 = /ab[erst]de/.test('abcde');
if (v0) {
    $ERROR('#1: /ab[erst]de/.test("abcde") === false');
}
