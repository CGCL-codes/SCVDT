var v0 = /Java(?!Script)([A-Z]\w*)/.test('using of Java language');
if (v0) {
    $ERROR('#1: /Java(?!Script)([A-Z]\\w*)/.test("using of Java language") === false');
}
