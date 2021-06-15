var v0 = /Java(?!Script)([A-Z]\w*)/.test('i\'m a JavaScripter ');
if (v0) {
    $ERROR('#1: /Java(?!Script)([A-Z]\\w*)/.test("i\'m a JavaScripter ") === false');
}
