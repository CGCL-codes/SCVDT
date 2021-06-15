var v0 = /\s+java\s+/.test('java\n\nobject');
if (v0) {
    $ERROR('#1: /\\s+java\\s+/.test("java\\n\\nobject") === false');
}
