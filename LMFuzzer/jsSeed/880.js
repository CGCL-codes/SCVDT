var v0 = /\s+java\s+/.test('\t javax package');
if (v0) {
    $ERROR('#1: /\\s+java\\s+/.test("\\t javax package") === false');
}
