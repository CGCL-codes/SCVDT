var v0 = /op\b/.test('pilot\nsoviet robot\topenoffice');
if (v0) {
    $ERROR('#1: /op\\b/.test("pilot\\nsoviet robot\\topenoffice") === false');
}
