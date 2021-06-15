var v0 = /\bot/.test('pilot\nsoviet robot\topenoffice');
if (v0) {
    $ERROR('#1: /\\bot/.test("pilot\\nsoviet robot\\topenoffice") === false');
}
