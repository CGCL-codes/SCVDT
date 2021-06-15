var v0 = /so\b/.test('pilot\nsoviet robot\topenoffice');
if (v0) {
    $ERROR('#1: /so\\b/.test("pilot\\nsoviet robot\\topenoffice") === false');
}
