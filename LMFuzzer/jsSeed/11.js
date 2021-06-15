var v0 = /r\b/.test('pilot\nsoviet robot\topenoffice');
if (v0) {
    $ERROR('#1: /r\\b/.test("pilot\\nsoviet robot\\topenoffice") === false');
}
