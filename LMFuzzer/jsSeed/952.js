var v0 = [
    0,
    'a',
    undefined
];
var v1 = [
    0,
    'b',
    undefined
];
if (compareArray(v0, v1) !== false) {
    $ERROR('Arrays containing different elements are not equivalent.');
}
