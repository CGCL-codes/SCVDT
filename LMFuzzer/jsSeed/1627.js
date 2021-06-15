var v0 = [
    255,
    247,
    255,
    255,
    255,
    255,
    255,
    255
];
v0.reverse();
var v1 = new Float64Array(new Uint8Array(v0).buffer)[0];
isNaN(v1 + 0);
