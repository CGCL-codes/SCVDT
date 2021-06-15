function f0(a, s) {
    a[s] = 35;
}
var v0 = { bilbo: 3 };
var v1 = {
    frodo: 3,
    bilbo: 'hi'
};
f0(v0, 'bilbo');
f0(v0, 'bilbo');
f0(v1, 'bilbo');
