function f0(b) {
    if (!b)
        throw new Error('Bad assertion');
}
f0((() => {
}).name === '');
v0 = () => {
};
f0(v0.name === 'f');
let v1 = () => {
};
f0(v1.name === 'lf');
