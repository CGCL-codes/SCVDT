var v0 = Promise.resolve(1), v1 = Promise.resolve(v0);
if (v0 !== v1) {
    $ERROR('Expected p1 === Promise.resolve(p1) because they have same constructor');
}
