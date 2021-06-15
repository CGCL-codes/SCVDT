var v0 = Promise.resolve(3);
if (!(v0.catch instanceof Function)) {
    $ERROR('Expected p.catch to be a function');
}
