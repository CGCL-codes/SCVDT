try {
    (function (v0) {
        try {
            let v0 = 'inner';
            throw 0;
        } finally {
            assert.sameValue(v0, 'outer');
        }
    }('outer'));
} catch (e) {
}
