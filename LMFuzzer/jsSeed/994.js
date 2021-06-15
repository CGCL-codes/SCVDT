try {
    e++;
} catch (e) {
    with ({ o: 2 }) {
        var v0 = [];
        v0.push(1);
        v0.forEach(function (key, val, map) {
            key;
        });
    }
}
WScript.Echo('PASSED');
