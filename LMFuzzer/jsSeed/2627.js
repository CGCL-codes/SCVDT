try {
} catch (e) {
    ;
}
function f0(expected, run) {
    var v0 = run();
}
;
f0('[1,2,3]', () => function () {
    return (async () => {
        [...await arguments];
    })();
}());
