if (!('oomTest' in this))
    throw new Error('out of memory');
fullcompartmentchecks(true);
var v0 = new Debugger();
v0.onNewGlobalObject = function () {
};
oomTest(function () {
    newGlobal();
});
