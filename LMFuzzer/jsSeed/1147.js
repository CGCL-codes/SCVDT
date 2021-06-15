if (typeof oomAtAllocation === 'object') {
    var v0 = [];
    oomAtAllocation(1);
    try {
        v0.forEach();
    } catch (e) {
    }
    v0.forEach(() => 1);
}
