try {
    fail;
} catch (e) {
    with ({}) {
        eval('const x = 7');
    }
}
