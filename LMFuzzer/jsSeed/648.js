try {
    for (var v0 = 0; v0 < 10; v0++) {
        if (v0 === 5)
            throw v0;
    }
} catch (e) {
    if (e !== 5)
        $ERROR('#1: Exception === 5. Actual:  Exception ===' + e);
}
