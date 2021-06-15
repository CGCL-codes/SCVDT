if (typeof verifybarriers !== 'undefined') {
    for (var v0 = 0; v0 < 30; v0++) {
    }
    for (v0 in Function('gc(verifybarriers()); yield')()) {
    }
}
