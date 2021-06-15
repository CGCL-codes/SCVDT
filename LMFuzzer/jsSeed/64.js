do {
    try {
        continue;
    } catch (e) {
        continue;
    } finally {
    }
} while (false);
L: {
    try {
        break L;
    } catch (e) {
        break L;
    } finally {
    }
}
