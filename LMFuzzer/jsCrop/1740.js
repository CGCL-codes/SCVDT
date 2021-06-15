var v0 = false;
try {
    try {
        throw {};
    } catch ({a = (print(a), b), b}) {
    }
} catch (e) {
    v0 = true;
}
if (!v0)
    throw Error('Missing ReferenceError');
