var v0 = false;
try {
    try {
        throw [void 0];
    } catch ([{constructor} = new constructor()]) {
    }
} catch (e) {
    v0 = true;
}
if (!v0)
    throw Error('Missing ReferenceError');
