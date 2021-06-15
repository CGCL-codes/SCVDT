try {
    evaluate('%', { noScriptRval: true });
} catch (e) {
}
new Function('');
try {
    evaluate('new Function("");', { noScriptRval: true });
} catch (e) {
}
