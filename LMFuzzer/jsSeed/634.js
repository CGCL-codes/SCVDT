try {
    v0 = v0;
} catch (e) {
    $ERROR('#1: VariableDeclaration in "var VariableDeclarationListNoIn" of for IterationStatement is allowed');
}
for (var v0 = 0; v0 < 6; v0++) {
    ;
}
