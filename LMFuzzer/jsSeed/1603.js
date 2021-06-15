try {
    offThreadCompileScript('Error()', { lineNumber: 4294967295 });
    runOffThreadScript().stack;
} catch (e) {
}
