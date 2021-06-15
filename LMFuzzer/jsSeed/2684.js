function f0(line) {
    return line && line.replace(/\(.+\\test.StackTrace./ig, '(');
}
