function f0() {
    try {
        this.f = 0;
    } finally {
    }
}
new f0();
