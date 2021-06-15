function f0() {
    return Math.hypot() === 0 && Math.hypot(1) === 1 && Math.hypot(9, 12, 20) === 25 && Math.hypot(27, 36, 60, 100) === 125;
}
if (!f0())
    throw new Error('Test failed');
