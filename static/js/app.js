function updateClock() {
    const el = document.getElementById("clock");
    if (el) el.textContent = new Date().toLocaleTimeString();
}
updateClock();
setInterval(updateClock, 1000);
