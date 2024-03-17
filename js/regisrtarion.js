document.addEventListener('DOMContentLoaded', function () {
    const toggleThemeButton = document.getElementById('toggleThemeButton');
    let darkMode = false;

    toggleThemeButton.addEventListener('click', () => {
        darkMode = !darkMode;
        if (darkMode) {
            document.body.style.backgroundColor = "#111";
            document.body.style.color = "#fff";
        } else {
            document.body.style.backgroundColor = "#f4f4f4";
            document.body.style.color = "#000";
        }
    });
});
