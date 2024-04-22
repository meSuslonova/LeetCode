const toggleThemeButton = document.getElementById('toggleThemeButton');

toggleThemeButton.addEventListener('click', () => {
    document.body.classList.toggle('dark-theme');
});

const passwordForm = document.querySelector('.settings-password form');

passwordForm.addEventListener('submit', (event) => {
    event.preventDefault();

    const currentPassword = document.getElementById('currentPassword').value;
    const newPassword = document.getElementById('newPassword').value;
    const confirmPassword = document.getElementById('confirmPassword').value;

    if (newPassword !== confirmPassword) {
        alert('Новый пароль и подтверждение пароля не совпадают.');
        return;
    }

    const data = {
        currentPassword,
        newPassword,
    };

    fetch('/settings/password', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRF-Token': document.querySelector('meta[name="csrf-token"]').content,
        },
        body: JSON.stringify(data),
    })
        .then((response) => response.json())
        .then((data) => {
            if (data.success) {
                alert('Пароль успешно изменен.');
            } else {
                alert(data.message);
            }
        })
        .catch((error) => {
            console.error('Error:', error);
            alert('Произошла ошибка. Попробуйте позже.');
        });
});
