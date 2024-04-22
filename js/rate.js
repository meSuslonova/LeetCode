const userRatingForm = document.querySelector('.user-rating-form form');
const currentUser = userRatingForm.getAttribute('action').split('/').pop(); // Получаем ID текущего пользователя из URL-адреса формы
const ratedUser = userRatingForm.getAttribute('action').split('/').pop(); // Получаем ID пользователя, рейтинг которого мы хотим обновить, из URL-адреса формы
userRatingForm.setAttribute('action', `/admin/user/${user._id}/rate`);
const updateRating = async (ratedUser, newRating, csrfToken) => {
    try {
        const response = await fetch(`/admin/user/${user._id}/rate`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'CSRF-Token': csrfToken
            },
            body: JSON.stringify({ rating: newRating })
        });

        if (!response.ok) {
            throw new Error('Ошибка сети');
        }

        const data = await response.json();
        return data.newRating; // Возвращаем новый рейтинг в качестве результата выполнения функции
    } catch (error) {
        console.error('Произошла ошибка:', error);
        return null;
    }
}

// Обработчик события отправки формы
document.addEventListener('DOMContentLoaded', () => {
    const userRatingForm = document.querySelector('.user-rating-form form');

    userRatingForm.addEventListener('submit', async (event) => {
        event.preventDefault(); // Предотвращаем стандартное поведение отправки формы

        const csrfToken = userRatingForm.querySelector('input[name="_csrf"]').value; // Получаем токен CSRF из формы
        const newRating = userRatingForm.querySelector('input[name="rating"]').value;// Получаем значение рейтинга из input

        const updatedRating = await updateRating(ratedUser, newRating, csrfToken);
        if (updatedRating !== null) {
            // Обновите элемент с рейтингом на странице
            const userRatingElement = document.getElementById('user-rating');
            if (userRatingElement) {
                userRatingElement.textContent = updatedRating;
            }
        } else {
            console.error('Произошла ошибка при обновлении рейтинга');
        }
    });
});
