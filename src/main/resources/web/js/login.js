document.addEventListener('DOMContentLoaded', function() {
    const loginForm = document.getElementById('login-form');
    const errorMessage = document.getElementById('login-error');
    
    loginForm.addEventListener('submit', function(e) {
        e.preventDefault();
        
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        
        if (!username || !password) {
            showError('Username and password are required');
            return;
        }
        
        loginUser(username, password);
    });
    
    function loginUser(username, password) {
        fetch('/api/auth/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                username: username,
                password: password
            })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                // Login successful
                window.location.href = '/dashboard.html';
            } else {
                // Login failed
                showError(data.message || 'Login failed');
            }
        })
        .catch(error => {
            console.error('Login error:', error);
            showError('Connection error. Please try again.');
        });
    }
    
    function showError(message) {
        errorMessage.textContent = message;
        errorMessage.style.display = 'block';
    }
});