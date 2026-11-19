import '../shared/theme.css';

const errorBox = document.getElementById('loginError');

const MESSAGES = {
  auth: 'Authentification Keycloak échouée. Veuillez réessayer.',
  forbidden: "Connexion réussie, mais votre compte n'a aucun rôle SOC autorisé.",
};

const error = new URLSearchParams(window.location.search).get('error');
if (error && errorBox) {
  errorBox.textContent = MESSAGES[error] || 'Connexion impossible.';
  errorBox.style.display = 'block';
}

document.getElementById('loginBtn')?.addEventListener('click', () => {
  window.location.href = '/api/auth/login';
});
