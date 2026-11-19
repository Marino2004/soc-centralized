// Highlights the current page's link in the shared top nav,
// and wires up the shared logout button.
// Call this once on each page after the DOM is ready.
export function highlightActiveNav() {
  const path = window.location.pathname;
  document.querySelectorAll('nav.topnav a').forEach((link) => {
    const page = link.dataset.page;
    link.classList.toggle('active', path.includes(`/${page}`));
  });

  wireLogout();
}

function wireLogout() {
  const btn = document.querySelector('nav.topnav .logout');
  if (!btn) return;

  btn.addEventListener('click', async () => {
    let target = '/';
    try {
      const res = await fetch('/api/auth/logout', {
        method: 'POST',
        credentials: 'include',
      });
      const data = await res.json();
      // Ferme aussi la session SSO côté Keycloak
      if (data.logout_url) target = data.logout_url;
    } catch (err) {
      console.error('Erreur lors de la déconnexion:', err);
    } finally {
      window.location.href = target;
    }
  });
}