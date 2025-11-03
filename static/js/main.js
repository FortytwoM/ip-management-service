// static/js/main.js

const appContent = document.getElementById('app-content');
const mainNav = document.getElementById('main-nav');

const pageModules = {
    bans: () => import('./modules/bans.js'),
    exceptions: () => import('./modules/exceptions.js'),
	notes: () => import('./modules/notes.js'),
    users: () => import('./modules/users.js'),
    stats: () => import('./modules/stats.js'),
    check: () => import('./modules/check.js'),
    playbooks: () => import('./modules/playbooks.js'),
    audit: () => import('./modules/audit.js'),
    webhooks: () => import('./modules/webhooks.js'),
    ad_access: () => import('./modules/ad_access.js'),
    ad_settings: () => import('./modules/ad_settings.js'),
};

async function loadPage(pageName, pushState = true) {
    if (!pageName || !pageModules[pageName]) {
        const defaultPageLink = mainNav.querySelector('a[data-page]');
        pageName = defaultPageLink ? defaultPageLink.dataset.page : 'stats';
    }

    const path = `/${pageName}`;
    if (pushState && window.location.pathname !== path) {
        history.pushState({ page: pageName }, '', path);
    }
    
    appContent.classList.add('content-loading');

    try {
        const response = await fetch(path, {
            headers: { 'X-Requested-With': 'fetch' }
        });

        if (!response.ok) {
            if (response.status === 401) return window.location.href = '/login';
            appContent.innerHTML = `<h1>Ошибка ${response.status}</h1><p>Не удалось загрузить содержимое страницы.</p>`;
        } else {
            appContent.innerHTML = await response.text();
        }

        const moduleLoader = pageModules[pageName];
        if (moduleLoader) {
            const module = await moduleLoader();
            if (module.init) {
                module.init();
            }
        }
        
        updateActiveLink(pageName);
    } catch (error) {
        console.error('Error loading page:', error);
        appContent.innerHTML = '<h1>Ошибка загрузки</h1><p>Проверьте подключение к сети и попробуйте снова.</p>';
    } finally {
        appContent.classList.remove('content-loading');
    }
}

function updateActiveLink(pageName) {
    mainNav.querySelectorAll('a').forEach(a => {
        a.classList.toggle('active', a.dataset.page === pageName);
    });
}

function initUI() {
    const sidebarToggle = document.getElementById('sidebar-toggle-btn');
    const sidebarOverlay = document.getElementById('sidebar-overlay');
    const themeToggle = document.getElementById('theme-toggle');

    const closeSidebar = () => {
        mainNav.classList.remove('active');
        sidebarOverlay.classList.remove('active');
    };

    sidebarToggle?.addEventListener('click', () => {
        mainNav.classList.toggle('active');
        sidebarOverlay.classList.toggle('active');
    });

    sidebarOverlay?.addEventListener('click', closeSidebar);
    
    mainNav.addEventListener('click', (e) => {
        if (e.target.tagName === 'A') closeSidebar();
    });

    const currentTheme = localStorage.getItem('theme') || 'light';
    document.documentElement.setAttribute('data-theme', currentTheme);
    if (themeToggle) themeToggle.textContent = currentTheme === 'dark' ? '☀️' : '🌙';

    themeToggle?.addEventListener('click', () => {
        let newTheme = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
        document.documentElement.setAttribute('data-theme', newTheme);
        localStorage.setItem('theme', newTheme);
        themeToggle.textContent = newTheme === 'dark' ? '☀️' : '🌙';
    });
}

function main() {
    initUI();

    mainNav.addEventListener('click', e => {
        const link = e.target.closest('a[data-page]');
        if (link && !link.href.endsWith('/logout')) {
            e.preventDefault();
            loadPage(link.dataset.page);
        }
    });

    window.addEventListener('popstate', e => {
        if (e.state && e.state.page) {
            loadPage(e.state.page, false);
        }
    });

    const initialPage = document.body.dataset.initialPage || window.location.pathname.substring(1) || '';
    history.replaceState({ page: initialPage }, '', `/${initialPage}`);
    loadPage(initialPage, false);
}

document.addEventListener('DOMContentLoaded', main);