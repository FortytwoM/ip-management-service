// static/js/modules/ad_settings.js
import { showToast, createModal, api } from '../lib.js';

let domains = [];

async function loadDomains() {
    const container = document.getElementById('domains-list');
    try {
        domains = await api.get('/api/ad/domains');
        if (domains.length === 0) {
            container.innerHTML = '<p>Домены не настроены.</p>';
        } else {
            container.innerHTML = `
                <table class="data-table">
                    <thead><tr><th>Имя</th><th>Хост</th><th>Пользователь</th><th>Base DN</th><th>Действия</th></tr></thead>
                    <tbody>
                        ${domains.map(d => `
                            <tr data-id="${d.id}">
                                <td>${d.name}</td>
                                <td>${d.host}:${d.port}</td>
                                <td>${d.bind_user}</td>
                                <td>${d.base_dn}</td>
                                <td>
                                    <button class="btn btn-small" data-action="edit">Изменить</button>
                                    <button class="btn btn-small" data-action="refresh">Обновить кэш</button>
                                    <button class="btn btn-small btn-danger" data-action="delete">Удалить</button>
                                </td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            `;
        }
        populateDomainSelect();
        addDomainEventListeners();
    } catch (error) {
        container.innerHTML = '<p>Не удалось загрузить список доменов.</p>';
    }
}

function showDomainForm(domain = null) {
    const isEditing = domain !== null;
    const title = isEditing ? 'Редактировать домен AD' : 'Добавить домен AD';

    const content = `
        <form id="domain-form">
            <div class="form-group"><label>Имя</label><input type="text" name="name" value="${domain?.name || ''}" required></div>
            <div class="form-group"><label>Хост</label><input type="text" name="host" value="${domain?.host || ''}" required></div>
            <div class="form-group"><label>Порт</label><input type="number" name="port" value="${domain?.port || 389}" required></div>
            <div class="form-group"><label>Base DN</label><input type="text" name="base_dn" placeholder="OU=Users,DC=example,DC=com" value="${domain?.base_dn || ''}" required></div>
            <div class="form-group"><label>Пользователь для подключения (Bind User)</label><input type="text" name="bind_user" placeholder="CN=binder,CN=Users,DC=example,DC=com" value="${domain?.bind_user || ''}" required></div>
            <div class="form-group">
                <label>Пароль</label>
                <input type="password" name="bind_pass" placeholder="${isEditing ? 'Оставьте пустым, чтобы не менять' : ''}" ${isEditing ? '' : 'required'}>
            </div>
            <div class="checkbox-group">
                <input type="checkbox" name="use_ssl" id="use_ssl_checkbox" ${domain?.use_ssl ? 'checked' : ''}>
                <label for="use_ssl_checkbox">Использовать SSL</label>
            </div>
        </form>
    `;
    const footer = `
        <button class="btn" id="test-conn-btn">Тест</button>
        <button class="btn" data-dismiss>Отмена</button>
        <button class="btn btn-primary" type="submit" form="domain-form">Сохранить</button>
    `;
    
    const getPayload = (form) => {
        const formData = new FormData(form);
        const payload = Object.fromEntries(formData.entries());
        payload.port = parseInt(payload.port, 10);
        payload.use_ssl = form.querySelector('[name="use_ssl"]').checked;
        return payload;
    };

    createModal({
        title,
        content,
        footer,
        onConfirm: async () => {
            const form = document.getElementById('domain-form');
            const payload = getPayload(form);
            
            if (isEditing) {
                payload.domain_id = domain.id;
                if (!payload.bind_pass) {
                    delete payload.bind_pass;
                }
                await api.post('/api/ad/domains/update', payload);
                showToast('Домен успешно обновлен', 'success');
            } else {
                await api.post('/api/ad/domains', payload);
                showToast('Домен успешно добавлен', 'success');
            }
            
            loadDomains();
            loadManagedGroups();
        }
    });

    document.getElementById('test-conn-btn').addEventListener('click', async (e) => {
        const btn = e.target;
        btn.disabled = true;
        btn.textContent = 'Проверка...';
        const form = document.getElementById('domain-form');
        const payload = getPayload(form);

        try {
            await api.post('/api/ad/domains/test', payload);
            showToast('Подключение успешно!', 'success');
        } finally {
            btn.disabled = false;
            btn.textContent = 'Тест';
        }
    });
}


function addDomainEventListeners() {
    document.getElementById('domains-list').addEventListener('click', async e => {
        const btn = e.target.closest('button[data-action]');
        if (!btn) return;

        const action = btn.dataset.action;
        const row = btn.closest('tr');
        const domainId = parseInt(row.dataset.id, 10);
        const domain = domains.find(d => d.id === domainId);

        if (!domain) return;

        if (action === 'edit') {
            showDomainForm(domain);
        } else if (action === 'refresh') {
            btn.disabled = true;
            btn.textContent = 'Обновление...';
            try {
                await api.post('/api/ad/domains/refresh_cache', { domain_id: domainId });
                showToast('Запущено обновление кэша домена', 'info');
            } finally {
                setTimeout(() => {
                    btn.disabled = false;
                    btn.textContent = 'Обновить кэш';
                }, 2000);
            }
        } else if (action === 'delete') {
            createModal({
                title: 'Удалить домен?',
                content: `<p>Вы уверены, что хотите удалить домен <strong>${domain.name}</strong>? Все связанные управляемые группы и выданные доступы также будут удалены.</p>`,
                footer: `<button class="btn" data-dismiss>Отмена</button><button class="btn btn-danger" data-confirm>Удалить</button>`,
                onConfirm: async () => {
                    await api.post('/api/ad/domains/delete', { domain_id: domainId });
                    showToast('Домен удален', 'success');
                    document.getElementById('managed-group-domain-select').value = '';
                    document.getElementById('group-management-area').style.display = 'none';
                    
                    loadDomains();
                    loadManagedGroups();
                }
            });
        }
    });
}

async function loadManagedGroups() {
    const domainId = document.getElementById('managed-group-domain-select').value;
    const container = document.getElementById('managed-groups-container');
    container.innerHTML = '';
    if (!domainId) return;

    try {
        const managedGroups = await api.get(`/api/ad/groups/managed?domain_id=${domainId}`);
        if (managedGroups.length > 0) {
            container.innerHTML = `
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Имя группы</th>
                            <th>Автоочистка</th>
                            <th>Действия</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${managedGroups.map(g => `
                            <tr data-group-id="${g.id}">
                                <td>${g.group_name}</td>
                                <td>
                                    <label class="switch">
                                        <input type="checkbox" class="cleanup-toggle" ${g.cleanup_enabled ? 'checked' : ''}>
                                        <span class="slider round"></span>
                                    </label>
                                </td>
                                <td>
                                    <button class="btn btn-small btn-danger delete-group-btn">Удалить</button>
                                </td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            `;
        } else {
            container.innerHTML = '<p>Нет управляемых групп для этого домена.</p>';
        }
    } catch (error) {
         container.innerHTML = '<p>Не удалось загрузить управляемые группы.</p>';
    }
}

function addManagedGroupsEventListeners() {
    const container = document.getElementById('managed-groups-container');

    container.addEventListener('click', e => {
        const target = e.target;
        if (target.classList.contains('delete-group-btn')) {
            const row = target.closest('tr');
            const groupId = parseInt(row.dataset.groupId, 10);
            const groupName = row.cells[0].textContent;
            
            createModal({
                title: 'Удалить группу?',
                content: `<p>Удалить <strong>${groupName}</strong> из списка управляемых?</p><p>Это не удалит группу из Active Directory.</p>`,
                footer: `<button class="btn" data-dismiss>Отмена</button><button class="btn btn-danger" data-confirm>Удалить</button>`,
                onConfirm: async () => {
                    await api.post('/api/ad/groups/managed/delete', { group_id: groupId });
                    showToast('Группа удалена из списка управляемых', 'success');
                    loadManagedGroups();
                }
            });
        }
    });

    container.addEventListener('change', async e => {
        const target = e.target;
        if (target.classList.contains('cleanup-toggle')) {
            const row = target.closest('tr');
            const groupId = parseInt(row.dataset.groupId, 10);
            const enabled = target.checked;
            
            try {
                await api.post('/api/ad/groups/managed/toggle_cleanup', { group_id: groupId, enabled: enabled });
                showToast(`Автоочистка ${enabled ? 'включена' : 'выключена'}`, 'success');
            } catch (error) {
                target.checked = !enabled;
            }
        }
    });
}


function populateDomainSelect() {
    const select = document.getElementById('managed-group-domain-select');
    select.innerHTML = '<option value="">-- Сначала выберите домен --</option>' +
        domains.map(d => `<option value="${d.id}">${d.name}</option>`).join('');
}

function initGroupManagement() {
    const domainSelect = document.getElementById('managed-group-domain-select');
    const groupArea = document.getElementById('group-management-area');
    const searchInput = document.getElementById('group-search-input');
    const searchResults = document.getElementById('group-search-results');
    
    domainSelect.addEventListener('change', () => {
        const domainId = domainSelect.value;
        groupArea.style.display = domainId ? 'block' : 'none';
        searchInput.value = '';
        searchResults.innerHTML = '';
        loadManagedGroups();
    });

    let debounceTimer;
    searchInput.addEventListener('input', e => {
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(async () => {
            const query = e.target.value;
            const domainId = domainSelect.value;
            if (query.length < 3) {
                searchResults.innerHTML = '';
                return;
            }
            try {
                const data = await api.get(`/api/ad/groups/search?domain_id=${domainId}&q=${query}`);
                searchResults.innerHTML = data.results.map(g =>
                    `<div class="search-result-item" data-dn="${g.dn}" data-name="${g.name}">${g.name} (${g.dn})</div>`
                ).join('');
            } catch (error) {
                 searchResults.innerHTML = '<div class="search-result-item error">Поиск не удался</div>';
            }
        }, 500);
    });

    searchResults.addEventListener('click', async e => {
        if (e.target.classList.contains('search-result-item') && !e.target.classList.contains('error')) {
            const payload = {
                domain_id: parseInt(domainSelect.value, 10),
                group_dn: e.target.dataset.dn,
                group_name: e.target.dataset.name
            };
            try {
                await api.post('/api/ad/groups/managed', payload);
                showToast('Группа добавлена в список управляемых', 'success');
                searchInput.value = '';
                searchResults.innerHTML = '';
                loadManagedGroups();
            } catch (error) {
            }
        }
    });
}

export function init() {
    loadDomains();
    document.getElementById('add-domain-btn').addEventListener('click', () => showDomainForm());
    initGroupManagement();
    addManagedGroupsEventListeners();
}