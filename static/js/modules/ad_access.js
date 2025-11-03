// static/js/modules/ad_access.js
import { showToast, createModal, DataTable, api } from '../lib.js';

let dataTable;
let domains = [];
let managedGroups = [];

async function loadPrerequisites() {
    try {
        const [domainData, groupData] = await Promise.all([
            api.get('/api/ad/domains'),
            api.get('/api/ad/groups/managed')
        ]);
        domains = domainData;
        managedGroups = groupData;
        return true;
    } catch (error) {
        showToast('Не удалось загрузить начальные данные AD. Некоторые функции могут не работать.', 'error');
        return false;
    }
}


async function showGrantAccessForm() {
    if (domains.length === 0) {
        return showToast('Не настроено ни одного домена AD. Пожалуйста, добавьте домен в настройках.', 'warning');
    }
    if (managedGroups.length === 0) {
        return showToast('Не настроено ни одной управляемой группы. Пожалуйста, добавьте группы в настройках.', 'warning');
    }

    const content = `
        <form id="grant-access-form">
            <div class="form-group">
                <label for="ad-domain">1. Выберите домен</label>
                <select id="ad-domain" name="domain" required>
                    <option value="">-- Выберите домен --</option>
                    ${domains.map(d => `<option value="${d.id}">${d.name}</option>`).join('')}
                </select>
            </div>
            <div class="form-group" style="display: none;">
                <label for="ad-group">2. Выберите группу</label>
                <select id="ad-group" name="group" required></select>
            </div>
            <div class="form-group" style="display: none;">
                <label for="ad-user-search">3. Найдите пользователя</label>
                <input type="text" id="ad-user-search" placeholder="Начните вводить имя или логин...">
                <div class="search-results-container" id="user-search-results"></div>
                <input type="hidden" id="ad-user-cache-id" name="user_cache_id">
                <p>Выбранный пользователь: <strong id="selected-user-display">Никто</strong></p>
            </div>
            
            <div id="final-steps" style="display: none;">
                <div class="form-group">
                    <label for="approved-by">4. Согласовано (опционально)</label>
                    <input type="text" id="approved-by" name="approved_by" placeholder="ФИО или номер заявки">
                </div>
                <div class="form-group">
                    <label for="expires-at">5. Срок действия по МСК (опционально)</label>
                    <input type="text" id="expires-at" name="expires_at" placeholder="ДД.ММ.ГГГГ ЧЧ:ММ">
                    <p class="form-hint">
                        Пример: 31.12.2025 18:00. Если время не указано, будет 00:00.
                    </p>
                </div>
            </div>

        </form>
    `;

    const footer = `
        <button class="btn" data-dismiss>Отмена</button>
        <button class="btn btn-primary" type="submit" form="grant-access-form">Выдать доступ</button>
    `;

    createModal({
        title: 'Выдача доступа в группу AD',
        content,
        footer,
        onConfirm: async () => {
            const form = document.getElementById('grant-access-form');
            const userCacheId = form.querySelector('#ad-user-cache-id').value;
            const groupDn = form.querySelector('#ad-group').value;
            const domainId = form.querySelector('#ad-domain').value;
            const expiresAtValue = form.querySelector('#expires-at').value.trim();
            const approvedBy = form.querySelector('#approved-by').value.trim();

            if (!userCacheId || !groupDn || !domainId) {
                showToast('Пожалуйста, выберите домен, группу и пользователя.', 'warning');
                throw new Error("Форма не заполнена");
            }
            
			let expiresAtISO = null;
			if (expiresAtValue) {
				const parts = expiresAtValue.match(/^(\d{2})\.(\d{2})\.(\d{4})(?:\s+(\d{2}):(\d{2}))?$/);
				if (!parts) {
					showToast('Неверный формат. Ожидается: ДД.ММ.ГГГГ или ДД.ММ.ГГГГ ЧЧ:ММ (24ч).', 'error');
					throw new Error('Неверный формат даты');
				}
				const [, day, month, year, hour = '00', minute = '00'] = parts;
				
				const validationDate = new Date(Date.UTC(year, parseInt(month, 10) - 1, day));
				if (isNaN(validationDate.getTime()) || validationDate.getUTCDate() !== parseInt(day)) {
					showToast('Некорректная дата (например, 32-е число). Проверьте ввод.', 'error');
					throw new Error('Некорректное значение даты');
				}

				const userTimeAsUTC = Date.UTC(year, parseInt(month, 10) - 1, day, parseInt(hour, 10) - 3, minute);

				if (userTimeAsUTC < Date.now()) {
					showToast('Нельзя установить дату истечения в прошлом (по московскому времени).', 'error');
					throw new Error('Дата в прошлом');
				}

				expiresAtISO = `${year}-${month.padStart(2, '0')}-${day.padStart(2, '0')}T${hour.padStart(2, '0')}:${minute.padStart(2, '0')}:00+03:00`;
			}
            
            const payload = {
                domain_id: parseInt(domainId),
                group_dn: groupDn,
                user_cache_id: parseInt(userCacheId),
                approved_by: approvedBy,
                expires_at: expiresAtISO
            };
            
            await api.post('/api/ad/memberships', payload);
            showToast('Запрос на выдачу доступа поставлен в очередь', 'success');
            dataTable.loadData();
        }
    });

    const domainSelect = document.getElementById('ad-domain');
    const groupSelect = document.getElementById('ad-group');
    const userSearchInput = document.getElementById('ad-user-search');
    const finalSteps = document.getElementById('final-steps');

    domainSelect.addEventListener('change', () => {
        const domainId = domainSelect.value;
        groupSelect.parentElement.style.display = domainId ? 'block' : 'none';
        userSearchInput.parentElement.style.display = 'none';
        finalSteps.style.display = 'none';
        document.getElementById('selected-user-display').textContent = 'Никто';
        document.getElementById('ad-user-cache-id').value = '';

        const relevantGroups = managedGroups.filter(g => g.domain_id == domainId);
        groupSelect.innerHTML = '<option value="">-- Выберите группу --</option>' + 
            relevantGroups.map(g => `<option value="${g.group_dn}">${g.group_name}</option>`).join('');
    });

    groupSelect.addEventListener('change', () => {
        userSearchInput.parentElement.style.display = groupSelect.value ? 'block' : 'none';
        finalSteps.style.display = 'none';
    });
    
    let debounceTimer;
    userSearchInput.addEventListener('input', (e) => {
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(async () => {
            const query = e.target.value;
            const domainId = domainSelect.value;
            const resultsContainer = document.getElementById('user-search-results');
            if (query.length < 3) {
                resultsContainer.innerHTML = '';
                return;
            }
            try {
                const data = await api.get(`/api/ad/users/search?domain_id=${domainId}&q=${query}`);
                resultsContainer.innerHTML = data.results.map(u => 
                    `<div class="search-result-item" data-id="${u.id}" data-display="${u.displayName}" data-upn="${u.upn || ''}">
                        ${u.displayName} <span class="text-muted">(${u.upn || 'N/A'})</span>
                    </div>`
                ).join('');
            } catch (error) {
                resultsContainer.innerHTML = '<div class="search-result-item error">Не удалось загрузить пользователей</div>';
            }
        }, 300);
    });

    document.getElementById('user-search-results').addEventListener('click', (e) => {
        const item = e.target.closest('.search-result-item');
        if (item && !item.classList.contains('error')) {
            document.getElementById('ad-user-cache-id').value = item.dataset.id;
            document.getElementById('selected-user-display').textContent = `${item.dataset.display} (${item.dataset.upn || 'N/A'})`;
            document.getElementById('user-search-results').innerHTML = '';
            userSearchInput.value = '';
            finalSteps.style.display = 'block';
        }
    });
}

export async function init() {
    const prerequisitesLoaded = await loadPrerequisites();
    if (!prerequisitesLoaded) {
        document.getElementById('table-container').innerHTML = '<p>Не удалось инициализировать модуль из-за ошибки загрузки данных AD.</p>';
        return;
    }

    const columns = [
        { 
            key: 'user', 
            label: 'Пользователь',
            sortable: true,
            render: (value, row) => `${row.user}<br><small class="text-muted">${row.user_principal_name || 'N/A'}</small>`
        },
        { key: 'group', label: 'Группа', sortable: true },
        { 
            key: 'sync_status', 
            label: 'Статус', 
            sortable: true,
            render: (value, row) => {
                switch(value) {
                    case 'active':
                        return '<span class="status-badge status-active">Активен</span>';
                    case 'pending_add':
                        return '<span class="status-badge status-pending">В ожидании добавления</span>';
                    case 'pending_remove':
                        return '<span class="status-badge status-pending">В ожидании удаления</span>';
                    case 'error':
                        return `<span class="status-badge status-error" title="${row.sync_message || ''}">Ошибка</span>`;
                    default:
                        return `<span class="status-badge">${value}</span>`;
                }
            }
        },
        { key: 'granted_by', label: 'Кем выдан', sortable: true },
        { key: 'approved_by', label: 'Согласовано', sortable: true },
        { key: 'granted_at', label: 'Когда выдан', sortable: true, defaultSort: 'desc' },
        { key: 'expires_at', label: 'Истекает', sortable: true }
    ];

    const actions = [
        {
            key: 'retry',
            label: 'Повторить',
            class: 'btn-warning',
            show: (row) => row.sync_status === 'error',
            handler: (row) => {
                createModal({
                    title: 'Повторить синхронизацию?',
                    content: `<p>Вы уверены, что хотите повторно запустить синхронизацию для <strong>${row.user}</strong> в группе <strong>${row.group}</strong>?</p>`,
                    footer: `<button class="btn" data-dismiss>Отмена</button><button class="btn btn-primary" data-confirm>Запустить</button>`,
                    onConfirm: async () => {
                        await api.post('/api/ad/memberships/retry', { grant_id: row.id });
                        showToast('Запрос на повторную синхронизацию отправлен', 'success');
                        dataTable.loadData();
                    }
                });
            }
        },
        {
            key: 'revoke',
            label: 'Отозвать',
            class: 'btn-danger',
            handler: (row) => {
                createModal({
                    title: 'Отозвать доступ?',
                    content: `<p>Вы уверены, что хотите отозвать доступ для <strong>${row.user}</strong> из группы <strong>${row.group}</strong>? Запрос будет поставлен в очередь.</p>`,
                    footer: `<button class="btn" data-dismiss>Отмена</button><button class="btn btn-danger" data-confirm>Отозвать</button>`,
                    onConfirm: async () => {
                        await api.post('/api/ad/memberships/delete', { grant_id: row.id });
                        showToast('Запрос на отзыв доступа поставлен в очередь', 'success');
                        dataTable.loadData();
                    }
                });
            }
        }
    ];

    dataTable = new DataTable({
        tableContainerId: 'table-container',
        paginationContainerId: 'pagination-container',
        apiEndpoint: '/api/ad/memberships',
        columns: columns,
        actions: actions,
        searchHandler: (callback) => {
            const searchInput = document.getElementById('search-input');
            let debounceTimer;
            searchInput.addEventListener('input', (e) => {
                clearTimeout(debounceTimer);
                debounceTimer = setTimeout(() => {
                    callback(e.target.value);
                }, 300);
            });
        }
    });

    dataTable.loadData();

    document.getElementById('add-access-btn').addEventListener('click', showGrantAccessForm);
}
