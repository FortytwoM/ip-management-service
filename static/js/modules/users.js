// static/js/modules/users.js
import { showToast, createModal, api, DataTable } from '../lib.js';

let dataTable;

function showCreateUserForm() {
    createModal({
        title: 'Создать пользователя',
        content: `
            <form id="user-form">
                <div class="form-group">
                    <label for="username">Имя пользователя</label>
                    <input type="text" id="username" name="username" required>
                </div>
                <div class="form-group">
                    <label for="password">Пароль</label>
                    <input type="password" id="password" name="password" required>
                </div>
                <div class="form-group">
                    <label for="role">Роль</label>
                    <select id="role" name="role" required>
                        <option value="viewer" selected>Viewer</option>
                        <option value="editor">Editor</option>
                        <option value="admin">Admin</option>
                    </select>
                </div>
            </form>
        `,
        footer: `
            <button class="btn" data-dismiss>Отмена</button>
            <button class="btn btn-primary" type="submit" form="user-form">Создать</button>
        `,
        onConfirm: async () => {
            const form = document.getElementById('user-form');
            const payload = {
                username: form.querySelector('#username').value,
                password: form.querySelector('#password').value,
                role: form.querySelector('#role').value,
            };

            if (!payload.username || !payload.password) {
                showToast('Имя пользователя и пароль обязательны', 'warning');
                throw new Error("Validation failed");
            }
            
            await api.post('/api/users', payload);
            showToast('Пользователь успешно создан', 'success');
            dataTable.loadData();
        }
    });
}

function showUpdateRoleForm(rowData) {
    createModal({
        title: `Изменить роль для ${rowData.username}`,
        content: `
            <form id="role-form">
                <div class="form-group">
                    <label for="role">Новая роль</label>
                    <select id="role" name="role" required>
                        <option value="viewer" ${rowData.role === 'viewer' ? 'selected' : ''}>Viewer</option>
                        <option value="editor" ${rowData.role === 'editor' ? 'selected' : ''}>Editor</option>
                        <option value="admin" ${rowData.role === 'admin' ? 'selected' : ''}>Admin</option>
                    </select>
                </div>
            </form>
        `,
        footer: `
            <button class="btn" data-dismiss>Отмена</button>
            <button class="btn btn-primary" type="submit" form="role-form">Сохранить</button>
        `,
        onConfirm: async () => {
            const form = document.getElementById('role-form');
            const role = form.querySelector('#role').value;
            const payload = { user_id: rowData.id, role };

            await api.post('/api/users/update_role', payload);
            showToast('Роль пользователя успешно обновлена', 'success');
            dataTable.loadData();
        }
    });
}

function showUpdatePasswordForm(rowData) {
    createModal({
        title: `Новый пароль для ${rowData.username}`,
        content: `
            <form id="pass-form">
                <div class="form-group">
                    <label for="password">Новый пароль</label>
                    <input type="password" id="password" name="password" required>
                </div>
            </form>
        `,
        footer: `
            <button class="btn" data-dismiss>Отмена</button>
            <button class="btn btn-primary" type="submit" form="pass-form">Сохранить</button>
        `,
        onConfirm: async () => {
            const form = document.getElementById('pass-form');
            const password = form.querySelector('#password').value;
            
            if (!password) {
                showToast('Пароль не может быть пустым', 'warning');
                throw new Error("Validation failed");
            }
            
            const payload = { user_id: rowData.id, password };
            await api.post('/api/users/update_password', payload);
            showToast('Пароль успешно изменен', 'success');
        }
    });
}

function confirmDeleteUser(rowData) {
    createModal({
        title: 'Удалить пользователя?',
        content: `<p>Вы уверены, что хотите удалить пользователя <strong>${rowData.username}</strong>? Это действие нельзя отменить.</p>`,
        footer: `
            <button class="btn" data-dismiss>Отмена</button>
            <button class="btn btn-danger" data-confirm>Удалить</button>
        `,
        onConfirm: async () => {
            await api.post('/api/users/delete', { user_id: rowData.id });
            showToast('Пользователь удален', 'success');
            dataTable.loadData();
        }
    });
}

async function showApiToken() {
    try {
        const data = await api.post('/api/token');
        if (!data || !data.api_token) throw new Error("Token not received");

        createModal({
            title: 'Ваш API Token',
            content: `
                <p>Скопируйте ваш токен. Он будет показан только один раз.</p>
                <input type="text" readonly value="${data.api_token}" style="width: 100%; padding: 0.5rem; border: 1px solid var(--border-color); border-radius: 4px; font-family: monospace;">
            `,
            footer: `<button class="btn" data-dismiss>Закрыть</button>`
        });
    } catch (error) {
        showToast('Не удалось получить токен', 'error');
    }
}

async function showAuditSettingsForm(rowData) {
    try {
        const settings = await api.get(`/api/users/${rowData.id}/audit_settings`);
        
        createModal({
            title: `Настройки аудита для ${rowData.username}`,
            content: `
                <form id="audit-settings-form">
                    <div class="audit-settings-grid">
                        <fieldset>
                            <legend>Вход и сессии</legend>
                            <label><input type="checkbox" name="log_login_success" ${settings.log_login_success ? 'checked' : ''}> Успешный вход</label>
                            <label><input type="checkbox" name="log_login_failure" ${settings.log_login_failure ? 'checked' : ''}> Неудачный вход</label>
                            <label><input type="checkbox" name="log_logout" ${settings.log_logout ? 'checked' : ''}> Выход</label>
                            <label><input type="checkbox" name="log_api_token_create" ${settings.log_api_token_create ? 'checked' : ''}> Создание API токена</label>
                        </fieldset>
                        <fieldset>
                            <legend>Баны</legend>
                            <label><input type="checkbox" name="log_ban_create" ${settings.log_ban_create ? 'checked' : ''}> Создание</label>
                            <label><input type="checkbox" name="log_ban_update" ${settings.log_ban_update ? 'checked' : ''}> Обновление</label>
                            <label><input type="checkbox" name="log_ban_delete" ${settings.log_ban_delete ? 'checked' : ''}> Удаление</label>
                        </fieldset>
                        <fieldset>
                            <legend>Исключения</legend>
                            <label><input type="checkbox" name="log_exception_create" ${settings.log_exception_create ? 'checked' : ''}> Создание</label>
                            <label><input type="checkbox" name="log_exception_update" ${settings.log_exception_update ? 'checked' : ''}> Обновление</label>
                            <label><input type="checkbox" name="log_exception_delete" ${settings.log_exception_delete ? 'checked' : ''}> Удаление</label>
                        </fieldset>
                         <fieldset>
                            <legend>Пользователи</legend>
                            <label><input type="checkbox" name="log_user_create" ${settings.log_user_create ? 'checked' : ''}> Создание</label>
                            <label><input type="checkbox" name="log_user_update" ${settings.log_user_update ? 'checked' : ''}> Обновление</label>
                            <label><input type="checkbox" name="log_user_delete" ${settings.log_user_delete ? 'checked' : ''}> Удаление</label>
                        </fieldset>
                        <fieldset>
                            <legend>Playbooks</legend>
                            <label><input type="checkbox" name="log_playbook_create" ${settings.log_playbook_create ? 'checked' : ''}> Создание</label>
                            <label><input type="checkbox" name="log_playbook_update" ${settings.log_playbook_update ? 'checked' : ''}> Обновление</label>
                            <label><input type="checkbox" name="log_playbook_delete" ${settings.log_playbook_delete ? 'checked' : ''}> Удаление</label>
                        </fieldset>
                        <fieldset>
                            <legend>Webhooks</legend>
                            <label><input type="checkbox" name="log_webhook_create" ${settings.log_webhook_create ? 'checked' : ''}> Создание</label>
                            <label><input type="checkbox" name="log_webhook_delete" ${settings.log_webhook_delete ? 'checked' : ''}> Удаление</label>
                        </fieldset>
                        <fieldset>
                            <legend>Active Directory</legend>
                            <label><input type="checkbox" name="log_ad_domain_cud" ${settings.log_ad_domain_cud ? 'checked' : ''}> Домены (созд./изм./удал.)</label>
                            <label><input type="checkbox" name="log_ad_group_cud" ${settings.log_ad_group_cud ? 'checked' : ''}> Управляемые группы</label>
                            <label><input type="checkbox" name="log_ad_membership_cud" ${settings.log_ad_membership_cud ? 'checked' : ''}> Членство в группах</label>
                        </fieldset>
                    </div>
                </form>
                <style>
                    .audit-settings-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 1.5rem; }
                    .audit-settings-grid fieldset { border: 1px solid var(--border-color); border-radius: var(--border-radius); padding: 1rem; }
                    .audit-settings-grid legend { font-weight: 600; padding: 0 0.5rem; }
                    .audit-settings-grid label { display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.5rem; }
                </style>
            `,
            footer: `
                <button class="btn" data-dismiss>Отмена</button>
                <button class="btn btn-primary" type="submit" form="audit-settings-form">Сохранить</button>
            `,
            onConfirm: async () => {
                const form = document.getElementById('audit-settings-form');
                const payload = {};
                form.querySelectorAll('input[type="checkbox"]').forEach(input => {
                    payload[input.name] = input.checked;
                });

                await api.post(`/api/users/${rowData.id}/audit_settings`, payload);
                showToast('Настройки аудита обновлены', 'success');
            }
        });
    } catch (error) {
        showToast('Не удалось загрузить настройки аудита', 'error');
    }
}

export function init() {
    dataTable = new DataTable({
        tableContainerId: 'table-container',
        paginationContainerId: 'pagination-container',
        apiEndpoint: '/api/users/list',
        tableClass: 'users-table',
        columns: [
            { key: 'username', label: 'Имя пользователя' },
            { 
                key: 'role', 
                label: 'Роль',
                render: (roleValue) => `<span class="user-role-badge ${roleValue}">${roleValue}</span>`
            }
        ],
        actions: [
            { key: 'edit-pass', label: 'Изменить пароль', handler: showUpdatePasswordForm },
            { key: 'edit-role', label: 'Изменить роль', handler: showUpdateRoleForm },
            { key: 'audit-settings', label: 'Настройки аудита', handler: showAuditSettingsForm },
            { key: 'delete', label: 'Удалить', class: 'btn-danger', handler: confirmDeleteUser }
        ],
        searchHandler: (callback) => {
            const searchInput = document.getElementById('search-input');
            if (searchInput) {
                let debounceTimer;
                searchInput.addEventListener('input', (e) => {
                    clearTimeout(debounceTimer);
                    debounceTimer = setTimeout(() => {
                        callback(e.target.value);
                    }, 300);
                });
            }
        }
    });

    dataTable.loadData();

    document.getElementById('add-user-btn')?.addEventListener('click', showCreateUserForm);
    document.getElementById('show-api-token-btn')?.addEventListener('click', showApiToken);
}