// static/js/modules/bans.js
import { showToast, createModal, api, DataTable } from '../lib.js';

function showBanForm(rowData = null) {
    const isEditing = rowData !== null;
    const title = isEditing ? 'Редактировать бан' : 'Добавить бан';
    const content = `
        <form id="ban-form">
            <div class="form-group">
                <label for="ip">IP</label>
                <input type="text" id="ip" name="ip" value="${rowData?.ip || ''}" required>
            </div>
            <div class="form-group">
                <label for="reason">Причина (опционально)</label>
                <input type="text" id="reason" name="reason" value="${rowData?.reason || ''}">
            </div>
        </form>
    `;
    const footer = `
        <button class="btn" data-dismiss>Отмена</button>
        <button class="btn btn-primary" type="submit" form="ban-form">${isEditing ? 'Сохранить' : 'Добавить'}</button>
    `;

    createModal({
        title,
        content,
        footer,
        onConfirm: async () => {
            const form = document.getElementById('ban-form');
            const payload = {
                ip: form.querySelector('#ip').value,
                reason: form.querySelector('#reason').value,
            };

            if (isEditing) {
                payload.ban_id = rowData.id;
            }

            const endpoint = isEditing ? '/api/bans/update' : '/api/bans';
            await api.post(endpoint, payload);
            showToast(`Бан успешно ${isEditing ? 'обновлен' : 'добавлен'}`, 'success');
            dataTable.loadData();
        }
    });
}

function confirmDelete(rowData) {
    createModal({
        title: 'Подтвердить удаление',
        content: `<p>Вы уверены, что хотите удалить бан для <strong>${rowData.ip}</strong>?</p>`,
        footer: `
            <button class="btn" data-dismiss>Отмена</button>
            <button class="btn btn-danger" data-confirm>Удалить</button>
        `,
        onConfirm: async () => {
            await api.post('/api/bans/delete', { ban_id: rowData.id });
            showToast('Бан успешно удален', 'success');
            dataTable.loadData();
        }
    });
}

async function handleBulkUpload(e) {
    e.preventDefault();
    const form = e.target;
    const fileInput = form.querySelector('input[type="file"]');
    const reasonInput = form.querySelector('input[type="text"]');
    const file = fileInput.files[0];

    if (!file) {
        return showToast('Выберите файл для загрузки', 'warning');
    }

    const formData = new FormData();
    formData.append('file', file);
    formData.append('reason', reasonInput.value || '');

    try {
        const result = await api.post('/api/bans/bulk', formData);
        showToast(`Добавлено ${result.added} банов`, 'success');
        form.reset();
        dataTable.loadData();
    } catch (error) {
    }
}

let dataTable;

export function init() {
    dataTable = new DataTable({
        tableContainerId: 'table-container',
        paginationContainerId: 'pagination-container',
        apiEndpoint: '/api/bans/list',
		tableClass: 'bans-table',
        columns: [
            { key: 'ip', label: 'IP' },
            { key: 'reason', label: 'Причина' },
            { key: 'banned_by', label: 'Кем забанен' },
            { key: 'timestamp_msk', label: 'Время' }
        ],
        actions: [
            { key: 'edit', label: 'Изменить', handler: showBanForm },
            { key: 'delete', label: 'Удалить', class: 'btn-danger', handler: confirmDelete }
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

    document.getElementById('add-ban-btn')?.addEventListener('click', () => showBanForm());
    document.getElementById('bulk-upload-form')?.addEventListener('submit', handleBulkUpload);
	document.getElementById('export-nginx-btn').addEventListener('click', () => {
        window.location.href = '/api/bans/export/nginx';
    });
    document.getElementById('export-iptables-btn').addEventListener('click', () => {
        window.location.href = '/api/bans/export/iptables';
    });
    document.getElementById('export-json-btn').addEventListener('click', () => {
        window.location.href = '/api/bans/export/json';
    });
}