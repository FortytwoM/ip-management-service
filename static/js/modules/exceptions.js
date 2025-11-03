// static/js/modules/exceptions.js
import { showToast, createModal, api, DataTable } from '../lib.js';

function showExceptionForm(rowData = null) {
    const isEditing = rowData !== null;
    const title = isEditing ? 'Редактировать исключение' : 'Добавить исключение';
    const content = `
        <form id="exception-form">
            <div class="form-group">
                <label for="ip">IP или CIDR</label>
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
        <button class="btn btn-primary" type="submit" form="exception-form">${isEditing ? 'Сохранить' : 'Добавить'}</button>
    `;

    createModal({
        title,
        content,
        footer,
        onConfirm: async () => {
            const form = document.getElementById('exception-form');
            const payload = {
                ip: form.querySelector('#ip').value,
                reason: form.querySelector('#reason').value,
            };

            if (isEditing) {
                payload.exc_id = rowData.id;
            }

            const endpoint = isEditing ? '/api/exceptions/update' : '/api/exceptions';
            await api.post(endpoint, payload);
            showToast(`Исключение успешно ${isEditing ? 'обновлено' : 'добавлено'}`, 'success');
            dataTable.loadData();
        }
    });
}

function confirmDelete(rowData) {
    createModal({
        title: 'Подтвердить удаление',
        content: `<p>Вы уверены, что хотите удалить исключение для <strong>${rowData.ip}</strong>?</p>`,
        footer: `
            <button class="btn" data-dismiss>Отмена</button>
            <button class="btn btn-danger" data-confirm>Удалить</button>
        `,
        onConfirm: async () => {
            await api.post('/api/exceptions/delete', { exc_id: rowData.id });
            showToast('Исключение успешно удалено', 'success');
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
        const result = await api.post('/api/exceptions/bulk', formData);
        showToast(`Добавлено ${result.added} исключений`, 'success');
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
        apiEndpoint: '/api/exceptions/list',
		tableClass: 'exceptions-table',
        columns: [
            { key: 'ip', label: 'IP/CIDR' },
            { key: 'reason', label: 'Причина' },
            { key: 'added_by', label: 'Кем добавлен' },
            { key: 'timestamp_msk', label: 'Время' }
        ],
        actions: [
            { key: 'edit', label: 'Изменить', handler: showExceptionForm },
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
    document.getElementById('add-exc-btn')?.addEventListener('click', () => showExceptionForm());
    document.getElementById('bulk-upload-form')?.addEventListener('submit', handleBulkUpload);
}