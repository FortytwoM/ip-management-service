// static/js/modules/playbooks.js
import { api, showToast, createModal } from '../lib.js';
import { DataTable } from '../lib.js';

let playbooksTable;

function handleView(playbook) {
    if (typeof showdown === 'undefined') {
        showToast('Ошибка: библиотека для отображения не загружена.', 'error');
        return;
    }
    const converter = new showdown.Converter();
    const contentHtml = converter.makeHtml(playbook.content);

    createModal({
        title: playbook.name,
        content: `<div class="playbook-content-view">${contentHtml}</div>`,
        footer: `<button type="button" class="btn" data-dismiss>Закрыть</button>`,
    });
}

function handleEdit(playbook) {
    createModal({
        title: 'Редактировать плейбук',
        content: `
            <form id="edit-playbook-form">
                <input type="hidden" name="playbook_id" value="${playbook.id}">
                <div class="form-group">
                    <label for="playbook-name-edit">Название</label>
                    <input type="text" id="playbook-name-edit" name="name" value="${playbook.name.replace(/"/g, '&quot;')}" required>
                </div>
                <div class="form-group">
                    <label for="playbook-content-edit">Содержимое (Markdown)</label>
                    <textarea id="playbook-content-edit" name="content" required>${playbook.content}</textarea>
                </div>
            </form>
        `,
        footer: `
            <button type="button" class="btn" data-dismiss>Отмена</button>
            <button type="submit" class="btn btn-primary" form="edit-playbook-form">Сохранить</button>
        `,
        onConfirm: async () => {
            const form = document.getElementById('edit-playbook-form');
            const data = {
                playbook_id: parseInt(form.elements.playbook_id.value),
                name: form.elements.name.value,
                content: form.elements.content.value
            };
            await api.post('/api/playbooks/update', data);
            showToast('Плейбук успешно обновлен', 'success');
            playbooksTable.loadData();
        }
    });
}

function handleDelete(playbook) {
    createModal({
        title: 'Удалить плейбук?',
        content: `<p>Вы уверены, что хотите удалить плейбук "<strong>${playbook.name}</strong>"? Это действие необратимо.</p>`,
        footer: `
            <button type="button" class="btn" data-dismiss>Отмена</button>
            <button type="button" class="btn btn-danger" data-confirm>Удалить</button>
        `,
        onConfirm: async () => {
            await api.post('/api/playbooks/delete', { playbook_id: playbook.id });
            showToast('Плейбук удален', 'success');
            playbooksTable.loadData();
        }
    });
}

function setupEventListeners() {
    document.getElementById('add-playbook-btn').addEventListener('click', () => {
        createModal({
            title: 'Создать плейбук',
            content: `
                <form id="add-playbook-form">
                    <div class="form-group">
                        <label for="playbook-name-add">Название</label>
                        <input type="text" id="playbook-name-add" name="name" required>
                    </div>
                    <div class="form-group">
                        <label for="playbook-content-add">Содержимое (Markdown)</label>
                        <textarea id="playbook-content-add" name="content" required></textarea>
                    </div>
                </form>
            `,
            footer: `
                <button type="button" class="btn" data-dismiss>Отмена</button>
                <button type="submit" class="btn btn-primary" form="add-playbook-form">Создать</button>
            `,
            onConfirm: async () => {
                const form = document.getElementById('add-playbook-form');
                const data = {
                    name: form.elements.name.value,
                    content: form.elements.content.value
                };
                await api.post('/api/playbooks', data);
                showToast('Плейбук успешно создан', 'success');
                playbooksTable.loadData();
            }
        });
    });
}

export function init() {
    playbooksTable = new DataTable({
        tableContainerId: 'playbooks-table-container',
        paginationContainerId: 'pagination-container',
        apiEndpoint: '/api/playbooks/list',
        tableClass: 'playbooks-table',
        columns: [
            { key: 'name', label: 'Название' },
            { key: 'created_by', label: 'Автор' },
            { key: 'timestamp_msk', label: 'Дата создания' }
        ],
        actions: [
            { key: 'edit', label: 'Редактировать', class: 'btn-primary', handler: handleEdit },
            { key: 'delete', label: 'Удалить', class: 'btn-danger', handler: handleDelete }
        ],
        onRowClick: (rowData) => {
            handleView(rowData);
        },
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

    playbooksTable.loadData();
    setupEventListeners();
}