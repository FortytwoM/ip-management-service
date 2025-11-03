// static/js/modules/notes.js
import { api, showToast, createModal } from '../lib.js';
import { DataTable } from '../lib.js';

let notesTable;

function handleView(note) {
    if (typeof showdown === 'undefined') {
        showToast('Ошибка: библиотека для отображения не загружена.', 'error');
        return;
    }
    const converter = new showdown.Converter();
    const contentHtml = converter.makeHtml(note.content);

    createModal({
        title: note.title,
        content: `<div class="playbook-content-view">${contentHtml}</div>`,
        footer: `<button type="button" class="btn" data-dismiss>Закрыть</button>`,
    });
}

function handleEdit(note) {
    createModal({
        title: 'Редактировать заметку',
        content: `
            <form id="edit-note-form">
                <input type="hidden" name="note_id" value="${note.id}">
                <div class="form-group">
                    <label for="note-title-edit">Заголовок</label>
                    <input type="text" id="note-title-edit" name="title" value="${note.title.replace(/"/g, '&quot;')}" required>
                </div>
                <div class="form-group">
                    <label for="note-content-edit">Содержимое (Markdown)</label>
                    <textarea id="note-content-edit" name="content" required>${note.content}</textarea>
                </div>
            </form>
        `,
        footer: `
            <button type="button" class="btn" data-dismiss>Отмена</button>
            <button type="submit" class="btn btn-primary" form="edit-note-form">Сохранить</button>
        `,
        onConfirm: async () => {
            const form = document.getElementById('edit-note-form');
            const data = {
                note_id: parseInt(form.elements.note_id.value),
                title: form.elements.title.value,
                content: form.elements.content.value
            };
            await api.post('/api/notes/update', data);
            showToast('Заметка успешно обновлена', 'success');
            notesTable.loadData();
        }
    });
}

function handleDelete(note) {
    createModal({
        title: 'Удалить заметку?',
        content: `<p>Вы уверены, что хотите удалить заметку "<strong>${note.title}</strong>"? Это действие необратимо.</p>`,
        footer: `
            <button type="button" class="btn" data-dismiss>Отмена</button>
            <button type="button" class="btn btn-danger" data-confirm>Удалить</button>
        `,
        onConfirm: async () => {
            await api.post('/api/notes/delete', { note_id: note.id });
            showToast('Заметка удалена', 'success');
            notesTable.loadData();
        }
    });
}

async function handleTogglePin(note) {
    try {
        await api.post('/api/notes/toggle_pin', { note_id: note.id });
        const message = note.is_pinned ? 'Заметка откреплена' : 'Заметка закреплена';
        showToast(message, 'success');
        notesTable.loadData();
    } catch (error) {
        showToast('Не удалось изменить статус заметки.', 'error');
    }
}


function setupEventListeners() {
    document.getElementById('add-note-btn').addEventListener('click', () => {
        createModal({
            title: 'Создать заметку',
            content: `
                <form id="add-note-form">
                    <div class="form-group">
                        <label for="note-title-add">Заголовок</label>
                        <input type="text" id="note-title-add" name="title" required>
                    </div>
                    <div class="form-group">
                        <label for="note-content-add">Содержимое (Markdown)</label>
                        <textarea id="note-content-add" name="content" required></textarea>
                    </div>
                </form>
            `,
            footer: `
                <button type="button" class="btn" data-dismiss>Отмена</button>
                <button type="submit" class="btn btn-primary" form="add-note-form">Создать</button>
            `,
            onConfirm: async () => {
                const form = document.getElementById('add-note-form');
                const data = {
                    title: form.elements.title.value,
                    content: form.elements.content.value
                };
                await api.post('/api/notes', data);
                showToast('Заметка успешно создана', 'success');
                notesTable.loadData();
            }
        });
    });
}

export function init() {
    notesTable = new DataTable({
        tableContainerId: 'notes-table-container',
        paginationContainerId: 'pagination-container',
        apiEndpoint: '/api/notes/list',
        tableClass: 'notes-table',
        columns: [
            { 
                key: 'is_pinned', 
                label: '📌',
                sortable: false,
                render: (is_pinned) => is_pinned ? '📌' : ''
            },
            { key: 'title', label: 'Заголовок', sortable: true },
            { key: 'timestamp_msk', label: 'Дата изменения', sortable: true, defaultSort: 'desc' }
        ],
        actions: [
            { 
                key: 'toggle-pin', 
                label: (note) => note.is_pinned ? 'Открепить' : 'Закрепить', 
                class: 'btn-default', 
                handler: handleTogglePin 
            },
            { key: 'edit', label: 'Изменить', class: 'btn-primary', handler: handleEdit },
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

    notesTable.loadData();
    setupEventListeners();
}