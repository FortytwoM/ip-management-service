// static/js/modules/webhooks.js
import { api, createModal, showToast } from '../lib.js';

let container;

async function loadWebhooks() {
    if (!container) return;
    try {
        const hooks = await api.get('/api/webhooks/list');
        renderWebhooks(hooks);
    } catch (error) {
        container.innerHTML = '<p>Не удалось загрузить вебхуки.</p>';
    }
}

function renderWebhooks(hooks) {
    if (!container) return;

    if (hooks.length === 0) {
        container.innerHTML = '<div class="app-card text-center"><p>Вебхуки еще не добавлены.</p></div>';
        return;
    }

    container.innerHTML = `
        <div class="table-container">
            <table class="data-table webhooks-table">
                <thead>
                    <tr>
                        <th>URL</th>
                        <th>Автор</th>
                        <th>Создан</th>
                        <th>Действия</th>
                    </tr>
                </thead>
                <tbody>
                    ${hooks.map(h => `
                        <tr data-id="${h.id}">
                            <td>${h.url}</td>
                            <td>${h.created_by}</td>
                            <td>${h.timestamp_msk}</td>
                            <td>
                                <button class="btn btn-small btn-danger" data-action="delete">Удалить</button>
                            </td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>
    `;
}

function handleAddWebhook() {
    createModal({
        title: 'Добавить новый вебхук',
        content: `
            <form id="add-webhook-form">
                <div class="form-group">
                    <label for="webhook-url">URL</label>
                    <input type="url" id="webhook-url" name="url" required placeholder="https://example.com/webhook">
                </div>
            </form>
        `,
        footer: `
            <button type="button" class="btn" data-dismiss>Отмена</button>
            <button type="submit" class="btn btn-primary" form="add-webhook-form">Сохранить</button>
        `,
        onConfirm: async () => {
            const form = document.getElementById('add-webhook-form');
            const url = form.elements.url.value;
            await api.post('/api/webhooks', { url });
            showToast('Вебхук успешно добавлен', 'success');
            loadWebhooks();
        }
    });
}

function handleDeleteWebhook(hookId) {
     createModal({
        title: 'Подтвердите удаление',
        content: '<p>Вы уверены, что хотите удалить этот вебхук?</p>',
        footer: `
            <button type="button" class="btn" data-dismiss>Отмена</button>
            <button type="button" class="btn btn-danger" data-confirm>Удалить</button>
        `,
        onConfirm: async () => {
            await api.post('/api/webhooks/delete', { webhook_id: parseInt(hookId, 10) });
            showToast('Вебхук удален', 'success');
            loadWebhooks();
        }
    });
}


export function init() {
    container = document.getElementById('table-container');
    if (!container) {
        console.error("Webhook container element not found!");
        return;
    }

    document.getElementById('add-webhook-btn').addEventListener('click', handleAddWebhook);

    container.addEventListener('click', e => {
        const btn = e.target.closest('button[data-action="delete"]');
        if (btn) {
            const hookId = btn.closest('tr').dataset.id;
            handleDeleteWebhook(hookId);
        }
    });

    loadWebhooks();
}