// static/js/lib.js

async function apiRequest(endpoint, method = 'GET', body = null) {
    const options = {
        method,
        headers: {
            'Accept': 'application/json',
        }
    };

    if (body) {
        if (body instanceof FormData) {
            options.body = body;
        } else if (typeof body === 'object') {
            options.headers['Content-Type'] = 'application/json';
            options.body = JSON.stringify(body);
        }
    }

    try {
        const response = await fetch(endpoint, options);
        if (!response.ok) {
            const data = await response.json().catch(() => ({ detail: `HTTP error! Status: ${response.status}` }));
            throw new Error(data.detail || `An unknown API error occurred.`);
        }
        if (response.status === 204 || response.headers.get('content-length') === '0') {
            return { ok: true };
        }
        return await response.json();
    } catch (error) {
        console.error(`API request failed: ${method} ${endpoint}`, error);
        showToast(error.message, 'error');
        throw error;
    }
}

export const api = {
    get: (endpoint) => apiRequest(endpoint),
    post: (endpoint, body) => apiRequest(endpoint, 'POST', body),
};


export function showToast(message, type = 'info', duration = 4000) {
    const container = document.getElementById('toast-outlet');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;
    container.appendChild(toast);

    requestAnimationFrame(() => {
        toast.classList.add('visible');
    });

    setTimeout(() => {
        toast.classList.remove('visible');
        toast.addEventListener('transitionend', () => toast.remove());
    }, duration);
}


export function createModal({ title, content, footer, onConfirm }) {
    const modalOutlet = document.getElementById('modal-outlet');
    if (!modalOutlet) return;
    
    const modalOverlay = document.createElement('div');
    modalOverlay.className = 'modal-overlay';
    modalOverlay.innerHTML = `
        <div class="modal-content" role="dialog" aria-modal="true" aria-labelledby="modal-title">
            <div class="modal-header" id="modal-title">${title}</div>
            <div class="modal-body">${content}</div>
            <div class="modal-footer">${footer}</div>
        </div>
    `;

    modalOutlet.appendChild(modalOverlay);

    const closeModal = () => {
        modalOverlay.classList.remove('visible');
        modalOverlay.addEventListener('transitionend', () => modalOverlay.remove());
    };

    modalOverlay.addEventListener('click', (e) => {
        if (e.target === modalOverlay) closeModal();
    });

    modalOverlay.querySelector('[data-dismiss]')?.addEventListener('click', closeModal);

    const form = modalOverlay.querySelector('form');
    const confirmButton = modalOverlay.querySelector('[data-confirm]') || modalOverlay.querySelector('.btn-primary');

    const confirmHandler = async () => {
        if (!onConfirm) return closeModal();

        if (confirmButton) {
            const originalButtonText = confirmButton.innerHTML;
            confirmButton.disabled = true;
            confirmButton.innerHTML = 'Сохранение...';
        
            try {
                await onConfirm();
                closeModal();
            } catch (error) {
            } finally {
                confirmButton.disabled = false;
                confirmButton.innerHTML = originalButtonText;
            }
        } else {
            await onConfirm();
            closeModal();
        }
    };

    if (form) {
        form.addEventListener('submit', (e) => {
            e.preventDefault();
            confirmHandler();
        });
    } else {
        confirmButton?.addEventListener('click', confirmHandler);
    }

    requestAnimationFrame(() => modalOverlay.classList.add('visible'));
    return { close: closeModal };
}


export class DataTable {
    constructor(config) {
        this.container = document.getElementById(config.tableContainerId);
        this.paginationContainer = document.getElementById(config.paginationContainerId);
        this.apiEndpoint = config.apiEndpoint;
        this.columns = config.columns;
        this.actions = config.actions;
        this.searchHandler = config.searchHandler;
        this.tableClass = config.tableClass;
        this.onRowClick = config.onRowClick;

        const defaultSortCol = this.columns.find(c => c.defaultSort);
        this.state = {
            page: 1,
            search: '',
            sortBy: defaultSortCol?.key || this.columns.find(c => c.sortable)?.key || 'timestamp',
            sortOrder: defaultSortCol?.defaultSort || 'desc',
        };
        
        if (!this.container || !this.paginationContainer) {
            console.error("DataTable initialization failed: container or pagination element not found.");
            return;
        }

        if (this.searchHandler) {
            this.searchHandler(this.handleSearch.bind(this));
        }
    }

    handleSearch(query) {
        this.state.search = query;
        this.state.page = 1;
        this.loadData();
    }

    async loadData() {
        const { page, search, sortBy, sortOrder } = this.state;
        const params = new URLSearchParams({
            page,
            limit: 50,
            search: search.trim(),
            sort_by: sortBy,
            sort_order: sortOrder,
        });

        try {
            const data = await api.get(`${this.apiEndpoint}?${params.toString()}`);
            this.render(data);
        } catch (error) {
            this.container.innerHTML = '<p class="text-center" style="padding: 2rem;">Не удалось загрузить данные.</p>';
        }
    }
    
    findRowData(rowId, data) {
        const key = Object.keys(data).find(k => Array.isArray(data[k]));
        return data[key]?.find(item => String(item.id) === String(rowId));
    }

    render(data) {
        const dataKey = Object.keys(data).find(k => Array.isArray(data[k]));
        const items = data[dataKey] || [];

        const table = document.createElement('table');
        table.className = `data-table ${this.tableClass || ''} ${this.onRowClick ? 'clickable-rows' : ''}`.trim();

        table.innerHTML = `
            <thead>
                <tr>
                    ${this.columns.map(col => `
                        <th class="${col.sortable ? 'sortable' : ''}" data-sortby="${col.key}">
                            ${col.label}
                            ${col.sortable ? `<span class="sort-icon">
                                ${this.state.sortBy === col.key ? (this.state.sortOrder === 'asc' ? '▲' : '▼') : ''}
                            </span>` : ''}
                        </th>
                    `).join('')}
                    ${this.actions ? '<th>Действия</th>' : ''}
                </tr>
            </thead>
            <tbody>
                ${items.map(row => `
                    <tr data-id="${row.id}">
						${this.columns.map(col => {
							const displayContent = col.render ? col.render(row[col.key], row) : (row[col.key] || '<span class="placeholder">N/A</span>');
							const titleText = String(row[col.key] || '').replace(/"/g, '&quot;');
							return `<td title="${titleText}">${displayContent}</td>`;
						}).join('')}
                        ${this.actions ? `
                            <td class="actions-cell">
                                ${this.actions
                                    .filter(action => !action.show || action.show(row))
                                    .map(action => {
                                        const buttonLabel = typeof action.label === 'function' ? action.label(row) : action.label;
                                        return `<button class="btn btn-small ${action.class || ''}" data-action="${action.key}">${buttonLabel}</button>`;
                                    }).join('')}
                            </td>
                        ` : ''}
                    </tr>
                `).join('')}
            </tbody>
        `;

        if (items.length === 0) {
            const colSpan = this.columns.length + (this.actions ? 1 : 0);
            table.querySelector('tbody').innerHTML = `<tr><td colspan="${colSpan}" class="text-center" style="padding: 2rem;">Записи не найдены.</td></tr>`;
        }
        
        this.container.innerHTML = '';
        this.container.appendChild(table);

        this.paginationContainer.innerHTML = '';
        if (data.total_pages > 1) {
            const prevBtn = document.createElement('button');
            prevBtn.className = 'btn';
            prevBtn.textContent = '« Назад';
            prevBtn.disabled = data.page === 1;
            prevBtn.onclick = () => { this.state.page--; this.loadData(); };
            
            const pageInfo = document.createElement('span');
            pageInfo.className = 'page-info';
            pageInfo.textContent = `Страница ${data.page} из ${data.total_pages}`;

            const nextBtn = document.createElement('button');
            nextBtn.className = 'btn';
            nextBtn.textContent = 'Вперед »';
            nextBtn.disabled = data.page === data.total_pages;
            nextBtn.onclick = () => { this.state.page++; this.loadData(); };

            this.paginationContainer.append(prevBtn, pageInfo, nextBtn);
        }

        this.addEventListeners(data);
    }

    addEventListeners(data) {
        this.container.querySelectorAll('th.sortable').forEach(th => {
            th.addEventListener('click', () => {
                const sortBy = th.dataset.sortby;
                if (this.state.sortBy === sortBy) {
                    this.state.sortOrder = this.state.sortOrder === 'asc' ? 'desc' : 'asc';
                } else {
                    this.state.sortBy = sortBy;
                    this.state.sortOrder = 'desc';
                }
                this.state.page = 1;
                this.loadData();
            });
        });

        this.container.querySelectorAll('tbody tr[data-id]').forEach(tr => {
            tr.addEventListener('click', (e) => {
                const button = e.target.closest('button[data-action]');
                const rowId = tr.dataset.id;
                const rowData = this.findRowData(rowId, data);
                
                if (button) {
                    e.stopPropagation();
                    const actionKey = button.dataset.action;
                    const actionConfig = this.actions.find(a => a.key === actionKey);
                    if (actionConfig && rowData) {
                        actionConfig.handler(rowData);
                    }
                } else if (this.onRowClick && rowData) {
                    this.onRowClick(rowData);
                }
            });
        });
    }
}