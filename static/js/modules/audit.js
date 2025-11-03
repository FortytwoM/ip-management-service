// static/js/modules/audit.js
import { DataTable } from '../lib.js';

export function init() {
    const table = new DataTable({
        tableContainerId: 'table-container',
        paginationContainerId: 'pagination-container',
        apiEndpoint: '/api/audit/list',
		tableClass: 'audit-table',
        columns: [
            { key: 'timestamp_msk', label: 'Время' },
            { key: 'username', label: 'Пользователь' },
            { key: 'action', label: 'Действие' },
            { key: 'details', label: 'Детали' },
            { key: 'ip_address', label: 'IP адрес' },
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

    table.loadData();
}