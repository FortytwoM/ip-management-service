// static/js/modules/check.js
import { showToast, api } from '../lib.js';

let lastResults = null;

const resultsContainer = document.getElementById('results-container');
const resultsActions = document.getElementById('results-actions');

function downloadFile(filename, content, mimeType) {
    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

function convertToCSV(data) {
    const results = data?.results;
    if (!results || !results.length) return '';

    const delimiter = ';';
    const escapeCsvCell = (cell) => {
        let cellString = cell === null || cell === undefined ? '' : String(cell);
        if (cellString.includes(delimiter) || cellString.includes('"') || cellString.includes('\n')) {
            const escapedQuotes = cellString.replace(/"/g, '""');
            return `"${escapedQuotes}"`;
        }
        return cellString;
    };

    const rawKeys = new Set();
    results.forEach(item => {
        if (item.raw && typeof item.raw === 'object') {
            Object.keys(item.raw).forEach(key => rawKeys.add(key));
        }
    });

    const sortedRawHeaders = Array.from(rawKeys).sort().map(key => `raw_${key}`);
    const staticHeaders = ['ip', 'percent', 'provider', 'auto_banned'];
    const finalHeaders = [...staticHeaders, ...sortedRawHeaders];
    const rows = results.map(item => {
        const rowData = [];
        staticHeaders.forEach(header => {
            rowData.push(item[header]);
        });
        const rawData = item.raw && typeof item.raw === 'object' ? item.raw : {};
        sortedRawHeaders.forEach(header => {
            const originalKey = header.substring(4); 
            rowData.push(rawData[originalKey]);
        });

        return rowData.map(escapeCsvCell).join(delimiter);
    });

    const csvContent = [
        finalHeaders.join(delimiter),
        ...rows
    ].join('\n');

    return '\uFEFF' + csvContent;
}


function displayResults(data) {
    if (!resultsContainer || !resultsActions) return;
    
    lastResults = data; 
    resultsActions.style.display = 'flex';

    const formattedJson = JSON.stringify(data, null, 2);
    resultsContainer.innerHTML = `<pre>${formattedJson}</pre>`;
}

function showLoader() {
    if (!resultsContainer || !resultsActions) return;
    
    lastResults = null;
    resultsActions.style.display = 'none';

    resultsContainer.innerHTML = '<div class="loader"></div>';
}

function handleError(err) {
    if (!resultsContainer || !resultsActions) return;

    lastResults = null;
    resultsActions.style.display = 'none';

    resultsContainer.innerHTML = `<pre class="error">${err.message || 'An unknown error occurred.'}</pre>`;
}

async function handleTextSubmit(e) {
    e.preventDefault();
    const form = e.target;
    
    const ips = form.querySelector('#ips-textarea').value.split(/\r?\n/)
        .map(s => s.trim()).filter(Boolean);
        
    if (ips.length === 0) {
        return showToast('Введите хотя бы один IP', 'warning');
    }

    const payload = {
        ips,
        provider: form.querySelector('#provider-select').value,
        threshold_percent: Number(form.querySelector('#threshold-input').value || 50),
        ban: form.querySelector('#autoban-check').checked,
        reason: form.querySelector('#autoban-reason').value || "Auto-banned"
    };

    showLoader();

    try {
        const data = await api.post('/api/check', payload);
        displayResults(data);
        showToast('Проверка завершена', 'success');
        if (data.auto_banned?.length > 0) {
            showToast(`${data.auto_banned.length} IP были автоматически заблокированы`, 'info');
        }
    } catch (err) {
        handleError(err);
    }
}

async function handleFileSubmit(e) {
    e.preventDefault();
    const form = e.target;
    
    const fileInput = form.querySelector('input[type="file"]');
    const file = fileInput.files[0];

    if (!file) {
        return showToast('Выберите файл для проверки', 'warning');
    }
    
    const formData = new FormData();
    formData.append('file', file);
    formData.append('provider', form.querySelector('#file-provider-select').value);
    formData.append('threshold_percent', form.querySelector('#file-threshold-input').value || 50);
    formData.append('ban', document.querySelector('#autoban-check-file').checked);
    formData.append('reason', form.querySelector('#autoban-reason-file').value || "Auto-banned");

    showLoader();

    try {
        const data = await api.post('/api/check/file', formData);
        displayResults(data);
        showToast('Файл успешно проверен', 'success');
        if (data.auto_banned?.length > 0) {
            showToast(`${data.auto_banned.length} IP были автоматически заблокированы`, 'info');
        }
    } catch (err) {
        handleError(err);
    }
}

export function init() {
    document.getElementById('check-text-form')?.addEventListener('submit', handleTextSubmit);
    document.getElementById('check-file-form')?.addEventListener('submit', handleFileSubmit);

    const copyBtn = document.getElementById('copy-results-btn');
    const downloadCsvBtn = document.getElementById('download-csv-btn');
    const downloadJsonBtn = document.getElementById('download-json-btn');

    if (copyBtn) {
        copyBtn.addEventListener('click', () => {
            if (!lastResults) return;
            const jsonString = JSON.stringify(lastResults, null, 2);
            navigator.clipboard.writeText(jsonString).then(() => {
                showToast('Результаты скопированы в буфер обмена', 'success');
            }).catch(() => {
                showToast('Ошибка при копировании', 'error');
            });
        });
    }

    if (downloadCsvBtn) {
        downloadCsvBtn.addEventListener('click', () => {
            if (!lastResults) return;
            const csvContent = convertToCSV(lastResults);
            downloadFile('check_results.csv', csvContent, 'text/csv;charset=utf-8;');
        });
    }

    if (downloadJsonBtn) {
        downloadJsonBtn.addEventListener('click', () => {
            if (!lastResults) return;
            const jsonContent = JSON.stringify(lastResults, null, 2);
            downloadFile('check_results.json', jsonContent, 'application/json');
        });
    }
}