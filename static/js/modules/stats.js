// static/js/modules/stats.js

import { api } from '../lib.js';

let bansChart = null;

async function updateSummaryStats(period) {
    const statElements = {
        total: document.getElementById('total-bans-stat'),
        bans: document.getElementById('bans-period-stat'),
        exceptions: document.getElementById('exceptions-period-stat'),
        grants: document.getElementById('grants-period-stat'),
    };

    Object.values(statElements).forEach(el => { if(el) el.textContent = '...'; });

    try {
        const response = await api.get(`/api/stats?period=${period}`);
        if (response?.ok) {
            statElements.total.textContent = response.stats.total_active_bans;
            statElements.bans.textContent = response.stats.bans_in_period;
            statElements.exceptions.textContent = response.stats.exceptions_in_period;
            statElements.grants.textContent = response.stats.grants_in_period;
        } else {
            throw new Error(response?.detail || 'Invalid response for summary stats');
        }
    } catch (error) {
        console.error('Failed to load summary stats:', error);
        Object.values(statElements).forEach(el => { if(el) el.textContent = 'Ошибка'; });
    }
}


async function loadChartData(period) {
    const loader = document.getElementById('chart-loader');
    const canvas = document.getElementById('bans-chart-canvas');

    if (!loader || !canvas) return;

    loader.style.display = 'block';
    canvas.style.display = 'none';

    try {
        const response = await api.get(`/api/stats/chart?period=${period}`);
        if (!response?.ok) {
            throw new Error(response?.detail || 'Failed to fetch chart data');
        }

        const chartData = {
            labels: response.labels,
            datasets: [{
                label: 'Количество блокировок',
                data: response.data,
                borderColor: '#2980b9',
                backgroundColor: 'rgba(52, 152, 219, 0.2)',
                borderWidth: 2,
                fill: true,
                tension: 0.1,
                pointRadius: 2,
            }]
        };

        renderChart(chartData);
    } catch (error) {
        console.error(`Failed to load chart data for period "${period}":`, error);
    } finally {
        loader.style.display = 'none';
        canvas.style.display = 'block';
    }
}

function renderChart(chartData) {
    const ctx = document.getElementById('bans-chart-canvas')?.getContext('2d');
    if (!ctx) return;

    if (bansChart) {
        bansChart.destroy();
    }

    const isDarkMode = document.documentElement.getAttribute('data-theme') === 'dark';
    const gridColor = isDarkMode ? 'rgba(255, 255, 255, 0.1)' : 'rgba(0, 0, 0, 0.1)';
    const textColor = isDarkMode ? '#f7fafc' : '#1a202c';

    bansChart = new Chart(ctx, {
        type: 'line',
        data: chartData,
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        color: textColor,
                        stepSize: 1,
                        callback: (value) => { if (Number.isInteger(value)) return value; }
                    },
                    grid: { color: gridColor }
                },
                x: {
                    ticks: { color: textColor },
                    grid: { color: gridColor }
                }
            },
            plugins: {
                legend: { display: false },
                tooltip: {
                    mode: 'index',
                    intersect: false,
                }
            },
            interaction: {
                mode: 'nearest',
                axis: 'x',
                intersect: false
            }
        }
    });
}

function updateAllData(period) {
    updateSummaryStats(period);
    loadChartData(period);
}

export function init() {
    const controls = document.querySelector('.stats-controls');
    if (!controls) return;
    
    const dayButton = controls.querySelector('button[data-period="day"]');
    controls.querySelectorAll('button').forEach(btn => btn.classList.remove('btn-primary'));
    if (dayButton) dayButton.classList.add('btn-primary');
    
    updateAllData('day');

    controls.addEventListener('click', (e) => {
        const button = e.target.closest('button[data-period]');
        if (button && !button.classList.contains('btn-primary')) {
            controls.querySelectorAll('button').forEach(btn => {
                btn.classList.remove('btn-primary');
            });
            button.classList.add('btn-primary');
            
            updateAllData(button.dataset.period);
        }
    });
}