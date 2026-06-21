/**
 * Dashboard charts
 */
document.addEventListener('DOMContentLoaded', () => {
  if (!window.dashboardData) return;
  const d = window.dashboardData;

  SafeNetCharts.lineChart(
    'dashboard-scan-chart',
    d.chart_labels,
    d.chart_scans,
    d.chart_threats
  );

  SafeNetCharts.doughnutChart(
    'dashboard-verdict-chart',
    ['Safe', 'Suspicious', 'Malicious'],
    [d.verdict_distribution.safe, d.verdict_distribution.suspicious, d.verdict_distribution.malicious]
  );
});
