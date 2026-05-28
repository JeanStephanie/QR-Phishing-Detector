/**
 * History page charts
 */
document.addEventListener('DOMContentLoaded', () => {
  if (window.historyChartData) {
    SafeNetCharts.doughnutChart(
      'history-verdict-chart',
      ['Safe', 'Suspicious', 'Malicious'],
      [
        window.historyChartData.safe,
        window.historyChartData.suspicious,
        window.historyChartData.malicious,
      ]
    );
  }
});
