function AlertTable({ alerts }) {
  return (
    <div className="panel">
      <div className="panel-header">
        <h2>Recent Security Alerts</h2>
      </div>

      <div className="table-container">
        <table>
          <thead>
            <tr>
              <th>Rule</th>
              <th>Severity</th>
              <th>Risk</th>
              <th>Source IP</th>
              <th>Status</th>
              <th>Time</th>
            </tr>
          </thead>
          <tbody>
            {alerts.slice(0, 10).map((alert) => (
              <tr key={alert.alert_id}>
                <td>{alert.rule_name}</td>
                <td>
                  <span className={`severity ${alert.severity.toLowerCase()}`}>
                    {alert.severity}
                  </span>
                </td>
                <td>{alert.risk_score}</td>
                <td>{alert.source_ip || '-'}</td>
                <td>{alert.status}</td>
                <td>{alert.timestamp}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default AlertTable;
