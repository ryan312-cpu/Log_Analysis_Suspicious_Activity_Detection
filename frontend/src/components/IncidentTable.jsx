function IncidentTable({ incidents }) {
  return (
    <div className="panel">
      <div className="panel-header">
        <h2>Incident Queue</h2>
      </div>

      <div className="table-container">
        <table>
          <thead>
            <tr>
              <th>Incident</th>
              <th>Severity</th>
              <th>Status</th>
              <th>Source IP</th>
              <th>Created</th>
            </tr>
          </thead>
          <tbody>
            {incidents.slice(0, 10).map((incident) => (
              <tr key={incident.incident_id}>
                <td>{incident.incident_id}</td>
                <td>
                  <span className={`severity ${incident.severity.toLowerCase()}`}>
                    {incident.severity}
                  </span>
                </td>
                <td>{incident.status}</td>
                <td>{incident.source_ip || '-'}</td>
                <td>{incident.created_at}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default IncidentTable;
