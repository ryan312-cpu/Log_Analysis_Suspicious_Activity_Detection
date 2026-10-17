import { useEffect, useState } from 'react';

import {
  getAlerts,
  getEvents,
  getIncidents,
  getThreatIntel,
} from './services/api';

import StatCard from './components/StatCard';
import AlertTable from './components/AlertTable';
import IncidentTable from './components/IncidentTable';
import SeverityChart from './components/SeverityChart';

import './App.css';

function App() {
  const [events, setEvents] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [incidents, setIncidents] = useState([]);
  const [threatIntel, setThreatIntel] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  async function loadDashboard() {
    try {
      setLoading(true);

      const [eventData, alertData, incidentData, threatData] = await Promise.all([
        getEvents(),
        getAlerts(),
        getIncidents(),
        getThreatIntel(),
      ]);

      setEvents(eventData);
      setAlerts(alertData);
      setIncidents(incidentData);
      setThreatIntel(threatData);
      setError(null);
    } catch (err) {
      console.error(err);
      setError('Unable to connect to Security Analytics API.');
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadDashboard();

    const interval = setInterval(loadDashboard, 30000);
    return () => clearInterval(interval);
  }, []);

  const criticalAlerts = alerts.filter((alert) => alert.severity === 'CRITICAL').length;
  const highRiskAlerts = alerts.filter((alert) => alert.risk_score >= 75).length;
  const openIncidents = incidents.filter((incident) => incident.status !== 'CLOSED').length;

  return (
    <div className="dashboard">
      <header className="topbar">
        <div>
          <h1>Security Operations Center</h1>
          <p>Log Analysis &amp; Suspicious Activity Detection</p>
        </div>

        <div className="system-status">
          <span className="status-dot"></span>
          API Connected
        </div>
      </header>

      {error && <div className="error-banner">{error}</div>}

      {loading ? (
        <div className="loading">Loading security data...</div>
      ) : (
        <>
          <section className="stats-grid">
            <StatCard title="Total Events" value={events.length} subtitle="Indexed security events" />
            <StatCard title="Total Alerts" value={alerts.length} subtitle="Generated detections" />
            <StatCard title="High-Risk Alerts" value={highRiskAlerts} subtitle="Risk score ≥ 75" />
            <StatCard title="Critical Alerts" value={criticalAlerts} subtitle="Critical severity" />
            <StatCard title="Open Incidents" value={openIncidents} subtitle="Active investigation queue" />
            <StatCard title="TI Indicators" value={threatIntel.length} subtitle="Known intelligence records" />
          </section>

          <section className="dashboard-grid">
            <SeverityChart alerts={alerts} />

            <div className="panel">
              <div className="panel-header">
                <h2>Security Overview</h2>
              </div>

              <div className="overview">
                <div>
                  <strong>{events.length}</strong>
                  <span>Events</span>
                </div>
                <div>
                  <strong>{alerts.length}</strong>
                  <span>Alerts</span>
                </div>
                <div>
                  <strong>{incidents.length}</strong>
                  <span>Incidents</span>
                </div>
                <div>
                  <strong>{threatIntel.length}</strong>
                  <span>TI Records</span>
                </div>
              </div>
            </div>
          </section>

          <AlertTable alerts={alerts} />
          <IncidentTable incidents={incidents} />
        </>
      )}
    </div>
  );
}

export default App;
