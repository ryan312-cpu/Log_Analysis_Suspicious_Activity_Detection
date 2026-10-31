const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000/api/v1').replace(/\/$/, '');
const API_KEY = import.meta.env.VITE_API_KEY || '';

async function request(endpoint) {
  const url = `${API_BASE_URL}${endpoint}`;
  const response = await fetch(url, {
    headers: {
      'X-API-Key': API_KEY,
    },
  });

  if (!response.ok) {
    throw new Error(`API request failed: ${response.status}`);
  }

  return response.json();
}

export async function getEvents() {
  return request('/events?limit=100');
}

export async function getAlerts() {
  return request('/alerts?limit=100');
}

export async function getIncidents() {
  return request('/incidents?limit=100');
}

export async function getThreatIntel() {
  return request('/threat-intel');
}
