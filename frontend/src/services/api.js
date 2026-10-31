const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000/api/v1').replace(/\/$/, '');
const API_KEY = import.meta.env.VITE_API_KEY || '';

async function request(endpoint) {
  const url = `${API_BASE_URL}${endpoint}`;
  try {
    const response = await fetch(url, {
      headers: {
        'X-API-Key': API_KEY,
      },
    });

    if (!response.ok) {
      if (response.status === 401) {
        throw new Error(`Authentication failed (401). Verify that VITE_API_KEY in Vercel matches API_KEY in Render.`);
      }
      if (response.status === 404) {
        throw new Error(`Endpoint not found (404) at ${url}. Ensure VITE_API_BASE_URL ends with '/api/v1'.`);
      }
      throw new Error(`API request failed with status ${response.status}: ${response.statusText}`);
    }

    return await response.json();
  } catch (err) {
    if (err.name === 'TypeError' && err.message.includes('fetch')) {
      throw new Error(`Network/CORS error reaching ${url}. Check your Render service URL and ensure it has finished starting.`);
    }
    throw err;
  }
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
