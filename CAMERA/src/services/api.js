import axios from "axios";

const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:5000",
  timeout: 15000,
});

export async function getHealth() {
  const response = await api.get("/api/health");
  return response.data;
}

export async function scanDns(hostnames) {
  const response = await api.post("/api/scans/dns", { hostnames });
  return response.data;
}

export async function scanDomain(domain) {
  const response = await api.post(
    "/api/scans/domain",
    { domain },
    { timeout: 180000 }
  );
  return response.data;
}

export async function scanAwsInventory({ region, dnsResults = [] } = {}) {
  const response = await api.post(
    "/api/scans/aws",
    { region, dns_results: dnsResults },
    { timeout: 120000 }
  );
  return response.data;
}

export async function getScanHistory(limit = 10) {
  const response = await api.get("/api/scans/history", { params: { limit } });
  return response.data;
}


export async function loadAwsDemo() {
  const response = await api.post("/api/scans/demo", {});
  return response.data;
}
