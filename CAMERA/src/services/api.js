import axios from "axios";

const api = axios.create({
    baseURL: "http://127.0.0.1:5000",
    timeout: 15000,
});

// Check backend connection
export const getHealth = async () => {
    const response = await api.get("/api/health");
    return response.data;
};

// Scan manually entered hostnames
export const scanDns = async (hostnames) => {
    const response = await api.post("/api/scans/dns", {
        hostnames,
    });

    return response.data;
};

// Discover subdomains and assess their DNS records
export const scanDomain = async (domain) => {
    const response = await api.post(
        "/api/scans/domain",
        { domain },
        { timeout: 120000 }
    );

    return response.data;
};