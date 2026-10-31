
import axios from "axios";

const api = axios.create({
    baseURL: "http://127.0.0.1:5000",
    timeout: 15000,
});

export const getHealth = async () => {
    const response = await api.get("/api/health");
    return response.data;
};

export const scanDns = async (hostnames) => {
    const response = await api.post("/api/scans/dns", {
        hostnames,
    });

    return response.data;
};
