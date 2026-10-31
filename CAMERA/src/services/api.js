import axios from "axios";

const api = axios.create({
    baseURL: "http://127.0.0.1:5000",
    timeout: 5000,
});

export const getHealth = async () => {
    const response = await api.get("/api/health");
    return response.data;
};
