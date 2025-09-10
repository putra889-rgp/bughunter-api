const express = require("express");
const serverless = require("serverless-http");
const axios = require("axios");

const app = express();
app.use(express.json());

// Payloads
const xssPayloads = ["<script>alert(1)</script>", "'\"><img src=x onerror=alert(1)>"];
const sqliPayloads = ["' OR '1'='1", "\" OR \"1\"=\"1", "'; DROP TABLE users; --"];

// GET status API
app.get("/", (req, res) => {
  res.json({ status: "Bug Hunter API Ready ✅" });
});

// POST /scan/xss
app.post("/scan/xss", async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: "URL required" });

  const results = [];
  for (let payload of xssPayloads) {
    try {
      const r = await axios.get(url + "?q=" + encodeURIComponent(payload), { timeout: 7000 });
      const vulnerable = r.data.includes(payload);
      results.push({ payload, vulnerable, evidence: vulnerable ? payload : null });
    } catch (err) {
      results.push({ payload, vulnerable: false, error: err.message });
    }
  }
  res.json({ target: url, scanType: "XSS", results, date: new Date().toISOString() });
});

// POST /scan/sqli
app.post("/scan/sqli", async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: "URL required" });

  const results = [];
  for (let payload of sqliPayloads) {
    try {
      const r = await axios.get(url + "?id=" + encodeURIComponent(payload), { timeout: 7000 });
      const vulnerable = /sql|syntax|error|mysql|mssql|pgsql/i.test(r.data);
      results.push({ payload, vulnerable, evidence: vulnerable ? r.data.slice(0,200) : null });
    } catch (err) {
      results.push({ payload, vulnerable: false, error: err.message });
    }
  }
  res.json({ target: url, scanType: "SQLi", results, date: new Date().toISOString() });
});

// POST /scan/all
app.post("/scan/all", async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: "URL required" });

  // XSS
  const xssResults = [];
  for (let p of xssPayloads) {
    try {
      const r = await axios.get(url + "?q=" + encodeURIComponent(p), { timeout: 7000 });
      const vulnerable = r.data.includes(p);
      xssResults.push({ payload: p, vulnerable, evidence: vulnerable ? p : null });
    } catch (err) {
      xssResults.push({ payload: p, vulnerable: false, error: err.message });
    }
  }

  // SQLi
  const sqliResults = [];
  for (let p of sqliPayloads) {
    try {
      const r = await axios.get(url + "?id=" + encodeURIComponent(p), { timeout: 7000 });
      const vulnerable = /sql|syntax|error|mysql|mssql|pgsql/i.test(r.data);
      sqliResults.push({ payload: p, vulnerable, evidence: vulnerable ? r.data.slice(0,200) : null });
    } catch (err) {
      sqliResults.push({ payload: p, vulnerable: false, error: err.message });
    }
  }

  res.json({ target: url, scanType: "ALL", results: { xss: xssResults, sqli: sqliResults }, date: new Date().toISOString() });
});

// Export serverless
module.exports = serverless(app);
