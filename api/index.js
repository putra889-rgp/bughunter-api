// bughunter-api.js
const express = require("express");
const serverless = require("serverless-http");
const axios = require("axios");
const fs = require("fs"); // <= penting!
const app = express();

app.use(express.json()); // body-parser diganti

const REPORT_FILE = "reports.json";

// ==========================
// Payloads
// ==========================
const xssPayloads = [
  "<script>alert(1)</script>",
  "'\"><img src=x onerror=alert(1)>"
];

const sqliPayloads = [
  "' OR '1'='1",
  "\" OR \"1\"=\"1",
  "'; DROP TABLE users; --"
];

// ==========================
// Helper
// ==========================
function saveReport(report) {
  let data = [];
  if (fs.existsSync(REPORT_FILE)) {
    const content = fs.readFileSync(REPORT_FILE, "utf-8");
    try {
      data = JSON.parse(content);
    } catch (err) {
      console.error("Error parsing existing report file:", err.message);
    }
  }
  data.push(report);
  fs.writeFileSync(REPORT_FILE, JSON.stringify(data, null, 2));
}

// ==========================
// Routes
// ==========================
app.get("/", (req, res) => {
  res.json({ status: "Bug Hunter API Ready ✅" });
});

// Scan XSS
app.post("/scan/xss", async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: "URL required" });

  const results = [];
  for (let payload of xssPayloads) {
    try {
      const response = await axios.get(url + "?q=" + encodeURIComponent(payload), { timeout: 7000 });
      const vulnerable = response.data.includes(payload);
      results.push({ payload, vulnerable, evidence: vulnerable ? payload : null });
    } catch (err) {
      results.push({ payload, vulnerable: false, error: err.message });
    }
  }

  const report = { target: url, scanType: "XSS", results, date: new Date().toISOString() };
  saveReport(report);
  res.json(report);
});

// Scan SQLi
app.post("/scan/sqli", async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: "URL required" });

  const results = [];
  for (let payload of sqliPayloads) {
    try {
      const response = await axios.get(url + "?id=" + encodeURIComponent(payload), { timeout: 7000 });
      const vulnerable = /sql|syntax|error|mysql|mssql|pgsql/i.test(response.data);
      results.push({ payload, vulnerable, evidence: vulnerable ? response.data.slice(0,200) : null });
    } catch (err) {
      results.push({ payload, vulnerable: false, error: err.message });
    }
  }

  const report = { target: url, scanType: "SQLi", results, date: new Date().toISOString() };
  saveReport(report);
  res.json(report);
});

// Scan All
app.post("/scan/all", async (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: "URL required" });

  const xssResults = [];
  for (let payload of xssPayloads) {
    try {
      const response = await axios.get(url + "?q=" + encodeURIComponent(payload), { timeout: 7000 });
      const vulnerable = response.data.includes(payload);
      xssResults.push({ payload, vulnerable, evidence: vulnerable ? payload : null });
    } catch (err) {
      xssResults.push({ payload, vulnerable: false, error: err.message });
    }
  }

  const sqliResults = [];
  for (let payload of sqliPayloads) {
    try {
      const response = await axios.get(url + "?id=" + encodeURIComponent(payload), { timeout: 7000 });
      const vulnerable = /sql|syntax|error|mysql|mssql|pgsql/i.test(response.data);
      sqliResults.push({ payload, vulnerable, evidence: vulnerable ? response.data.slice(0,200) : null });
    } catch (err) {
      sqliResults.push({ payload, vulnerable: false, error: err.message });
    }
  }

  const report = {
    target: url,
    scanType: "ALL",
    results: { xss: xssResults, sqli: sqliResults },
    date: new Date().toISOString()
  };

  saveReport(report);
  res.json(report);
});

// ==========================
// Serverless export
// ==========================
module.exports.handler = serverless(app);
