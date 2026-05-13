const { execFile } = require("child_process");
const dns = require("dns").promises;
const express = require("express");
const net = require("net");
const os = require("os");
const path = require("path");

const app = express();
const port = process.env.PORT || 3000;

app.use((req, res, next) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");

  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }

  next();
});

app.use(express.json({ limit: "1mb" }));
app.use(express.static(path.join(__dirname, "public")));

const COMMON_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 3306, 5432, 6379, 8080];
const PRIVATE_RANGES = [
  /^10\./,
  /^127\./,
  /^172\.(1[6-9]|2\d|3[0-1])\./,
  /^192\.168\./,
];

function isPrivateIp(ip) {
  return net.isIP(ip) === 4 && PRIVATE_RANGES.some((range) => range.test(ip));
}

async function resolveTarget(target) {
  const cleanTarget = String(target || "").trim();

  if (!cleanTarget) {
    throw new Error("IP yoki hostname kiriting.");
  }

  if (net.isIP(cleanTarget)) {
    return cleanTarget;
  }

  const result = await dns.lookup(cleanTarget, { family: 4 });
  return result.address;
}

async function resolvePrivateTarget(target) {
  const ip = await resolveTarget(target);

  if (!isPrivateIp(ip)) {
    throw new Error("Xavfsizlik uchun faqat localhost yoki shaxsiy tarmoq IP manzillari scan qilinadi.");
  }

  return ip;
}

function pingHost(ip) {
  const args = os.platform() === "win32" ? ["-n", "1", "-w", "1000", ip] : ["-c", "1", "-W", "1", ip];

  return new Promise((resolve) => {
    execFile("ping", args, { timeout: 2000 }, (error) => {
      resolve(!error);
    });
  });
}

async function getHostname(ip) {
  try {
    const names = await dns.reverse(ip);
    return names[0] || "Topilmadi";
  } catch {
    return "Topilmadi";
  }
}

function scanPort(ip, scanPort) {
  return new Promise((resolve) => {
    const socket = new net.Socket();

    socket.setTimeout(500);
    socket.once("connect", () => {
      socket.destroy();
      resolve({ port: scanPort, open: true });
    });
    socket.once("timeout", () => {
      socket.destroy();
      resolve({ port: scanPort, open: false });
    });
    socket.once("error", () => {
      socket.destroy();
      resolve({ port: scanPort, open: false });
    });
    socket.connect(scanPort, ip);
  });
}

function parsePorts(body) {
  if (Array.isArray(body.ports) && body.ports.length > 0) {
    return body.ports
      .map((value) => Number(value))
      .filter((value) => Number.isInteger(value) && value > 0 && value <= 65535)
      .slice(0, 50);
  }

  const start = Number(body.startPort || 1);
  const end = Number(body.endPort || 1024);

  if (!Number.isInteger(start) || !Number.isInteger(end) || start < 1 || end > 65535 || start > end) {
    return COMMON_PORTS;
  }

  return Array.from({ length: Math.min(end - start + 1, 100) }, (_, index) => start + index);
}

function analyzeLog(logText, threshold = 20) {
  const text = String(logText || "");
  const ipMatches = text.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g) || [];
  const counts = new Map();
  const failedLines = [];

  text.split(/\r?\n/).forEach((line) => {
    if (/failed|invalid|unauthorized|forbidden|401|403/i.test(line)) {
      failedLines.push(line);
    }
  });

  ipMatches
    .filter((ip) => net.isIP(ip) === 4)
    .forEach((ip) => counts.set(ip, (counts.get(ip) || 0) + 1));

  const topIps = [...counts.entries()]
    .map(([ip, requests]) => ({ ip, requests, suspicious: requests >= threshold }))
    .sort((a, b) => b.requests - a.requests);

  return {
    totalIps: ipMatches.length,
    uniqueIps: counts.size,
    topIps: topIps.slice(0, 10),
    suspiciousIps: topIps.filter((item) => item.suspicious),
    failedLoginLines: failedLines.slice(0, 10),
  };
}

app.post("/api/ip-scan", async (req, res) => {
  try {
    const ip = await resolvePrivateTarget(req.body.target);
    const [online, hostname] = await Promise.all([pingHost(ip), getHostname(ip)]);

    res.json({ target: req.body.target, ip, online, hostname });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post("/api/port-scan", async (req, res) => {
  try {
    const ip = await resolvePrivateTarget(req.body.target);
    const ports = parsePorts(req.body);
    const results = await Promise.all(ports.map((scanPortNumber) => scanPort(ip, scanPortNumber)));

    res.json({
      ip,
      scannedPorts: results.length,
      openPorts: results.filter((result) => result.open),
      results,
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post("/api/log-analyzer", (req, res) => {
  const threshold = Number(req.body.threshold || 20);
  res.json(analyzeLog(req.body.logText, threshold));
});

app.post("/api/ddos-detect", (req, res) => {
  const threshold = Number(req.body.threshold || 50);
  const analysis = analyzeLog(req.body.logText, threshold);

  res.json({
    threshold,
    status: analysis.suspiciousIps.length > 0 ? "Possible DDoS / brute force activity" : "Normal activity",
    suspiciousIps: analysis.suspiciousIps,
    topIps: analysis.topIps,
  });
});

app.post("/api/geoip", async (req, res) => {
  try {
    const ip = await resolveTarget(req.body.target);

    if (isPrivateIp(ip)) {
      return res.json({
        ip,
        type: "Private network",
        message: "Bu lokal/shaxsiy tarmoq IP manzili, public GeoIP ma'lumoti bo‘lmaydi.",
      });
    }

    const response = await fetch(`http://ip-api.com/json/${ip}?fields=status,country,city,isp,query,message`);
    const data = await response.json();

    if (data.status !== "success") {
      return res.status(400).json({ error: data.message || "GeoIP topilmadi." });
    }

    res.json({
      ip: data.query,
      country: data.country,
      city: data.city,
      isp: data.isp,
    });
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.listen(port, () => {
  console.log(`Server ishga tushdi: http://localhost:${port}`);
});
