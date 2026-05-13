const API_BASE = window.location.protocol === "file:" ? "http://localhost:3000" : "";

async function postJson(url, body) {
  let response;

  try {
    response = await fetch(`${API_BASE}${url}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
  } catch {
    throw new Error("Serverga ulanib bo‘lmadi. Saytni http://localhost:3000 orqali oching va server ishlayotganini tekshiring.");
  }

  const data = await response.json();

  if (!response.ok) {
    throw new Error(data.error || "Xatolik yuz berdi.");
  }

  return data;
}

function showResult(elementId, data) {
  document.getElementById(elementId).textContent = JSON.stringify(data, null, 2);
}

function showTextResult(elementId, text) {
  document.getElementById(elementId).textContent = text;
}

function showLoading(elementId) {
  document.getElementById(elementId).textContent = "Tekshirilmoqda...";
}

function showError(elementId, error) {
  document.getElementById(elementId).textContent = `Xatolik: ${error.message}`;
}

const PORT_DESCRIPTIONS = {
  21: "FTP - fayl almashish xizmati",
  22: "SSH - serverga masofadan kirish",
  25: "SMTP - email yuborish",
  53: "DNS - domen nomlarini IP ga aylantirish",
  80: "HTTP - oddiy web sayt",
  110: "POP3 - email qabul qilish",
  143: "IMAP - email qabul qilish",
  443: "HTTPS - xavfsiz web sayt",
  3000: "Node.js/local development server",
  3306: "MySQL database",
  5432: "PostgreSQL database",
  6379: "Redis cache",
  8080: "Alternativ web server",
};

function describePort(port) {
  return PORT_DESCRIPTIONS[port] || "Noma'lum yoki custom xizmat";
}

function formatPortScanResult(data) {
  const openPorts = data.results.filter((result) => result.open);
  const closedPorts = data.results.filter((result) => !result.open);
  const lines = [
    "Port Scanner natijasi",
    "--------------------",
    `Tekshirilgan IP: ${data.ip}`,
    `Jami tekshirilgan portlar: ${data.scannedPorts}`,
    `Ochiq portlar soni: ${openPorts.length}`,
    "",
  ];

  if (openPorts.length > 0) {
    lines.push("OCHIQ PORTLAR:");
    openPorts.forEach((result) => {
      lines.push(`- ${result.port}: OCHIQ (${describePort(result.port)})`);
    });
    lines.push("", "Izoh: Ochiq port degani shu portda biror xizmat ishlayotgan bo‘lishi mumkin.");
  } else {
    lines.push("Ochiq port topilmadi.", "Izoh: Bu qurilmada tanlangan portlar yopiq yoki firewall bilan bloklangan bo‘lishi mumkin.");
  }

  if (closedPorts.length > 0) {
    lines.push("", "YOPIQ / JAVOB BERMAGAN PORTLAR:");
    closedPorts.forEach((result) => {
      lines.push(`- ${result.port}: yopiq (${describePort(result.port)})`);
    });
  }

  if (openPorts.some((result) => result.port === 3000)) {
    lines.push("", "Xulosa: 3000-port ochiq, demak hozirgi Node.js serveringiz ishlab turibdi.");
  }

  return lines.join("\n");
}

function formatLogAnalyzerResult(data, threshold) {
  const suspiciousIps = data.suspiciousIps || [];
  const topIps = data.topIps || [];
  const failedLines = data.failedLoginLines || [];
  const lines = [
    "Log Analyzer natijasi",
    "--------------------",
    `Log ichida topilgan IP yozuvlari: ${data.totalIps}`,
    `Takrorlanmas IP lar soni: ${data.uniqueIps}`,
    `Shubhali limit: ${threshold} ta request`,
    "",
  ];

  if (topIps.length > 0) {
    lines.push("ENG FAOL IP MANZILLAR:");
    topIps.forEach((item, index) => {
      const status = item.suspicious ? "SHUBHALI" : "normal";
      lines.push(`${index + 1}. ${item.ip} - ${item.requests} ta request (${status})`);
    });
  } else {
    lines.push("Log ichidan IP manzil topilmadi.");
  }

  lines.push("");

  if (suspiciousIps.length > 0) {
    lines.push("SHUBHALI IP LAR:");
    suspiciousIps.forEach((item) => {
      lines.push(`- ${item.ip}: ${item.requests} ta request. Bu IP limitdan oshgan.`);
    });
    lines.push("", "Tavsiya: bu IP larni firewall, server loglari yoki rate limit orqali qo‘shimcha tekshiring.");
  } else {
    lines.push("Shubhali IP topilmadi.", "Izoh: Hech qaysi IP belgilangan limitdan oshmagan.");
  }

  if (failedLines.length > 0) {
    lines.push("", "FAILED / 401 / 403 QATORLARI:");
    failedLines.forEach((line) => {
      lines.push(`- ${line}`);
    });
    lines.push("", "Izoh: Bu qatorlar login xatosi, ruxsatsiz urinish yoki bloklangan so‘rov bo‘lishi mumkin.");
  }

  return lines.join("\n");
}

function formatDdosDetectResult(data) {
  const suspiciousIps = data.suspiciousIps || [];
  const topIps = data.topIps || [];
  const isDanger = suspiciousIps.length > 0;
  const lines = [
    "DDoS Detector natijasi",
    "---------------------",
    `Holat: ${isDanger ? "XAVF BELGISI BOR" : "NORMAL"}`,
    `Request limiti: ${data.threshold}`,
    "",
  ];

  if (isDanger) {
    lines.push(
      "Xulosa: Ayrim IP manzillar limitdan oshgan. Bu DDoS, brute force yoki juda faol bot belgisi bo‘lishi mumkin.",
      "",
      "SHUBHALI IP LAR:",
    );
    suspiciousIps.forEach((item) => {
      lines.push(`- ${item.ip}: ${item.requests} ta request`);
    });
    lines.push("", "Tavsiya: bu IP larni vaqtincha bloklash, rate limit qo‘yish yoki loglarni chuqurroq tekshirish kerak.");
  } else {
    lines.push(
      "Xulosa: Kiritilgan log bo‘yicha DDoS belgisi topilmadi.",
      "Izoh: Hech qaysi IP belgilangan limitdan oshmagan.",
    );
  }

  if (topIps.length > 0) {
    lines.push("", "ENG KO‘P REQUEST YUBORGAN IP LAR:");
    topIps.forEach((item, index) => {
      const status = item.suspicious ? "SHUBHALI" : "normal";
      lines.push(`${index + 1}. ${item.ip} - ${item.requests} ta request (${status})`);
    });
  }

  return lines.join("\n");
}

function formatGeoIpResult(data) {
  if (data.type === "Private network") {
    return [
      "GeoIP natijasi",
      "-------------",
      `IP manzil: ${data.ip}`,
      "Turi: Lokal/private tarmoq IP manzili",
      "",
      data.message,
      "",
      "Izoh: 127.0.0.1, 10.x.x.x, 172.16-31.x.x va 192.168.x.x kabi IP lar internetdagi haqiqiy joylashuvni bermaydi.",
    ].join("\n");
  }

  return [
    "GeoIP natijasi",
    "-------------",
    `IP manzil: ${data.ip}`,
    `Davlat: ${data.country || "Topilmadi"}`,
    `Shahar: ${data.city || "Topilmadi"}`,
    `Internet provayder: ${data.isp || "Topilmadi"}`,
    "",
    "Izoh: GeoIP aniq uy manzilini ko‘rsatmaydi. U IP ro‘yxatdan o‘tgan hudud va provider haqida taxminiy ma'lumot beradi.",
  ].join("\n");
}

async function runIpScan() {
  const resultId = "ipResult";
  showLoading(resultId);

  try {
    const data = await postJson("/api/ip-scan", {
      target: document.getElementById("ipTarget").value,
    });

    showTextResult(
      resultId,
      [
        "IP Scanner natijasi",
        "-------------------",
        `Kiritilgan manzil: ${data.target}`,
        `Aniqlangan IP: ${data.ip}`,
        `Holati: ${data.online ? "ONLINE - qurilma javob berdi" : "OFFLINE - qurilma javob bermadi"}`,
        `Hostname: ${data.hostname}`,
        "",
        data.hostname === "Topilmadi"
          ? "Izoh: Hostname topilmagani xato emas. Bu IP uchun DNS/hostname sozlanmagan bo‘lishi mumkin."
          : "Izoh: Hostname muvaffaqiyatli topildi.",
      ].join("\n"),
    );
  } catch (error) {
    showError(resultId, error);
  }
}

async function runPortScan() {
  const resultId = "portResult";
  const ports = document
    .getElementById("ports")
    .value.split(",")
    .map((port) => Number(port.trim()))
    .filter(Boolean);

  showLoading(resultId);

  try {
    const data = await postJson("/api/port-scan", {
      target: document.getElementById("portTarget").value,
      ports,
    });

    showTextResult(resultId, formatPortScanResult(data));
  } catch (error) {
    showError(resultId, error);
  }
}

async function runLogAnalyzer() {
  const resultId = "logResult";
  showLoading(resultId);

  try {
    const threshold = document.getElementById("logThreshold").value;
    const data = await postJson("/api/log-analyzer", {
      logText: document.getElementById("logText").value,
      threshold,
    });

    showTextResult(resultId, formatLogAnalyzerResult(data, threshold));
  } catch (error) {
    showError(resultId, error);
  }
}

async function runDdosDetect() {
  const resultId = "ddosResult";
  showLoading(resultId);

  try {
    const data = await postJson("/api/ddos-detect", {
      logText: document.getElementById("ddosText").value,
      threshold: document.getElementById("ddosThreshold").value,
    });

    showTextResult(resultId, formatDdosDetectResult(data));
  } catch (error) {
    showError(resultId, error);
  }
}

async function runGeoIp() {
  const resultId = "geoResult";
  showLoading(resultId);

  try {
    const data = await postJson("/api/geoip", {
      target: document.getElementById("geoTarget").value,
    });

    showTextResult(resultId, formatGeoIpResult(data));
  } catch (error) {
    showError(resultId, error);
  }
}
