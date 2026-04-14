const SESSION_KEY_STORAGE = "five10-openrouter-key";
const DEFAULT_MODEL = "openrouter/auto";
const MAX_FILE_CHARS = 40000;
const MAX_TOTAL_EVIDENCE_CHARS = 120000;

const OUTPUT_LABELS = {
  pir: "Post Incident Report",
  incident_summary: "Incident Summary",
  executive_summary: "Executive Summary",
  timeline_report: "Timeline Report",
  ioc_report: "IOC Report",
  remediation_plan: "Remediation Plan",
  customer_update: "Customer Update",
};

const form = document.querySelector("#analysis-form");
const apiKeyInput = document.querySelector("#api-key");
const modelInput = document.querySelector("#model");
const keyStatus = document.querySelector("#key-status");
const keyFileInput = document.querySelector("#key-file-input");
const importKeyButton = document.querySelector("#import-key-button");
const clearKeyButton = document.querySelector("#clear-key-button");
const evidenceFilesInput = document.querySelector("#evidence-files");
const evidenceSummary = document.querySelector("#evidence-summary");
const fileList = document.querySelector("#file-list");
const runState = document.querySelector("#run-state");
const runMessage = document.querySelector("#run-message");
const resultChips = document.querySelector("#result-chips");
const resultsEmpty = document.querySelector("#results-empty");
const resultsContainer = document.querySelector("#results-container");
const rawJson = document.querySelector("#raw-json");
const downloadJsonButton = document.querySelector("#download-json-button");
const exportDocxButton = document.querySelector("#export-docx-button");

let loadedFiles = [];
let latestAnalysis = null;
let latestPayload = null;

hydrateSessionKey();
bindEvents();
renderFileList();

function bindEvents() {
  importKeyButton.addEventListener("click", () => keyFileInput.click());
  clearKeyButton.addEventListener("click", clearSessionKey);
  keyFileInput.addEventListener("change", importKeyFile);
  apiKeyInput.addEventListener("change", persistSessionKey);
  evidenceFilesInput.addEventListener("change", handleEvidenceFiles);
  form.addEventListener("submit", handleAnalyze);
  downloadJsonButton.addEventListener("click", downloadJson);
  exportDocxButton.addEventListener("click", exportSelectedDocs);
}

function hydrateSessionKey() {
  const stored = sessionStorage.getItem(SESSION_KEY_STORAGE);
  if (stored) {
    apiKeyInput.value = stored;
    keyStatus.textContent = "Session key restored.";
  }
  if (!modelInput.value.trim()) {
    modelInput.value = DEFAULT_MODEL;
  }
}

function persistSessionKey() {
  const key = apiKeyInput.value.trim();
  if (!key) {
    sessionStorage.removeItem(SESSION_KEY_STORAGE);
    keyStatus.textContent = "No key loaded.";
    return;
  }
  sessionStorage.setItem(SESSION_KEY_STORAGE, key);
  keyStatus.textContent = "Key stored for this browser session.";
}

function clearSessionKey() {
  apiKeyInput.value = "";
  sessionStorage.removeItem(SESSION_KEY_STORAGE);
  keyStatus.textContent = "Session key cleared.";
}

async function importKeyFile(event) {
  const file = event.target.files?.[0];
  if (!file) {
    return;
  }

  try {
    const text = await file.text();
    const key = parseOpenRouterKey(text);
    if (!key) {
      throw new Error("No OpenRouter key found in the selected file.");
    }
    apiKeyInput.value = key;
    sessionStorage.setItem(SESSION_KEY_STORAGE, key);
    keyStatus.textContent = `Imported key from ${file.name}.`;
  } catch (error) {
    keyStatus.textContent = error.message;
  } finally {
    keyFileInput.value = "";
  }
}

function parseOpenRouterKey(text) {
  const matches = text.match(/sk-or-v1-[A-Za-z0-9]+/g);
  return matches ? matches[matches.length - 1] : "";
}

async function handleEvidenceFiles(event) {
  const files = Array.from(event.target.files || []);
  loadedFiles = [];

  for (const file of files) {
    const extracted = await extractFileContent(file);
    loadedFiles.push(extracted);
  }

  renderFileList();
}

async function extractFileContent(file) {
  const sizeKb = Math.round(file.size / 1024);
  let text = "";
  let truncated = false;
  let readError = "";

  try {
    text = await file.text();
    if (text.length > MAX_FILE_CHARS) {
      text = text.slice(0, MAX_FILE_CHARS);
      truncated = true;
    }
  } catch (error) {
    readError = `Unable to read ${file.name} as text.`;
  }

  return {
    name: file.name,
    type: file.type || "unknown",
    size: file.size,
    sizeKb,
    text,
    truncated,
    readError,
  };
}

function renderFileList() {
  fileList.innerHTML = "";

  if (!loadedFiles.length) {
    evidenceSummary.textContent = "No evidence files loaded.";
    return;
  }

  let readableChars = 0;
  for (const file of loadedFiles) {
    readableChars += file.text.length;
    const item = document.createElement("li");
    item.textContent = `${file.name} | ${file.sizeKb} KB | ${file.readError || `${file.text.length.toLocaleString()} chars${file.truncated ? " | truncated" : ""}`}`;
    fileList.appendChild(item);
  }

  evidenceSummary.textContent = `${loadedFiles.length} file(s) loaded | ${readableChars.toLocaleString()} extracted chars available to the case packet.`;
}

async function handleAnalyze(event) {
  event.preventDefault();

  const key = apiKeyInput.value.trim();
  const model = modelInput.value.trim() || DEFAULT_MODEL;
  const selectedOutputs = getSelectedOutputs();

  if (!key) {
    setRunState("Error", "Load an OpenRouter key before running analysis.", true);
    return;
  }

  if (!selectedOutputs.length) {
    setRunState("Error", "Select at least one output type.", true);
    return;
  }

  const payload = buildCasePayload(selectedOutputs);
  latestPayload = payload;

  if (!payload.problemStatement && !payload.analystSummary && !payload.evidenceBundle) {
    setRunState("Error", "Add a problem statement, analyst summary, or evidence before analysis.", true);
    return;
  }

  setRunState("Running", "Submitting structured case packet to OpenRouter.");
  toggleActionState(true);

  try {
    const analysis = await requestAnalysis({ key, model, payload });
    latestAnalysis = analysis;
    renderAnalysis(analysis, selectedOutputs, payload);
    setRunState("Ready", "Analysis complete. Review the cards, then export the documents you need.");
    downloadJsonButton.disabled = false;
    exportDocxButton.disabled = false;
  } catch (error) {
    console.error(error);
    latestAnalysis = null;
    renderError(error);
    setRunState("Error", error.message || "Analysis failed.", true);
  } finally {
    toggleActionState(false);
  }
}

function buildCasePayload(selectedOutputs) {
  const formData = new FormData(form);
  const combinedEvidence = buildEvidenceBundle();

  return {
    metadata: {
      clientName: (formData.get("clientName") || "").toString().trim(),
      caseTitle: (formData.get("caseTitle") || "").toString().trim(),
      analystName: (formData.get("analystName") || "").toString().trim(),
      severity: (formData.get("severity") || "").toString().trim(),
      incidentType: (formData.get("incidentType") || "Auto-detect").toString().trim(),
      generatedAt: new Date().toISOString(),
    },
    selectedOutputs,
    problemStatement: (formData.get("problemStatement") || "").toString().trim(),
    analystSummary: (formData.get("analystSummary") || "").toString().trim(),
    pastedEvidence: (formData.get("pastedEvidence") || "").toString().trim(),
    evidenceFiles: loadedFiles.map(({ name, type, sizeKb, truncated, readError }) => ({
      name,
      type,
      sizeKb,
      truncated,
      readError,
    })),
    evidenceBundle: combinedEvidence,
  };
}

function buildEvidenceBundle() {
  const chunks = [];
  let total = 0;

  for (const file of loadedFiles) {
    if (!file.text || file.readError) {
      continue;
    }

    const wrapper = `FILE: ${file.name}\nTYPE: ${file.type || "unknown"}\n${file.text}`;
    if (total + wrapper.length > MAX_TOTAL_EVIDENCE_CHARS) {
      const remaining = Math.max(MAX_TOTAL_EVIDENCE_CHARS - total, 0);
      if (remaining > 256) {
        chunks.push(wrapper.slice(0, remaining));
      }
      break;
    }
    chunks.push(wrapper);
    total += wrapper.length;
  }

  return chunks.join("\n\n---\n\n");
}

function getSelectedOutputs() {
  return Array.from(document.querySelectorAll('input[name="outputs"]:checked')).map((input) => input.value);
}

function setRunState(label, message, isError = false) {
  runState.textContent = label;
  runMessage.textContent = message;
  runState.classList.toggle("panel-badge-live", !isError);
  runState.style.color = isError ? "var(--danger)" : "";
}

function toggleActionState(isRunning) {
  form.querySelector("#analyze-button").disabled = isRunning;
  if (isRunning) {
    form.querySelector("#analyze-button").textContent = "Analyzing...";
  } else {
    form.querySelector("#analyze-button").textContent = "Analyze Incident";
  }
}

async function requestAnalysis({ key, model, payload }) {
  const systemPrompt = buildSystemPrompt();
  const userPrompt = buildUserPrompt(payload);

  const response = await fetch("https://openrouter.ai/api/v1/chat/completions", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${key}`,
      "HTTP-Referer": window.location.href,
      "X-Title": "Five-10 PIR Lab",
    },
    body: JSON.stringify({
      model,
      temperature: 0.2,
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: userPrompt },
      ],
    }),
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`OpenRouter request failed: ${response.status} ${errorText}`);
  }

  const data = await response.json();
  const content = data?.choices?.[0]?.message?.content;
  if (!content) {
    throw new Error("No message content returned from OpenRouter.");
  }

  const parsed = normalizeAnalysis(parseJsonResponse(content));
  parsed._meta = {
    model,
    generatedAt: new Date().toISOString(),
  };

  return parsed;
}

function buildSystemPrompt() {
  return [
    "You are a senior incident response report writer producing structured deliverables for SOC analysts.",
    "Use only the evidence supplied by the user. If evidence is incomplete, say so explicitly.",
    "PIR means Post Incident Report.",
    "Support all incident categories, including phishing, malware, identity, cloud, network, insider, and operational events.",
    "Return strict JSON only. Do not wrap the response in markdown.",
    "Keep wording direct, technical, and review-ready.",
    "Every list must contain concise, useful items rather than filler.",
    "For uncertain claims, mark confidence as low or medium and explain why.",
    "If no IOCs are present, return empty arrays rather than inventing indicators.",
    "Use this JSON schema:",
    JSON.stringify(getResponseTemplate(), null, 2),
  ].join("\n\n");
}

function buildUserPrompt(payload) {
  return [
    "CASE PAYLOAD",
    JSON.stringify(payload, null, 2),
    "INSTRUCTIONS",
    [
      "Fill the full JSON structure.",
      "Prioritize the user's selected outputs but still populate the canonical schema.",
      "Derive an incident type if the user selected Auto-detect.",
      "Provide a realistic timeline when evidence supports it.",
      "Recommend immediate containment and follow-up remediation steps.",
      "Use concise bullets and structured findings.",
    ].join("\n"),
  ].join("\n\n");
}

function getResponseTemplate() {
  return {
    incident_profile: {
      incident_type: "",
      severity: "",
      confidence: "",
      status: "",
      scope: "",
    },
    executive_summary: "",
    incident_summary: {
      what_happened: "",
      impact: "",
      affected_assets: [],
      likely_root_cause: "",
      priority_actions: [],
    },
    pir: {
      title: "",
      overview: "",
      business_impact: "",
      technical_findings: [],
      timeline: [],
      indicators_of_compromise: [],
      containment_actions: [],
      eradication_actions: [],
      recovery_actions: [],
      recommendations: [],
      lessons_learned: [],
    },
    timeline_report: {
      events: [],
    },
    ioc_report: {
      hosts: [],
      users: [],
      ips: [],
      domains: [],
      hashes: [],
      artifacts: [],
    },
    remediation_plan: {
      immediate: [],
      next_24_hours: [],
      hardening: [],
    },
    customer_update: {
      subject: "",
      message: "",
    },
  };
}

function parseJsonResponse(content) {
  const trimmed = content.trim();
  if (trimmed.startsWith("{")) {
    return JSON.parse(trimmed);
  }

  const fenced = trimmed.match(/```json\s*([\s\S]*?)```/i) || trimmed.match(/```\s*([\s\S]*?)```/i);
  if (fenced?.[1]) {
    return JSON.parse(fenced[1].trim());
  }

  const firstBrace = trimmed.indexOf("{");
  const lastBrace = trimmed.lastIndexOf("}");
  if (firstBrace >= 0 && lastBrace > firstBrace) {
    return JSON.parse(trimmed.slice(firstBrace, lastBrace + 1));
  }

  throw new Error("The model response did not contain valid JSON.");
}

function normalizeAnalysis(raw) {
  const template = getResponseTemplate();
  const merged = structuredClone(template);

  deepMerge(merged, raw || {});

  merged.incident_profile = merged.incident_profile || template.incident_profile;
  merged.executive_summary = toParagraph(merged.executive_summary);
  merged.incident_summary.what_happened = toParagraph(merged.incident_summary.what_happened);
  merged.incident_summary.impact = toParagraph(merged.incident_summary.impact);
  merged.incident_summary.likely_root_cause = toParagraph(merged.incident_summary.likely_root_cause);
  merged.incident_summary.affected_assets = toList(merged.incident_summary.affected_assets);
  merged.incident_summary.priority_actions = toList(merged.incident_summary.priority_actions);

  merged.pir.technical_findings = toList(merged.pir.technical_findings);
  merged.pir.timeline = normalizeTimeline(merged.pir.timeline);
  merged.pir.indicators_of_compromise = toList(merged.pir.indicators_of_compromise);
  merged.pir.containment_actions = toList(merged.pir.containment_actions);
  merged.pir.eradication_actions = toList(merged.pir.eradication_actions);
  merged.pir.recovery_actions = toList(merged.pir.recovery_actions);
  merged.pir.recommendations = toList(merged.pir.recommendations);
  merged.pir.lessons_learned = toList(merged.pir.lessons_learned);

  merged.timeline_report.events = normalizeTimeline(merged.timeline_report.events.length ? merged.timeline_report.events : merged.pir.timeline);

  for (const key of Object.keys(merged.ioc_report)) {
    merged.ioc_report[key] = toList(merged.ioc_report[key]);
  }

  merged.remediation_plan.immediate = toList(merged.remediation_plan.immediate);
  merged.remediation_plan.next_24_hours = toList(merged.remediation_plan.next_24_hours);
  merged.remediation_plan.hardening = toList(merged.remediation_plan.hardening);
  merged.customer_update.subject = toParagraph(merged.customer_update.subject);
  merged.customer_update.message = toParagraph(merged.customer_update.message);

  return merged;
}

function deepMerge(target, source) {
  for (const [key, value] of Object.entries(source)) {
    if (value && typeof value === "object" && !Array.isArray(value) && target[key] && typeof target[key] === "object" && !Array.isArray(target[key])) {
      deepMerge(target[key], value);
    } else {
      target[key] = value;
    }
  }
}

function toList(value) {
  if (Array.isArray(value)) {
    return value.map((item) => toParagraph(item)).filter(Boolean);
  }
  if (!value) {
    return [];
  }
  return String(value)
    .split(/\n|•|-/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function normalizeTimeline(value) {
  if (!value) {
    return [];
  }

  if (Array.isArray(value)) {
    return value
      .map((entry) => {
        if (typeof entry === "string") {
          return { timestamp: "", event: entry.trim(), source: "" };
        }
        return {
          timestamp: toParagraph(entry.timestamp || entry.time || entry.date),
          event: toParagraph(entry.event || entry.summary || entry.description),
          source: toParagraph(entry.source || entry.evidence || ""),
        };
      })
      .filter((entry) => entry.event);
  }

  return toList(value).map((item) => ({ timestamp: "", event: item, source: "" }));
}

function toParagraph(value) {
  if (!value) {
    return "";
  }
  return String(value).trim();
}

function renderAnalysis(analysis, selectedOutputs, payload) {
  resultsEmpty.hidden = true;
  resultsContainer.hidden = false;
  resultsContainer.innerHTML = "";
  rawJson.textContent = JSON.stringify(analysis, null, 2);
  renderChips(analysis, payload);

  for (const outputKey of selectedOutputs) {
    const card = buildResultCard(outputKey, analysis);
    resultsContainer.appendChild(card);
  }
}

function renderChips(analysis, payload) {
  resultChips.innerHTML = "";
  const chipValues = [
    analysis.incident_profile.incident_type || payload.metadata.incidentType,
    analysis.incident_profile.severity || payload.metadata.severity || "Severity pending",
    analysis.incident_profile.confidence || "Confidence pending",
    analysis.incident_profile.status || "Status pending",
  ].filter(Boolean);

  for (const value of chipValues) {
    const chip = document.createElement("span");
    chip.className = "chip";
    chip.textContent = value;
    resultChips.appendChild(chip);
  }
}

function buildResultCard(outputKey, analysis) {
  const card = document.createElement("article");
  card.className = "result-card";

  const header = document.createElement("header");
  const title = document.createElement("h4");
  title.textContent = OUTPUT_LABELS[outputKey] || outputKey;
  const copyButton = document.createElement("button");
  copyButton.className = "button button-ghost";
  copyButton.type = "button";
  copyButton.textContent = "Copy";
  copyButton.addEventListener("click", async () => {
    const text = extractPlainText(outputKey, analysis);
    await navigator.clipboard.writeText(text);
    copyButton.textContent = "Copied";
    setTimeout(() => {
      copyButton.textContent = "Copy";
    }, 1200);
  });
  header.append(title, copyButton);
  card.appendChild(header);

  switch (outputKey) {
    case "pir":
      appendParagraph(card, analysis.pir.title || OUTPUT_LABELS.pir, true);
      appendSection(card, "Overview", analysis.pir.overview);
      appendSection(card, "Business Impact", analysis.pir.business_impact);
      appendListSection(card, "Technical Findings", analysis.pir.technical_findings);
      appendTimelineSection(card, "Timeline", analysis.pir.timeline);
      appendListSection(card, "Indicators of Compromise", analysis.pir.indicators_of_compromise);
      appendListSection(card, "Containment Actions", analysis.pir.containment_actions);
      appendListSection(card, "Eradication Actions", analysis.pir.eradication_actions);
      appendListSection(card, "Recovery Actions", analysis.pir.recovery_actions);
      appendListSection(card, "Recommendations", analysis.pir.recommendations);
      appendListSection(card, "Lessons Learned", analysis.pir.lessons_learned);
      break;
    case "incident_summary":
      appendSection(card, "What Happened", analysis.incident_summary.what_happened);
      appendSection(card, "Impact", analysis.incident_summary.impact);
      appendListSection(card, "Affected Assets", analysis.incident_summary.affected_assets);
      appendSection(card, "Likely Root Cause", analysis.incident_summary.likely_root_cause);
      appendListSection(card, "Priority Actions", analysis.incident_summary.priority_actions);
      break;
    case "executive_summary":
      appendSection(card, "Executive Summary", analysis.executive_summary);
      break;
    case "timeline_report":
      appendTimelineSection(card, "Timeline", analysis.timeline_report.events);
      break;
    case "ioc_report":
      appendIocSection(card, analysis.ioc_report);
      break;
    case "remediation_plan":
      appendListSection(card, "Immediate Actions", analysis.remediation_plan.immediate);
      appendListSection(card, "Next 24 Hours", analysis.remediation_plan.next_24_hours);
      appendListSection(card, "Hardening", analysis.remediation_plan.hardening);
      break;
    case "customer_update":
      appendSection(card, "Subject", analysis.customer_update.subject);
      appendSection(card, "Message", analysis.customer_update.message);
      break;
    default:
      appendSection(card, "Content", JSON.stringify(analysis, null, 2));
      break;
  }

  return card;
}

function appendParagraph(parent, text, emphasized = false) {
  if (!text) {
    return;
  }
  const paragraph = document.createElement(emphasized ? "strong" : "p");
  paragraph.textContent = text;
  parent.appendChild(paragraph);
}

function appendSection(parent, label, value) {
  if (!value) {
    return;
  }
  const wrap = document.createElement("section");
  wrap.className = "subsection";
  const heading = document.createElement("h5");
  heading.textContent = label;
  const body = document.createElement("p");
  body.textContent = value;
  wrap.append(heading, body);
  parent.appendChild(wrap);
}

function appendListSection(parent, label, items) {
  if (!items?.length) {
    return;
  }
  const wrap = document.createElement("section");
  wrap.className = "subsection";
  const heading = document.createElement("h5");
  heading.textContent = label;
  const list = document.createElement("ul");
  items.forEach((item) => {
    const li = document.createElement("li");
    li.textContent = item;
    list.appendChild(li);
  });
  wrap.append(heading, list);
  parent.appendChild(wrap);
}

function appendTimelineSection(parent, label, events) {
  if (!events?.length) {
    return;
  }
  const wrap = document.createElement("section");
  wrap.className = "subsection";
  const heading = document.createElement("h5");
  heading.textContent = label;
  const grid = document.createElement("div");
  grid.className = "timeline-grid";

  events.forEach((event) => {
    const item = document.createElement("article");
    item.className = "timeline-event";
    const title = document.createElement("strong");
    title.textContent = event.timestamp ? `${event.timestamp} | ${event.event}` : event.event;
    const source = document.createElement("p");
    source.textContent = event.source || "No source string supplied.";
    item.append(title, source);
    grid.appendChild(item);
  });

  wrap.append(heading, grid);
  parent.appendChild(wrap);
}

function appendIocSection(parent, iocReport) {
  const categories = Object.entries(iocReport).filter(([, values]) => values.length);
  if (!categories.length) {
    appendSection(parent, "IOCs", "No concrete indicators were identified in the supplied evidence.");
    return;
  }

  const wrap = document.createElement("section");
  wrap.className = "subsection";
  const heading = document.createElement("h5");
  heading.textContent = "Indicators of Compromise";
  const grid = document.createElement("div");
  grid.className = "ioc-grid";

  categories.forEach(([name, values]) => {
    const item = document.createElement("article");
    item.className = "ioc-group";
    const title = document.createElement("strong");
    title.textContent = name.replaceAll("_", " ").toUpperCase();
    const list = document.createElement("ul");
    values.forEach((value) => {
      const li = document.createElement("li");
      li.textContent = value;
      list.appendChild(li);
    });
    item.append(title, list);
    grid.appendChild(item);
  });

  wrap.append(heading, grid);
  parent.appendChild(wrap);
}

function renderError(error) {
  resultsEmpty.hidden = false;
  resultsContainer.hidden = true;
  resultsContainer.innerHTML = "";
  rawJson.textContent = error.stack || error.message || String(error);
  resultChips.innerHTML = "";
  downloadJsonButton.disabled = true;
  exportDocxButton.disabled = true;
}

function extractPlainText(outputKey, analysis) {
  const parts = [OUTPUT_LABELS[outputKey] || outputKey];

  if (outputKey === "pir") {
    parts.push(analysis.pir.title, analysis.pir.overview, analysis.pir.business_impact);
    parts.push(...analysis.pir.technical_findings, ...analysis.pir.indicators_of_compromise, ...analysis.pir.recommendations);
  }
  if (outputKey === "incident_summary") {
    parts.push(analysis.incident_summary.what_happened, analysis.incident_summary.impact, analysis.incident_summary.likely_root_cause);
    parts.push(...analysis.incident_summary.priority_actions);
  }
  if (outputKey === "executive_summary") {
    parts.push(analysis.executive_summary);
  }
  if (outputKey === "timeline_report") {
    parts.push(...analysis.timeline_report.events.map((event) => `${event.timestamp} ${event.event} ${event.source}`.trim()));
  }
  if (outputKey === "ioc_report") {
    for (const [name, values] of Object.entries(analysis.ioc_report)) {
      if (values.length) {
        parts.push(`${name}: ${values.join(", ")}`);
      }
    }
  }
  if (outputKey === "remediation_plan") {
    parts.push(...analysis.remediation_plan.immediate, ...analysis.remediation_plan.next_24_hours, ...analysis.remediation_plan.hardening);
  }
  if (outputKey === "customer_update") {
    parts.push(analysis.customer_update.subject, analysis.customer_update.message);
  }

  return parts.filter(Boolean).join("\n\n");
}

function downloadJson() {
  if (!latestAnalysis) {
    return;
  }
  const filename = `${slugify(latestPayload?.metadata?.caseTitle || "incident-analysis")}.json`;
  const blob = new Blob([JSON.stringify(latestAnalysis, null, 2)], { type: "application/json" });
  saveAs(blob, filename);
}

async function exportSelectedDocs() {
  if (!latestAnalysis || !latestPayload) {
    return;
  }

  const selectedOutputs = getSelectedOutputs();
  if (!selectedOutputs.length) {
    setRunState("Error", "Select at least one output before exporting.", true);
    return;
  }

  setRunState("Exporting", "Building DOCX bundle.");
  exportDocxButton.disabled = true;

  try {
    const zip = new JSZip();
    const docs = [];

    for (const outputKey of selectedOutputs) {
      const blob = await buildDocx(outputKey, latestAnalysis, latestPayload);
      docs.push({ outputKey, blob });
    }

    if (docs.length === 1) {
      const { outputKey, blob } = docs[0];
      saveAs(blob, `${slugify(latestPayload.metadata.caseTitle || "incident")}-${outputKey}.docx`);
    } else {
      docs.forEach(({ outputKey, blob }) => {
        zip.file(`${slugify(latestPayload.metadata.caseTitle || "incident")}-${outputKey}.docx`, blob);
      });
      const bundle = await zip.generateAsync({ type: "blob" });
      saveAs(bundle, `${slugify(latestPayload.metadata.caseTitle || "incident")}-report-pack.zip`);
    }

    setRunState("Ready", "DOCX export complete.");
  } catch (error) {
    console.error(error);
    setRunState("Error", `Export failed: ${error.message}`, true);
  } finally {
    exportDocxButton.disabled = false;
  }
}

async function buildDocx(outputKey, analysis, payload) {
  const { Document, HeadingLevel, Packer, Paragraph, TextRun } = window.docx;

  const children = [];
  children.push(new Paragraph({
    text: OUTPUT_LABELS[outputKey] || outputKey,
    heading: HeadingLevel.TITLE,
  }));

  children.push(new Paragraph({
    children: [
      new TextRun({ text: `Client: ${payload.metadata.clientName || "Unspecified"}\n`, bold: true }),
      new TextRun(`Case: ${payload.metadata.caseTitle || "Unspecified"}\n`),
      new TextRun(`Analyst: ${payload.metadata.analystName || "Unspecified"}\n`),
      new TextRun(`Generated: ${new Date().toLocaleString()}`),
    ],
  }));

  appendDocParagraph(children, `Incident Type: ${analysis.incident_profile.incident_type || payload.metadata.incidentType}`);
  appendDocParagraph(children, `Severity: ${analysis.incident_profile.severity || payload.metadata.severity || "Pending"}`);
  appendDocParagraph(children, `Confidence: ${analysis.incident_profile.confidence || "Pending"}`);

  if (outputKey === "pir") {
    appendDocHeading(children, "Overview");
    appendDocParagraph(children, analysis.pir.overview);
    appendDocHeading(children, "Business Impact");
    appendDocParagraph(children, analysis.pir.business_impact);
    appendDocBulletList(children, analysis.pir.technical_findings, "Technical Findings");
    appendDocTimeline(children, analysis.pir.timeline, "Timeline");
    appendDocBulletList(children, analysis.pir.indicators_of_compromise, "Indicators of Compromise");
    appendDocBulletList(children, analysis.pir.containment_actions, "Containment Actions");
    appendDocBulletList(children, analysis.pir.eradication_actions, "Eradication Actions");
    appendDocBulletList(children, analysis.pir.recovery_actions, "Recovery Actions");
    appendDocBulletList(children, analysis.pir.recommendations, "Recommendations");
    appendDocBulletList(children, analysis.pir.lessons_learned, "Lessons Learned");
  }

  if (outputKey === "incident_summary") {
    appendDocHeading(children, "What Happened");
    appendDocParagraph(children, analysis.incident_summary.what_happened);
    appendDocHeading(children, "Impact");
    appendDocParagraph(children, analysis.incident_summary.impact);
    appendDocBulletList(children, analysis.incident_summary.affected_assets, "Affected Assets");
    appendDocHeading(children, "Likely Root Cause");
    appendDocParagraph(children, analysis.incident_summary.likely_root_cause);
    appendDocBulletList(children, analysis.incident_summary.priority_actions, "Priority Actions");
  }

  if (outputKey === "executive_summary") {
    appendDocHeading(children, "Executive Summary");
    appendDocParagraph(children, analysis.executive_summary);
  }

  if (outputKey === "timeline_report") {
    appendDocTimeline(children, analysis.timeline_report.events, "Timeline");
  }

  if (outputKey === "ioc_report") {
    appendDocHeading(children, "Indicators of Compromise");
    for (const [name, values] of Object.entries(analysis.ioc_report)) {
      appendDocBulletList(children, values, name.replaceAll("_", " ").toUpperCase());
    }
  }

  if (outputKey === "remediation_plan") {
    appendDocBulletList(children, analysis.remediation_plan.immediate, "Immediate Actions");
    appendDocBulletList(children, analysis.remediation_plan.next_24_hours, "Next 24 Hours");
    appendDocBulletList(children, analysis.remediation_plan.hardening, "Hardening");
  }

  if (outputKey === "customer_update") {
    appendDocHeading(children, "Subject");
    appendDocParagraph(children, analysis.customer_update.subject);
    appendDocHeading(children, "Message");
    appendDocParagraph(children, analysis.customer_update.message);
  }

  const doc = new Document({ sections: [{ children }] });
  return Packer.toBlob(doc);
}

function appendDocHeading(children, text) {
  const { HeadingLevel, Paragraph } = window.docx;
  children.push(new Paragraph({ text, heading: HeadingLevel.HEADING_2 }));
}

function appendDocParagraph(children, text) {
  const { Paragraph } = window.docx;
  if (!text) {
    return;
  }
  children.push(new Paragraph({ text }));
}

function appendDocBulletList(children, items, heading) {
  const { Paragraph } = window.docx;
  if (!items?.length) {
    return;
  }
  appendDocHeading(children, heading);
  items.forEach((item) => {
    children.push(new Paragraph({
      text: item,
      bullet: { level: 0 },
    }));
  });
}

function appendDocTimeline(children, events, heading) {
  const { Paragraph } = window.docx;
  if (!events?.length) {
    return;
  }
  appendDocHeading(children, heading);
  events.forEach((event) => {
    const line = [event.timestamp, event.event, event.source].filter(Boolean).join(" | ");
    children.push(new Paragraph({ text: line }));
  });
}

function slugify(value) {
  return (value || "incident")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80);
}