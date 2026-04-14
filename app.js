const SESSION_KEY_STORAGE = "five10-openrouter-key";
const DEFAULT_MODEL = "openrouter/auto";
const MAX_FILE_CHARS = 40000;
const MAX_TOTAL_EVIDENCE_CHARS = 120000;
const FALLBACK_DOCX_CDN = "https://cdn.jsdelivr.net/npm/docx@8.5.0/+esm";
const FALLBACK_JSZIP_CDN = "https://cdn.jsdelivr.net/npm/jszip@3.10.1/+esm";
const APP_CONFIG = window.FIVE10_CONFIG || {};
const API_BASE_URL = normalizeApiBaseUrl(APP_CONFIG.apiBaseUrl);

const OUTPUT_LABELS = {
  pir: "Post Incident Report",
  incident_summary: "Incident Summary",
  executive_summary: "Executive Summary",
  timeline_report: "Timeline Report",
  ioc_report: "IOC Report",
  remediation_plan: "Remediation Plan",
  customer_update: "Customer Update",
};

const INCIDENT_TEMPLATE_GUIDANCE = {
  generic: [
    "State clearly what happened, why it matters, what is confirmed, and what remains unknown.",
    "Use concrete timestamps, actors, assets, systems, and business consequences wherever evidence allows.",
    "Separate confirmed facts from assessment. Avoid vague filler and generic security boilerplate.",
    "When evidence supports it, structure the PIR as phases of the incident lifecycle rather than a flat bullet dump.",
  ],
  phishing_bec: [
    "Emphasize impersonation path, targeted recipients, fraudulent messages sent, attachment sizes, banking or payment risk, and any internal recipients who may have acted.",
    "Call out dwell time, mailbox reconnaissance, OAuth abuse, fake account creation, forwarding rules, and business process abuse.",
  ],
  malware_ransomware: [
    "Focus on initial access, execution, persistence, privilege escalation, lateral movement, encryption or destructive actions, and recovery blockers.",
    "Highlight impacted hosts, containment boundaries, encryption scope, backups, and restoration status.",
  ],
  identity_account_compromise: [
    "Focus on login events, MFA challenges, impossible travel, session hijacking, OAuth grants, device registrations, admin actions, and privilege abuse.",
    "Document account takeover sequence, persistence mechanisms, and downstream actions taken from the compromised identity.",
  ],
  endpoint_compromise: [
    "Focus on host timeline, process execution, persistence, tools dropped, affected user accounts, and containment verification.",
  ],
  network_intrusion: [
    "Focus on ingress, lateral movement, firewall or VPN activity, pivot points, affected subnets, exposed services, and infrastructure touched.",
  ],
  cloud_saas_incident: [
    "Focus on tenant-level actions, admin console activity, application grants, API abuse, external sharing, mailbox or file access, and identity propagation.",
  ],
  data_exfiltration: [
    "Focus on data accessed, data staged, transfer mechanism, likely recipients, sensitivity, volume, and legal or notification implications.",
  ],
  insider_threat: [
    "Focus on user intent indicators, unusual access patterns, policy deviation, privileged actions, data handling, and decision or HR touchpoints.",
  ],
  third_party_vendor_incident: [
    "Focus on trust relationships, vendor access scope, downstream exposure, notification dependencies, and compensating controls.",
  ],
  vulnerability_exploitation: [
    "Focus on exploited weakness, attack path, patch status, exposed systems, exploit evidence, and residual risk if remediation is incomplete.",
  ],
  operational_service_disruption: [
    "Focus on outage timeline, affected business functions, root cause indicators, restoration milestones, and open service risks.",
  ],
  compliance_policy_event: [
    "Focus on policy deviation, evidence trail, systems or records involved, scope, materiality, and required follow-up actions.",
  ],
};

const form = document.querySelector("#analysis-form");
const apiKeyInput = document.querySelector("#api-key");
const modelInput = document.querySelector("#model");
const keyStatus = document.querySelector("#key-status");
const keyFileInput = document.querySelector("#key-file-input");
const importKeyButton = document.querySelector("#import-key-button");
const clearKeyButton = document.querySelector("#clear-key-button");
const apiPanelNote = document.querySelector("#api-panel-note");
const backendStatus = document.querySelector("#backend-status");
const actionPanelNote = document.querySelector("#action-panel-note");
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
let docxLibraryPromise = null;
let zipLibraryPromise = null;

hydrateSessionKey();
configureBackendMode();
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
  if (API_BASE_URL) {
    keyStatus.textContent = "Backend mode active.";
    return;
  }
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
  if (API_BASE_URL) {
    return;
  }
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
  if (API_BASE_URL) {
    return;
  }
  apiKeyInput.value = "";
  sessionStorage.removeItem(SESSION_KEY_STORAGE);
  keyStatus.textContent = "Session key cleared.";
}

function configureBackendMode() {
  if (!API_BASE_URL) {
    backendStatus.hidden = true;
    return;
  }

  apiKeyInput.closest("label")?.classList.add("is-hidden");
  importKeyButton.classList.add("is-hidden");
  clearKeyButton.classList.add("is-hidden");
  keyStatus.textContent = "Server-managed key mode.";
  backendStatus.hidden = false;
  backendStatus.textContent = `Backend API enabled: ${API_BASE_URL}/api/analyze`;

  if (apiPanelNote) {
    apiPanelNote.textContent = "This deployment is configured to call a backend API. OpenRouter credentials are expected to live on the server, not in the browser.";
  }

  if (actionPanelNote) {
    actionPanelNote.textContent = "This page is configured for backend API mode. The browser will post case data to the server-side analysis endpoint instead of sending your key from the client.";
  }
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

  if (!API_BASE_URL && !key) {
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
  if (API_BASE_URL) {
    const response = await fetch(`${API_BASE_URL}/api/analyze`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ model, payload }),
    });

    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Backend analysis request failed: ${response.status} ${errorText}`);
    }

    const data = await response.json();
    if (!data?.analysis) {
      throw new Error("Backend response did not include an analysis payload.");
    }

    const normalized = normalizeAnalysis(data.analysis);
    normalized._meta = {
      model: data.model || model,
      generatedAt: data.generatedAt || new Date().toISOString(),
      source: "backend",
    };
    return normalized;
  }

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
  const templateRequirements = [
    "EXECUTIVE SUMMARY TEMPLATE:",
    "- Open with a concise title block and a leadership-friendly short version of the incident.",
    "- Include what happened, why it matters, immediate actions required today, and a bottom-line statement.",
    "- Keep wording plain enough for business stakeholders while preserving technical accuracy.",
    "POST INCIDENT REPORT TEMPLATE:",
    "- Use numbered major sections and a structured, review-ready report tone.",
    "- Prefer a phased incident narrative where evidence supports phases such as initial compromise, persistence, attack execution, containment, and recovery.",
    "- Include tables or table-friendly data structures for timeline, attacker infrastructure, affected accounts/assets, and risk tracking whenever evidence exists.",
    "- Include explicit risk status, urgent actions, unresolved questions, and evidence-backed conclusions.",
    "ALL OUTPUTS:",
    "- Do not invent evidence, indicators, targets, or business impact.",
    "- If evidence is partial, say what is confirmed, what is assessed, and what remains unknown.",
    "- Use strong, declarative writing and avoid generic filler such as 'continue monitoring' unless tied to a concrete risk.",
  ].join("\n");

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
    templateRequirements,
    "Use this JSON schema:",
    JSON.stringify(getResponseTemplate(), null, 2),
  ].join("\n\n");
}

function buildUserPrompt(payload) {
  const incidentGuidance = getIncidentSpecificGuidance(payload?.metadata?.incidentType);

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
      "Follow the executive summary and PIR template style described in the system prompt.",
      "For the PIR, include phase-based narrative, evidence-backed findings, and table-friendly detail objects whenever the evidence supports them.",
      "Return string arrays for technical findings, evidence highlights, indicators, recommendations, lessons learned, open questions, remediation steps, and talking points. Use object arrays only for timeline, infrastructure, affected accounts/assets, fraud path, and risk register.",
      "For the executive summary, make the short version understandable to non-technical leadership and make the urgent actions explicit.",
      "Use concise bullets and structured findings.",
    ].join("\n"),
    "INCIDENT-TYPE GUIDANCE",
    incidentGuidance,
  ].join("\n\n");
}

function getResponseTemplate() {
  return {
    report_metadata: {
      report_title: "",
      report_subtitle: "",
      prepared_for: "",
      prepared_by: "",
      report_date: "",
      classification: "Confidential",
    },
    incident_profile: {
      incident_type: "",
      severity: "",
      confidence: "",
      status: "",
      scope: "",
      reporting_window: "",
      attack_summary: "",
    },
    executive_brief: {
      headline: "",
      short_version: "",
      full_scope: "",
      why_it_matters: "",
      immediate_actions: [],
      bottom_line: "",
    },
    executive_summary: "",
    incident_summary: {
      what_happened: "",
      impact: "",
      business_risk: "",
      affected_assets: [],
      likely_root_cause: "",
      key_observations: [],
      priority_actions: [],
      decisions_required: [],
    },
    pir: {
      title: "",
      subtitle: "",
      overview: "",
      summary_of_findings: "",
      scope_and_exposure: "",
      business_impact: "",
      attack_narrative: "",
      technical_findings: [],
      evidence_highlights: [],
      timeline: [],
      attacker_infrastructure: [],
      affected_accounts: [],
      affected_assets: [],
      fraud_or_abuse_path: [],
      indicators_of_compromise: [],
      containment_actions: [],
      eradication_actions: [],
      recovery_actions: [],
      recommendations: [],
      lessons_learned: [],
      open_questions: [],
      references: [],
    },
    timeline_report: {
      events: [],
    },
    ioc_report: {
      hosts: [],
      users: [],
      ips: [],
      domains: [],
      urls: [],
      email_addresses: [],
      hashes: [],
      artifacts: [],
    },
    risk_register: [],
    remediation_plan: {
      immediate: [],
      next_24_hours: [],
      hardening: [],
      strategic: [],
    },
    customer_update: {
      subject: "",
      message: "",
      talking_points: [],
    },
  };
}

function getIncidentSpecificGuidance(incidentType) {
  const normalizedType = normalizeIncidentTypeKey(incidentType);
  const lines = [
    ...INCIDENT_TEMPLATE_GUIDANCE.generic,
    ...(INCIDENT_TEMPLATE_GUIDANCE[normalizedType] || []),
  ];

  return lines.map((line) => `- ${line}`).join("\n");
}

function normalizeIncidentTypeKey(incidentType) {
  const value = (incidentType || "").toString().trim().toLowerCase();

  if (value.includes("phishing") || value.includes("bec")) {
    return "phishing_bec";
  }
  if (value.includes("malware") || value.includes("ransomware")) {
    return "malware_ransomware";
  }
  if (value.includes("identity") || value.includes("account compromise")) {
    return "identity_account_compromise";
  }
  if (value.includes("endpoint")) {
    return "endpoint_compromise";
  }
  if (value.includes("network")) {
    return "network_intrusion";
  }
  if (value.includes("cloud") || value.includes("saas")) {
    return "cloud_saas_incident";
  }
  if (value.includes("exfiltration")) {
    return "data_exfiltration";
  }
  if (value.includes("insider")) {
    return "insider_threat";
  }
  if (value.includes("vendor") || value.includes("third-party") || value.includes("third party")) {
    return "third_party_vendor_incident";
  }
  if (value.includes("vulnerability") || value.includes("exploitation")) {
    return "vulnerability_exploitation";
  }
  if (value.includes("disruption") || value.includes("operational") || value.includes("service")) {
    return "operational_service_disruption";
  }
  if (value.includes("compliance") || value.includes("policy")) {
    return "compliance_policy_event";
  }

  return "generic";
}

const OBJECT_LIST_ALIASES = {
  attacker_infrastructure: {
    ip_address: ["ip_address", "ip", "source_ip", "address", "indicator"],
    asn: ["asn", "as_number", "autonomous_system_number"],
    provider: ["provider", "isp", "service", "host", "hostname"],
    region: ["region", "geo", "country", "location"],
    role: ["role", "purpose", "type", "description"],
    notes: ["notes", "details", "summary", "evidence", "context"],
  },
  affected_accounts: {
    identifier: ["identifier", "account", "user", "email", "username", "principal", "mailbox"],
    account_type: ["account_type", "type", "category"],
    status: ["status", "state", "condition"],
    role: ["role", "title", "function", "privilege"],
    notes: ["notes", "details", "summary", "context"],
  },
  affected_assets: {
    asset: ["asset", "hostname", "host", "system", "resource", "mailbox", "application"],
    asset_type: ["asset_type", "type", "category"],
    owner: ["owner", "custodian", "assigned_to", "user"],
    status: ["status", "state", "condition"],
    notes: ["notes", "details", "summary", "context"],
  },
  fraud_or_abuse_path: {
    step: ["step", "action", "activity", "event", "phase"],
    description: ["description", "details", "summary", "narrative"],
    status: ["status", "state", "result"],
    notes: ["notes", "evidence", "context"],
  },
  risk_register: {
    risk: ["risk", "description", "summary", "issue", "finding", "name", "title", "details"],
    status: ["status", "state", "disposition", "progress"],
    priority: ["priority", "severity", "level"],
    owner: ["owner", "assigned_to", "assignee", "team"],
    next_step: ["next_step", "next_steps", "action", "recommended_action", "mitigation", "follow_up"],
  },
};

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

  merged.report_metadata.report_title = toParagraph(merged.report_metadata.report_title);
  merged.report_metadata.report_subtitle = toParagraph(merged.report_metadata.report_subtitle);
  merged.report_metadata.prepared_for = toParagraph(merged.report_metadata.prepared_for);
  merged.report_metadata.prepared_by = toParagraph(merged.report_metadata.prepared_by);
  merged.report_metadata.report_date = toParagraph(merged.report_metadata.report_date);
  merged.report_metadata.classification = toParagraph(merged.report_metadata.classification) || "Confidential";

  merged.incident_profile = merged.incident_profile || template.incident_profile;
  merged.incident_profile.reporting_window = toParagraph(merged.incident_profile.reporting_window);
  merged.incident_profile.attack_summary = toParagraph(merged.incident_profile.attack_summary);

  merged.executive_brief.headline = toParagraph(merged.executive_brief.headline);
  merged.executive_brief.short_version = toParagraph(merged.executive_brief.short_version);
  merged.executive_brief.full_scope = toParagraph(merged.executive_brief.full_scope);
  merged.executive_brief.why_it_matters = toParagraph(merged.executive_brief.why_it_matters);
  merged.executive_brief.immediate_actions = toList(merged.executive_brief.immediate_actions);
  merged.executive_brief.bottom_line = toParagraph(merged.executive_brief.bottom_line);

  merged.executive_summary = toParagraph(merged.executive_summary);
  merged.incident_summary.what_happened = toParagraph(merged.incident_summary.what_happened);
  merged.incident_summary.impact = toParagraph(merged.incident_summary.impact);
  merged.incident_summary.business_risk = toParagraph(merged.incident_summary.business_risk);
  merged.incident_summary.likely_root_cause = toParagraph(merged.incident_summary.likely_root_cause);
  merged.incident_summary.affected_assets = toList(merged.incident_summary.affected_assets);
  merged.incident_summary.key_observations = toList(merged.incident_summary.key_observations);
  merged.incident_summary.priority_actions = toList(merged.incident_summary.priority_actions);
  merged.incident_summary.decisions_required = toList(merged.incident_summary.decisions_required);

  merged.pir.title = toParagraph(merged.pir.title);
  merged.pir.subtitle = toParagraph(merged.pir.subtitle);
  merged.pir.summary_of_findings = toParagraph(merged.pir.summary_of_findings);
  merged.pir.overview = toParagraph(merged.pir.overview);
  merged.pir.scope_and_exposure = toParagraph(merged.pir.scope_and_exposure);
  merged.pir.business_impact = toParagraph(merged.pir.business_impact);
  merged.pir.attack_narrative = toParagraph(merged.pir.attack_narrative);
  merged.pir.technical_findings = toList(merged.pir.technical_findings);
  merged.pir.evidence_highlights = toList(merged.pir.evidence_highlights);
  merged.pir.timeline = normalizeTimeline(merged.pir.timeline);
  merged.pir.attacker_infrastructure = normalizeObjectList(merged.pir.attacker_infrastructure, OBJECT_LIST_ALIASES.attacker_infrastructure);
  merged.pir.affected_accounts = normalizeObjectList(merged.pir.affected_accounts, OBJECT_LIST_ALIASES.affected_accounts);
  merged.pir.affected_assets = normalizeObjectList(merged.pir.affected_assets, OBJECT_LIST_ALIASES.affected_assets);
  merged.pir.fraud_or_abuse_path = normalizeObjectList(merged.pir.fraud_or_abuse_path, OBJECT_LIST_ALIASES.fraud_or_abuse_path);
  merged.pir.indicators_of_compromise = toList(merged.pir.indicators_of_compromise);
  merged.pir.containment_actions = toList(merged.pir.containment_actions);
  merged.pir.eradication_actions = toList(merged.pir.eradication_actions);
  merged.pir.recovery_actions = toList(merged.pir.recovery_actions);
  merged.pir.recommendations = toList(merged.pir.recommendations);
  merged.pir.lessons_learned = toList(merged.pir.lessons_learned);
  merged.pir.open_questions = toList(merged.pir.open_questions);
  merged.pir.references = toList(merged.pir.references);

  merged.timeline_report.events = normalizeTimeline(merged.timeline_report.events.length ? merged.timeline_report.events : merged.pir.timeline);

  for (const key of Object.keys(merged.ioc_report)) {
    merged.ioc_report[key] = toList(merged.ioc_report[key]);
  }

  merged.risk_register = normalizeObjectList(merged.risk_register, OBJECT_LIST_ALIASES.risk_register);
  merged.risk_register = merged.risk_register.map(normalizeRiskRegisterEntry);
  merged.remediation_plan.immediate = toList(merged.remediation_plan.immediate);
  merged.remediation_plan.next_24_hours = toList(merged.remediation_plan.next_24_hours);
  merged.remediation_plan.hardening = toList(merged.remediation_plan.hardening);
  merged.remediation_plan.strategic = toList(merged.remediation_plan.strategic);
  merged.customer_update.subject = toParagraph(merged.customer_update.subject);
  merged.customer_update.message = toParagraph(merged.customer_update.message);
  merged.customer_update.talking_points = toList(merged.customer_update.talking_points);

  if (!merged.pir.indicators_of_compromise.length) {
    merged.pir.indicators_of_compromise = flattenIocReport(merged.ioc_report);
  }

  if (!merged.executive_summary) {
    merged.executive_summary = merged.executive_brief.short_version || merged.executive_brief.headline || merged.pir.summary_of_findings || merged.pir.overview;
  }

  if (!merged.pir.title) {
    merged.pir.title = merged.report_metadata.report_title || "Post Incident Report";
  }

  if (!merged.report_metadata.report_title) {
    merged.report_metadata.report_title = merged.pir.title || "Incident Report";
  }

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
          return { timestamp: "", phase: "", event: entry.trim(), details: "", source: "", actor: "", ip_address: "" };
        }
        return {
          timestamp: toParagraph(entry.timestamp || entry.time || entry.date),
          phase: toParagraph(entry.phase || entry.stage || ""),
          event: toParagraph(entry.event || entry.summary || entry.description),
          details: toParagraph(entry.details || entry.notes || ""),
          source: toParagraph(entry.source || entry.evidence || ""),
          actor: toParagraph(entry.actor || entry.user || ""),
          ip_address: toParagraph(entry.ip_address || entry.ip || entry.source_ip || ""),
        };
      })
      .filter((entry) => entry.event);
  }

  return toList(value).map((item) => ({ timestamp: "", phase: "", event: item, details: "", source: "", actor: "", ip_address: "" }));
}

function normalizeObjectList(value, keys) {
  if (!value) {
    return [];
  }

  const aliasMap = Array.isArray(keys)
    ? Object.fromEntries(keys.map((key) => [key, [key]]))
    : keys;
  const canonicalKeys = Object.keys(aliasMap);

  if (Array.isArray(value)) {
    return value
      .map((item) => {
        if (typeof item === "string") {
          return { [canonicalKeys[0]]: toParagraph(item) };
        }

        const normalized = {};
        canonicalKeys.forEach((key) => {
          normalized[key] = firstMatchingText(item, aliasMap[key]);
        });

        if (!normalized[canonicalKeys[0]]) {
          normalized[canonicalKeys[0]] = objectToParagraph(item);
        }

        return normalized;
      })
      .filter((item) => canonicalKeys.some((key) => item[key]));
  }

  return toList(value).map((item) => ({ [canonicalKeys[0]]: item }));
}

function toParagraph(value) {
  if (!value) {
    return "";
  }

  if (Array.isArray(value)) {
    return value.map((item) => toParagraph(item)).filter(Boolean).join("; ");
  }

  if (typeof value === "object") {
    return objectToParagraph(value);
  }

  const normalized = String(value).trim();
  return normalized === "[object Object]" ? "" : normalized;
}

function firstMatchingText(item, aliases) {
  for (const key of aliases || []) {
    const text = toParagraph(item?.[key]);
    if (text) {
      return text;
    }
  }
  return "";
}

function objectToParagraph(value) {
  if (!value || typeof value !== "object") {
    return String(value || "").trim();
  }

  const parts = Object.entries(value)
    .map(([key, entryValue]) => ({
      key,
      text: typeof entryValue === "object" ? toParagraph(entryValue) : String(entryValue || "").trim(),
    }))
    .filter(({ text }) => text);

  if (!parts.length) {
    return "";
  }

  if (parts.length === 1) {
    return parts[0].text;
  }

  return parts.map(({ key, text }) => `${humanizeKey(key)}: ${text}`).join(" | ");
}

function humanizeKey(value) {
  return (value || "")
    .replace(/[_-]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function flattenIocReport(iocReport) {
  return Object.entries(iocReport || {})
    .flatMap(([key, values]) => values.map((value) => `${humanizeKey(key)}: ${value}`))
    .filter(Boolean);
}

function normalizeRiskRegisterEntry(entry) {
  const normalized = { ...entry };
  const segments = parseLabeledSegments(entry.risk);
  const riskId = segments["risk id"];
  const riskDescription = segments["risk description"] || segments.risk || segments.description || segments.summary;

  if (!normalized.risk && riskDescription) {
    normalized.risk = riskId ? `${riskId}: ${riskDescription}` : riskDescription;
  }

  if (normalized.risk && riskDescription && normalized.risk.includes("|") ) {
    normalized.risk = riskId ? `${riskId}: ${riskDescription}` : riskDescription;
  }

  if (!normalized.status) {
    normalized.status = segments["current status"] || segments.status;
  }

  if (!normalized.priority) {
    normalized.priority = segments.priority || segments.severity || segments.impact || segments.likelihood;
  }

  if (!normalized.owner) {
    normalized.owner = segments.owner || segments.team;
  }

  if (!normalized.next_step) {
    normalized.next_step = segments["mitigation actions"] || segments["next step"] || segments.action || segments["follow up"];
  }

  return normalized;
}

function parseLabeledSegments(value) {
  return String(value || "")
    .split("|")
    .map((segment) => segment.trim())
    .reduce((accumulator, segment) => {
      const match = segment.match(/^([^:]+):\s*(.+)$/);
      if (match) {
        accumulator[match[1].trim().toLowerCase()] = match[2].trim();
      }
      return accumulator;
    }, {});
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

  resultsContainer.scrollIntoView({ behavior: "smooth", block: "start" });
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
      appendSection(card, "Subtitle", analysis.pir.subtitle);
      appendSection(card, "Summary of Findings", analysis.pir.summary_of_findings);
      appendSection(card, "Overview", analysis.pir.overview);
      appendSection(card, "Scope and Exposure", analysis.pir.scope_and_exposure);
      appendSection(card, "Business Impact", analysis.pir.business_impact);
      appendSection(card, "Attack Narrative", analysis.pir.attack_narrative);
      appendListSection(card, "Evidence Highlights", analysis.pir.evidence_highlights);
      appendListSection(card, "Technical Findings", analysis.pir.technical_findings);
      appendTimelineSection(card, "Timeline", analysis.pir.timeline);
      appendObjectMatrixSection(card, "Attacker Infrastructure", analysis.pir.attacker_infrastructure, ["ip_address", "asn", "provider", "region", "role", "notes"]);
      appendObjectMatrixSection(card, "Affected Accounts", analysis.pir.affected_accounts, ["identifier", "account_type", "status", "role", "notes"]);
      appendObjectMatrixSection(card, "Affected Assets", analysis.pir.affected_assets, ["asset", "asset_type", "owner", "status", "notes"]);
      appendObjectMatrixSection(card, "Fraud / Abuse Path", analysis.pir.fraud_or_abuse_path, ["step", "description", "status", "notes"]);
      appendListSection(card, "Indicators of Compromise", analysis.pir.indicators_of_compromise);
      appendRiskRegisterSection(card, analysis.risk_register);
      appendListSection(card, "Containment Actions", analysis.pir.containment_actions);
      appendListSection(card, "Eradication Actions", analysis.pir.eradication_actions);
      appendListSection(card, "Recovery Actions", analysis.pir.recovery_actions);
      appendListSection(card, "Recommendations", analysis.pir.recommendations);
      appendListSection(card, "Lessons Learned", analysis.pir.lessons_learned);
      appendListSection(card, "Open Questions", analysis.pir.open_questions);
      appendListSection(card, "References", analysis.pir.references);
      break;
    case "incident_summary":
      appendSection(card, "What Happened", analysis.incident_summary.what_happened);
      appendSection(card, "Impact", analysis.incident_summary.impact);
      appendSection(card, "Business Risk", analysis.incident_summary.business_risk);
      appendListSection(card, "Affected Assets", analysis.incident_summary.affected_assets);
      appendSection(card, "Likely Root Cause", analysis.incident_summary.likely_root_cause);
      appendListSection(card, "Key Observations", analysis.incident_summary.key_observations);
      appendListSection(card, "Priority Actions", analysis.incident_summary.priority_actions);
      appendListSection(card, "Decisions Required", analysis.incident_summary.decisions_required);
      break;
    case "executive_summary":
      appendSection(card, "Headline", analysis.executive_brief.headline);
      appendSection(card, "Short Version", analysis.executive_brief.short_version || analysis.executive_summary);
      appendSection(card, "Full Scope", analysis.executive_brief.full_scope);
      appendSection(card, "Why It Matters", analysis.executive_brief.why_it_matters);
      appendListSection(card, "Immediate Actions", analysis.executive_brief.immediate_actions);
      appendSection(card, "Bottom Line", analysis.executive_brief.bottom_line);
      appendRiskRegisterSection(card, analysis.risk_register);
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
      appendListSection(card, "Strategic Improvements", analysis.remediation_plan.strategic);
      break;
    case "customer_update":
      appendSection(card, "Subject", analysis.customer_update.subject);
      appendSection(card, "Message", analysis.customer_update.message);
      appendListSection(card, "Talking Points", analysis.customer_update.talking_points);
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
    source.textContent = [event.phase, event.actor, event.ip_address, event.details, event.source].filter(Boolean).join(" | ") || "No supporting detail supplied.";
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

function appendObjectMatrixSection(parent, label, items, keys) {
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
    li.textContent = keys
      .map((key) => item[key])
      .filter(Boolean)
      .join(" | ");
    if (li.textContent) {
      list.appendChild(li);
    }
  });

  if (!list.children.length) {
    return;
  }

  wrap.append(heading, list);
  parent.appendChild(wrap);
}

function appendRiskRegisterSection(parent, risks) {
  if (!risks?.length) {
    return;
  }

  const wrap = document.createElement("section");
  wrap.className = "subsection";
  const heading = document.createElement("h5");
  heading.textContent = "Risk Register";
  const list = document.createElement("ul");

  risks.forEach((risk) => {
    const li = document.createElement("li");
    li.textContent = [risk.risk, risk.status, risk.priority, risk.owner, risk.next_step].filter(Boolean).join(" | ");
    if (li.textContent) {
      list.appendChild(li);
    }
  });

  if (!list.children.length) {
    return;
  }

  wrap.append(heading, list);
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
    parts.push(
      analysis.incident_summary.what_happened,
      analysis.incident_summary.impact,
      analysis.incident_summary.business_risk,
      analysis.incident_summary.likely_root_cause,
    );
    parts.push(...analysis.incident_summary.key_observations, ...analysis.incident_summary.priority_actions, ...analysis.incident_summary.decisions_required);
  }
  if (outputKey === "executive_summary") {
    parts.push(
      analysis.executive_brief.headline,
      analysis.executive_brief.short_version || analysis.executive_summary,
      analysis.executive_brief.full_scope,
      analysis.executive_brief.why_it_matters,
      analysis.executive_brief.bottom_line,
    );
    parts.push(...analysis.executive_brief.immediate_actions);
  }
  if (outputKey === "timeline_report") {
    parts.push(...analysis.timeline_report.events.map((event) => [event.timestamp, event.phase, event.event, event.details, event.actor, event.ip_address, event.source].filter(Boolean).join(" | ")));
  }
  if (outputKey === "ioc_report") {
    for (const [name, values] of Object.entries(analysis.ioc_report)) {
      if (values.length) {
        parts.push(`${name}: ${values.join(", ")}`);
      }
    }
  }
  if (outputKey === "remediation_plan") {
    parts.push(...analysis.remediation_plan.immediate, ...analysis.remediation_plan.next_24_hours, ...analysis.remediation_plan.hardening, ...analysis.remediation_plan.strategic);
  }
  if (outputKey === "customer_update") {
    parts.push(analysis.customer_update.subject, analysis.customer_update.message, ...analysis.customer_update.talking_points);
  }

  return parts.filter(Boolean).join("\n\n");
}

function downloadJson() {
  if (!latestAnalysis) {
    return;
  }
  const filename = `${slugify(latestPayload?.metadata?.caseTitle || "incident-analysis")}.json`;
  const blob = new Blob([JSON.stringify(latestAnalysis, null, 2)], { type: "application/json" });
  downloadBlob(blob, filename);
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
    const ZipLibrary = await getZipLibrary();
    const zip = new ZipLibrary();
    const docs = [];

    for (const outputKey of selectedOutputs) {
      const blob = await buildDocx(outputKey, latestAnalysis, latestPayload);
      docs.push({ outputKey, blob });
    }

    if (docs.length === 1) {
      const { outputKey, blob } = docs[0];
      downloadBlob(blob, `${slugify(latestPayload.metadata.caseTitle || "incident")}-${outputKey}.docx`);
    } else {
      docs.forEach(({ outputKey, blob }) => {
        zip.file(`${slugify(latestPayload.metadata.caseTitle || "incident")}-${outputKey}.docx`, blob);
      });
      const bundle = await zip.generateAsync({ type: "blob" });
      downloadBlob(bundle, `${slugify(latestPayload.metadata.caseTitle || "incident")}-report-pack.zip`);
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
  const docxLibrary = await getDocxLibrary();
  const { Document, HeadingLevel, Packer, Paragraph } = docxLibrary;

  const children = [];
  const title = getOutputDocumentTitle(outputKey, analysis, payload);
  const subtitle = getOutputDocumentSubtitle(outputKey, analysis, payload);

  children.push(new Paragraph({ text: title, heading: HeadingLevel.TITLE }));
  if (subtitle) {
    children.push(new Paragraph({ text: subtitle }));
  }

  appendDocMetadataTable(children, analysis, payload, outputKey);

  if (outputKey === "pir") {
    appendDocHeading(children, "1. Executive Overview");
    appendDocParagraph(children, analysis.pir.summary_of_findings || analysis.pir.overview);
    appendDocParagraph(children, analysis.pir.overview);
    appendDocHeading(children, "2. Scope and Business Impact");
    appendDocParagraph(children, analysis.pir.scope_and_exposure);
    appendDocParagraph(children, analysis.pir.business_impact);
    appendDocHeading(children, "3. Attack Narrative");
    appendDocParagraph(children, analysis.pir.attack_narrative);
    appendDocBulletList(children, analysis.pir.evidence_highlights, "4. Evidence Highlights");
    appendDocBulletList(children, analysis.pir.technical_findings, "5. Technical Findings");
    appendDocTimelineTable(children, analysis.pir.timeline, "6. Timeline of Events");
    appendDocObjectTable(children, "7. Attacker Infrastructure", analysis.pir.attacker_infrastructure, [
      { key: "ip_address", label: "IP Address" },
      { key: "asn", label: "ASN" },
      { key: "provider", label: "Provider" },
      { key: "region", label: "Region" },
      { key: "role", label: "Role / Notes" },
    ]);
    appendDocObjectTable(children, "8. Affected Accounts", analysis.pir.affected_accounts, [
      { key: "identifier", label: "Account" },
      { key: "account_type", label: "Type" },
      { key: "status", label: "Status" },
      { key: "role", label: "Role" },
      { key: "notes", label: "Notes" },
    ]);
    appendDocObjectTable(children, "9. Affected Assets", analysis.pir.affected_assets, [
      { key: "asset", label: "Asset" },
      { key: "asset_type", label: "Type" },
      { key: "owner", label: "Owner" },
      { key: "status", label: "Status" },
      { key: "notes", label: "Notes" },
    ]);
    appendDocObjectTable(children, "10. Fraud / Abuse Activity", analysis.pir.fraud_or_abuse_path, [
      { key: "step", label: "Step" },
      { key: "description", label: "Description" },
      { key: "status", label: "Status" },
      { key: "notes", label: "Notes" },
    ]);
    appendDocIocTables(children, analysis.ioc_report, "11. Indicators of Compromise");
    appendDocRiskRegister(children, analysis.risk_register, "12. Risk Register");
    appendDocBulletList(children, analysis.pir.containment_actions, "13. Containment Actions");
    appendDocBulletList(children, analysis.pir.eradication_actions, "14. Eradication Actions");
    appendDocBulletList(children, analysis.pir.recovery_actions, "15. Recovery Actions");
    appendDocBulletList(children, analysis.pir.recommendations, "16. Recommendations");
    appendDocBulletList(children, analysis.pir.lessons_learned, "17. Lessons Learned");
    appendDocBulletList(children, analysis.pir.open_questions, "18. Open Questions");
    appendDocBulletList(children, analysis.pir.references, "19. References");
  }

  if (outputKey === "incident_summary") {
    appendDocHeading(children, "Incident Summary");
    appendDocParagraph(children, analysis.incident_summary.what_happened);
    appendDocHeading(children, "Business Impact");
    appendDocParagraph(children, analysis.incident_summary.impact);
    appendDocParagraph(children, analysis.incident_summary.business_risk);
    appendDocBulletList(children, analysis.incident_summary.affected_assets, "Affected Assets");
    appendDocHeading(children, "Likely Root Cause");
    appendDocParagraph(children, analysis.incident_summary.likely_root_cause);
    appendDocBulletList(children, analysis.incident_summary.key_observations, "Key Observations");
    appendDocBulletList(children, analysis.incident_summary.priority_actions, "Priority Actions");
    appendDocBulletList(children, analysis.incident_summary.decisions_required, "Decisions Required");
  }

  if (outputKey === "executive_summary") {
    appendDocHeading(children, "WHAT HAPPENED - THE SHORT VERSION");
    appendDocParagraph(children, analysis.executive_brief.short_version || analysis.executive_summary);
    appendDocHeading(children, "THE FULL SCOPE");
    appendDocParagraph(children, analysis.executive_brief.full_scope || analysis.pir.attack_narrative || analysis.pir.overview);
    appendDocHeading(children, "WHY IT MATTERS");
    appendDocParagraph(children, analysis.executive_brief.why_it_matters || analysis.incident_summary.business_risk || analysis.pir.business_impact);
    appendDocBulletList(children, analysis.executive_brief.immediate_actions.length ? analysis.executive_brief.immediate_actions : analysis.incident_summary.priority_actions, "WHAT STILL NEEDS TO HAPPEN - URGENTLY");
    appendDocHeading(children, "BOTTOM LINE");
    appendDocParagraph(children, analysis.executive_brief.bottom_line || analysis.executive_summary);
    appendDocRiskRegister(children, analysis.risk_register, "Key Risks and Status");
  }

  if (outputKey === "timeline_report") {
    appendDocTimelineTable(children, analysis.timeline_report.events, "Timeline");
  }

  if (outputKey === "ioc_report") {
    appendDocIocTables(children, analysis.ioc_report, "Indicators of Compromise");
  }

  if (outputKey === "remediation_plan") {
    appendDocBulletList(children, analysis.remediation_plan.immediate, "Immediate Actions");
    appendDocBulletList(children, analysis.remediation_plan.next_24_hours, "Next 24 Hours");
    appendDocBulletList(children, analysis.remediation_plan.hardening, "Hardening");
    appendDocBulletList(children, analysis.remediation_plan.strategic, "Strategic Improvements");
    appendDocRiskRegister(children, analysis.risk_register, "Related Risks");
  }

  if (outputKey === "customer_update") {
    appendDocHeading(children, "Subject");
    appendDocParagraph(children, analysis.customer_update.subject);
    appendDocHeading(children, "Message");
    appendDocParagraph(children, analysis.customer_update.message);
    appendDocBulletList(children, analysis.customer_update.talking_points, "Talking Points");
  }

  const doc = new Document({ sections: [{ children }] });
  return Packer.toBlob(doc);
}

function getOutputDocumentTitle(outputKey, analysis, payload) {
  if (outputKey === "pir") {
    return analysis.pir.title || analysis.report_metadata.report_title || OUTPUT_LABELS.pir;
  }

  if (outputKey === "executive_summary") {
    return analysis.executive_brief.headline || OUTPUT_LABELS.executive_summary;
  }

  return OUTPUT_LABELS[outputKey] || payload.metadata.caseTitle || "Incident Report";
}

function getOutputDocumentSubtitle(outputKey, analysis, payload) {
  if (outputKey === "executive_summary") {
    return [payload.metadata.clientName, analysis.report_metadata.report_date, analysis.report_metadata.classification].filter(Boolean).join(" | ");
  }

  return [analysis.pir.subtitle, payload.metadata.clientName, analysis.report_metadata.report_date].filter(Boolean).join(" | ");
}

function appendDocHeading(children, text, level = "HEADING_2") {
  const { HeadingLevel, Paragraph } = getLoadedDocxLibrary();
  children.push(new Paragraph({ text, heading: HeadingLevel[level] }));
}

function appendDocParagraph(children, text) {
  const { Paragraph } = getLoadedDocxLibrary();
  if (!text) {
    return;
  }
  children.push(new Paragraph({ text }));
}

function appendDocBulletList(children, items, heading) {
  const { Paragraph } = getLoadedDocxLibrary();
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

function appendDocMetadataTable(children, analysis, payload, outputKey) {
  const rows = [
    { field: "Client / Organization", value: payload.metadata.clientName || analysis.report_metadata.prepared_for || "Unspecified" },
    { field: "Case Title", value: payload.metadata.caseTitle || analysis.report_metadata.report_title || "Unspecified" },
    { field: "Analyst", value: payload.metadata.analystName || analysis.report_metadata.prepared_by || "Unspecified" },
    { field: "Incident Type", value: analysis.incident_profile.incident_type || payload.metadata.incidentType || "Pending" },
    { field: "Severity", value: analysis.incident_profile.severity || payload.metadata.severity || "Pending" },
    { field: "Confidence", value: analysis.incident_profile.confidence || "Pending" },
    { field: "Status", value: analysis.incident_profile.status || "Pending" },
    { field: "Scope", value: analysis.incident_profile.scope || "Pending" },
    { field: "Classification", value: analysis.report_metadata.classification || "Confidential" },
    { field: "Prepared Date", value: analysis.report_metadata.report_date || new Date().toLocaleDateString() },
    { field: "Output Type", value: OUTPUT_LABELS[outputKey] || outputKey },
  ];

  appendDocObjectTable(children, "Case Metadata", rows, [
    { key: "field", label: "Field" },
    { key: "value", label: "Value" },
  ]);
}

function appendDocTimelineTable(children, events, heading) {
  if (!events?.length) {
    return;
  }

  appendDocObjectTable(children, heading, events.map((event) => ({
    timestamp: event.timestamp || "",
    phase: event.phase || "",
    event: event.event || "",
    context: [event.actor, event.ip_address, event.details, event.source].filter(Boolean).join(" | "),
  })), [
    { key: "timestamp", label: "Timestamp" },
    { key: "phase", label: "Phase" },
    { key: "event", label: "Event" },
    { key: "context", label: "Context" },
  ]);
}

function appendDocIocTables(children, iocReport, heading) {
  const rows = Object.entries(iocReport)
    .filter(([, values]) => values.length)
    .map(([name, values]) => ({ indicator_type: name.replaceAll("_", " ").toUpperCase(), values: values.join("; ") }));

  if (!rows.length) {
    appendDocHeading(children, heading);
    appendDocParagraph(children, "No concrete indicators were identified in the supplied evidence.");
    return;
  }

  appendDocObjectTable(children, heading, rows, [
    { key: "indicator_type", label: "Indicator Type" },
    { key: "values", label: "Values" },
  ]);
}

function appendDocRiskRegister(children, risks, heading) {
  if (!risks?.length) {
    return;
  }

  appendDocObjectTable(children, heading, risks, [
    { key: "risk", label: "Risk" },
    { key: "status", label: "Status" },
    { key: "priority", label: "Priority" },
    { key: "owner", label: "Owner" },
    { key: "next_step", label: "Next Step" },
  ]);
}

function appendDocObjectTable(children, heading, items, columns) {
  const { Paragraph, Table, TableCell, TableRow, TextRun, WidthType } = getLoadedDocxLibrary();
  if (!items?.length) {
    return;
  }

  appendDocHeading(children, heading);

  const headerRow = new TableRow({
    children: columns.map((column) => new TableCell({
      children: [new Paragraph({ children: [new TextRun({ text: column.label, bold: true })] })],
    })),
  });

  const dataRows = items.map((item) => new TableRow({
    children: columns.map((column) => new TableCell({
      children: [new Paragraph({ text: toParagraph(item[column.key]) || "-" })],
    })),
  }));

  children.push(new Table({
    width: { size: 100, type: WidthType.PERCENTAGE },
    rows: [headerRow, ...dataRows],
  }));
}

function slugify(value) {
  return (value || "incident")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80);
}

function normalizeApiBaseUrl(value) {
  return (value || "").toString().trim().replace(/\/+$/, "");
}

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.style.display = "none";
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

async function getDocxLibrary() {
  if (window.docx) {
    return window.docx;
  }
  if (!docxLibraryPromise) {
    docxLibraryPromise = import(FALLBACK_DOCX_CDN).then((module) => module.default || module);
  }
  const library = await docxLibraryPromise;
  if (!window.docx) {
    window.docx = library;
  }
  return library;
}

function getLoadedDocxLibrary() {
  if (!window.docx) {
    throw new Error("DOCX library is not loaded.");
  }
  return window.docx;
}

async function getZipLibrary() {
  if (window.JSZip) {
    return window.JSZip;
  }
  if (!zipLibraryPromise) {
    zipLibraryPromise = import(FALLBACK_JSZIP_CDN).then((module) => module.default || module);
  }
  const library = await zipLibraryPromise;
  if (!window.JSZip) {
    window.JSZip = library;
  }
  return library;
}