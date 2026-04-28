import { useCallback, useEffect, useMemo, useState } from "react";
import MainLayout from "../layout/MainLayout";
import { rules } from "../services/api";
import { useAuth } from "../context/AuthContext";

const emptyRuleForm = {
  name: "",
  description: "",
  category: "custom",
  severity: "Medium",
  enabled: true,
  logic: "AND",
  alertType: "Custom Rule Match",
  conditions: [{ field: "message", operator: "contains", value: "" }],
};

const normalizeConditions = (conditions) =>
  Array.isArray(conditions)
    ? conditions.filter((condition) => condition?.field && condition?.operator)
    : [];

const formatConditionSummary = (rule) => {
  const conditions = normalizeConditions(rule?.conditions);

  if (!conditions.length) return "No rule conditions configured.";

  return conditions
    .map(
      (condition) =>
        `${condition.field} ${condition.operator} "${condition.value ?? ""}"`
    )
    .join(` ${rule?.logic || "AND"} `);
};

const getSeverityClass = (severity = "") => {
  switch (String(severity).toLowerCase()) {
    case "critical":
      return "severity-critical";
    case "high":
      return "severity-high";
    case "medium":
      return "severity-medium";
    case "low":
      return "severity-low";
    default:
      return "severity-unknown";
  }
};

const Rules = () => {
  const { user } = useAuth();

  const [ruleList, setRuleList] = useState([]);
  const [form, setForm] = useState(emptyRuleForm);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [feedback, setFeedback] = useState("");
  const [search, setSearch] = useState("");
  const [categoryFilter, setCategoryFilter] = useState("");
  const [severityFilter, setSeverityFilter] = useState("");

  const isAdmin = user?.role === "admin";

  const loadRules = useCallback(async () => {
    try {
      setLoading(true);
      setError("");

      const response = await rules.list();
      setRuleList(response?.data?.data ?? []);
    } catch (fetchError) {
      setError(fetchError?.response?.data?.message || "Failed to load detection rules.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadRules();
  }, [loadRules]);

  const validateRule = () => {
    if (!form.name.trim()) return "Rule name is required.";
    if (!form.alertType.trim()) return "Alert type is required.";

    const validConditions = normalizeConditions(form.conditions);
    if (!validConditions.length) return "At least one valid condition is required.";

    const hasEmptyValue = validConditions.some(
      (condition) =>
        condition.operator !== "exists" && String(condition.value || "").trim() === ""
    );

    if (hasEmptyValue) return "Condition value cannot be empty unless operator is Exists.";

    return "";
  };

  const handleCreate = async () => {
    const validationError = validateRule();

    if (validationError) {
      setError(validationError);
      setFeedback("");
      return;
    }

    try {
      setSaving(true);
      setError("");
      setFeedback("");

      await rules.create({
        name: form.name.trim(),
        description: form.description.trim(),
        category: form.category,
        severity: form.severity,
        enabled: form.enabled,
        logic: form.logic,
        alertType: form.alertType.trim() || form.name.trim(),
        conditions: normalizeConditions(form.conditions),
      });

      setForm(emptyRuleForm);
      setFeedback("Detection rule deployed successfully.");
      await loadRules();
    } catch (saveError) {
      setError(saveError?.response?.data?.message || "Failed to create rule.");
    } finally {
      setSaving(false);
    }
  };

  const handleToggle = async (rule) => {
    try {
      setError("");
      setFeedback("");

      await rules.update(rule._id, { enabled: !rule.enabled });

      setFeedback(
        rule.enabled
          ? "Rule deactivated successfully."
          : "Rule activated successfully."
      );

      await loadRules();
    } catch (toggleError) {
      setError(toggleError?.response?.data?.message || "Failed to update rule.");
    }
  };

  const addCondition = () => {
    setForm((current) => ({
      ...current,
      conditions: [
        ...current.conditions,
        { field: "message", operator: "contains", value: "" },
      ],
    }));
  };

  const updateCondition = (index, field, value) => {
    setForm((current) => {
      const nextConditions = [...current.conditions];
      nextConditions[index] = {
        ...nextConditions[index],
        [field]: value,
      };

      return {
        ...current,
        conditions: nextConditions,
      };
    });
  };

  const removeCondition = (index) => {
    if (form.conditions.length <= 1) return;

    setForm((current) => ({
      ...current,
      conditions: current.conditions.filter(
        (_, conditionIndex) => conditionIndex !== index
      ),
    }));
  };

  const summary = useMemo(
    () =>
      ruleList.reduce(
        (acc, rule) => {
          acc.total += 1;
          if (rule.enabled) acc.enabled += 1;
          if (rule.category === "host" || rule.category === "auth") acc.host += 1;
          if (rule.category === "network") acc.network += 1;
          if (String(rule.severity).toLowerCase() === "critical") acc.critical += 1;
          return acc;
        },
        { total: 0, enabled: 0, host: 0, network: 0, critical: 0 }
      ),
    [ruleList]
  );

  const filteredRules = useMemo(() => {
    return ruleList.filter((rule) => {
      const keyword = search.toLowerCase();

      const matchesSearch =
        !keyword ||
        rule.name?.toLowerCase().includes(keyword) ||
        rule.description?.toLowerCase().includes(keyword) ||
        rule.alertType?.toLowerCase().includes(keyword) ||
        formatConditionSummary(rule).toLowerCase().includes(keyword);

      const matchesCategory = !categoryFilter || rule.category === categoryFilter;
      const matchesSeverity = !severityFilter || rule.severity === severityFilter;

      return matchesSearch && matchesCategory && matchesSeverity;
    });
  }, [ruleList, search, categoryFilter, severityFilter]);

  if (loading) {
    return (
      <MainLayout>
        <div className="loading">Loading rules...</div>
      </MainLayout>
    );
  }

  return (
    <MainLayout>
      <style>{`
        .rules-page {
          padding: 34px;
          min-height: calc(100vh - 80px);
          background: linear-gradient(135deg, #fff7ed 0%, #f8fbff 55%, #eef9f1 100%);
        }

        .rules-shell {
          max-width: 1220px;
          margin: 0 auto;
        }

        .rules-header {
          background: rgba(255,255,255,.96);
          border: 1px solid rgba(148,163,184,.2);
          border-radius: 24px;
          padding: 30px;
          margin-bottom: 24px;
          box-shadow: 0 18px 45px rgba(15,23,42,.08);
        }

        .rules-eyebrow {
          color: #0ea5e9;
          font-size: 12px;
          font-weight: 900;
          text-transform: uppercase;
          letter-spacing: .12em;
          margin-bottom: 8px;
        }

        .rules-header h1 {
          margin: 0;
          font-size: 34px;
          color: #0f2742;
        }

        .rules-header p {
          margin: 10px 0 0;
          color: #64748b;
          line-height: 1.6;
        }

        .rules-metrics {
          display: grid;
          grid-template-columns: repeat(5, minmax(0, 1fr));
          gap: 18px;
          margin-bottom: 22px;
        }

        .rule-metric-card,
        .rules-card {
          background: rgba(255,255,255,.96);
          border: 1px solid rgba(148,163,184,.2);
          box-shadow: 0 14px 34px rgba(15,23,42,.07);
        }

        .rule-metric-card {
          border-radius: 20px;
          padding: 22px;
        }

        .rule-metric-card span {
          display: block;
          font-size: 12px;
          color: #64748b;
          font-weight: 900;
          text-transform: uppercase;
          margin-bottom: 10px;
        }

        .rule-metric-card strong {
          font-size: 30px;
          color: #0f2742;
        }

        .rules-card {
          border-radius: 24px;
          padding: 24px;
          margin-bottom: 22px;
        }

        .rules-card h3 {
          margin: 0 0 6px;
          color: #172033;
          font-size: 21px;
        }

        .rules-card p {
          margin: 0 0 20px;
          color: #64748b;
          line-height: 1.6;
        }

        .rules-form-grid {
          display: grid;
          grid-template-columns: repeat(3, minmax(0, 1fr));
          gap: 16px;
          margin-bottom: 18px;
        }

        .rule-field {
          display: grid;
          gap: 9px;
        }

        .rule-field label {
          font-size: 13px;
          font-weight: 900;
          color: #334155;
        }

        .rule-field input,
        .rule-field select,
        .rule-field textarea,
        .rules-filter-bar input,
        .rules-filter-bar select {
          width: 100%;
          border: 1px solid #dbe3ef;
          background: #f8fbff;
          border-radius: 14px;
          padding: 13px 14px;
          outline: none;
          color: #172033;
          font-size: 14px;
        }

        .rule-field textarea {
          min-height: 92px;
          resize: vertical;
        }

        .rule-field input:focus,
        .rule-field select:focus,
        .rule-field textarea:focus,
        .rules-filter-bar input:focus,
        .rules-filter-bar select:focus {
          border-color: #0ea5e9;
          box-shadow: 0 0 0 4px rgba(14,165,233,.12);
          background: #fff;
        }

        .rules-conditions {
          margin-top: 18px;
        }

        .condition-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          gap: 14px;
          margin-bottom: 12px;
        }

        .condition-header strong {
          color: #172033;
        }

        .condition-row {
          display: grid;
          grid-template-columns: 1.1fr 1fr 1.5fr auto;
          gap: 12px;
          align-items: center;
          padding: 14px;
          border: 1px solid #e2e8f0;
          background: #f8fbff;
          border-radius: 16px;
          margin-bottom: 12px;
        }

        .primary-btn,
        .secondary-btn,
        .danger-btn {
          border: 0;
          border-radius: 14px;
          padding: 12px 17px;
          font-weight: 900;
          cursor: pointer;
          transition: .2s ease;
        }

        .primary-btn {
          color: #fff;
          background: linear-gradient(90deg, #0ea5e9, #2563eb);
          box-shadow: 0 12px 26px rgba(37,99,235,.22);
        }

        .secondary-btn {
          background: #eef6ff;
          color: #0f2742;
          border: 1px solid #dbeafe;
        }

        .danger-btn {
          background: #fff1f2;
          color: #be123c;
          border: 1px solid #fecdd3;
        }

        .primary-btn:disabled,
        .secondary-btn:disabled,
        .danger-btn:disabled {
          opacity: .55;
          cursor: not-allowed;
        }

        .rules-actions {
          display: flex;
          justify-content: flex-end;
          margin-top: 18px;
        }

        .rules-filter-bar {
          display: grid;
          grid-template-columns: 2fr 1fr 1fr;
          gap: 14px;
          margin-bottom: 18px;
        }

        .rule-list {
          display: grid;
          gap: 14px;
        }

        .rule-row {
          display: grid;
          grid-template-columns: minmax(0, 1fr) auto;
          gap: 18px;
          align-items: center;
          padding: 18px;
          border: 1px solid #e2e8f0;
          border-radius: 18px;
          background: #f8fbff;
        }

        .rule-title {
          display: flex;
          align-items: center;
          gap: 10px;
          flex-wrap: wrap;
          margin-bottom: 8px;
        }

        .rule-title strong {
          font-size: 17px;
          color: #172033;
        }

        .rule-meta {
          color: #64748b;
          font-size: 13px;
          margin-bottom: 8px;
        }

        .rule-summary {
          font-family: Consolas, monospace;
          font-size: 13px;
          color: #475569;
          background: #fff;
          border: 1px dashed #cbd5e1;
          border-radius: 12px;
          padding: 10px;
          overflow-wrap: anywhere;
        }

        .severity-pill,
        .status-pill {
          display: inline-flex;
          padding: 6px 10px;
          border-radius: 999px;
          font-size: 12px;
          font-weight: 900;
        }

        .severity-critical {
          background: #fee2e2;
          color: #991b1b;
        }

        .severity-high {
          background: #ffedd5;
          color: #9a3412;
        }

        .severity-medium {
          background: #fef9c3;
          color: #854d0e;
        }

        .severity-low {
          background: #dcfce7;
          color: #166534;
        }

        .severity-unknown {
          background: #e2e8f0;
          color: #475569;
        }

        .status-active {
          background: #ecfdf5;
          color: #047857;
        }

        .status-disabled {
          background: #f1f5f9;
          color: #64748b;
        }

        .error-message {
          background: #fff1f2;
          color: #be123c;
          border: 1px solid #fecdd3;
          border-radius: 14px;
          padding: 14px 16px;
          margin-bottom: 18px;
          font-weight: 800;
        }

        .success-message {
          background: #ecfdf5;
          color: #047857;
          border: 1px solid #bbf7d0;
          border-radius: 14px;
          padding: 14px 16px;
          margin-bottom: 18px;
          font-weight: 800;
        }

        .empty-rules {
          text-align: center;
          padding: 44px 18px;
          color: #64748b;
        }

        @media (max-width: 1050px) {
          .rules-metrics {
            grid-template-columns: repeat(2, minmax(0, 1fr));
          }

          .rules-form-grid,
          .rules-filter-bar {
            grid-template-columns: 1fr;
          }

          .condition-row {
            grid-template-columns: 1fr;
          }
        }

        @media (max-width: 700px) {
          .rules-page {
            padding: 16px;
          }

          .rules-header {
            padding: 24px;
          }

          .rules-header h1 {
            font-size: 28px;
          }

          .rules-metrics {
            grid-template-columns: 1fr;
          }

          .rule-row {
            grid-template-columns: 1fr;
          }

          .rules-actions,
          .primary-btn,
          .secondary-btn,
          .danger-btn {
            width: 100%;
          }
        }
      `}</style>

      <div className="rules-page">
        <div className="rules-shell">
          <section className="rules-header">
            <div className="rules-eyebrow">ThreatLens / Detection Policies</div>
            <h1>Detection Rules</h1>
            <p>
              Create, tune and manage rule-based detection logic for HIDS, NIDS,
              Snort alerts, authentication failures and suspicious telemetry.
            </p>
          </section>

          {error && <div className="error-message">{error}</div>}
          {feedback && <div className="success-message">{feedback}</div>}

          <section className="rules-metrics">
            <div className="rule-metric-card">
              <span>Total Rules</span>
              <strong>{summary.total}</strong>
            </div>

            <div className="rule-metric-card">
              <span>Enabled</span>
              <strong>{summary.enabled}</strong>
            </div>

            <div className="rule-metric-card">
              <span>Host/Auth</span>
              <strong>{summary.host}</strong>
            </div>

            <div className="rule-metric-card">
              <span>Network</span>
              <strong>{summary.network}</strong>
            </div>

            <div className="rule-metric-card">
              <span>Critical</span>
              <strong>{summary.critical}</strong>
            </div>
          </section>

          {isAdmin && (
            <section className="rules-card">
              <h3>Rule Builder</h3>
              <p>
                Build explainable detection rules. These rules work alongside your
                ML engine to detect known suspicious behavior.
              </p>

              <div className="rules-form-grid">
                <div className="rule-field">
                  <label>Rule Name</label>
                  <input
                    value={form.name}
                    placeholder="e.g. SSH Brute Force Attempt"
                    onChange={(event) =>
                      setForm((current) => ({ ...current, name: event.target.value }))
                    }
                  />
                </div>

                <div className="rule-field">
                  <label>Alert Type</label>
                  <input
                    value={form.alertType}
                    placeholder="e.g. Brute Force"
                    onChange={(event) =>
                      setForm((current) => ({
                        ...current,
                        alertType: event.target.value,
                      }))
                    }
                  />
                </div>

                <div className="rule-field">
                  <label>Severity</label>
                  <select
                    value={form.severity}
                    onChange={(event) =>
                      setForm((current) => ({
                        ...current,
                        severity: event.target.value,
                      }))
                    }
                  >
                    <option value="Low">Low</option>
                    <option value="Medium">Medium</option>
                    <option value="High">High</option>
                    <option value="Critical">Critical</option>
                  </select>
                </div>

                <div className="rule-field">
                  <label>Category</label>
                  <select
                    value={form.category}
                    onChange={(event) =>
                      setForm((current) => ({
                        ...current,
                        category: event.target.value,
                      }))
                    }
                  >
                    <option value="custom">Custom</option>
                    <option value="network">Network / NIDS</option>
                    <option value="host">Host / HIDS</option>
                    <option value="auth">Authentication</option>
                    <option value="malware">Malware Behavior</option>
                    <option value="data">Data Exfiltration</option>
                  </select>
                </div>

                <div className="rule-field">
                  <label>Logic</label>
                  <select
                    value={form.logic}
                    onChange={(event) =>
                      setForm((current) => ({ ...current, logic: event.target.value }))
                    }
                  >
                    <option value="AND">AND - all conditions match</option>
                    <option value="OR">OR - any condition matches</option>
                  </select>
                </div>

                <div className="rule-field">
                  <label>Initial Status</label>
                  <select
                    value={String(form.enabled)}
                    onChange={(event) =>
                      setForm((current) => ({
                        ...current,
                        enabled: event.target.value === "true",
                      }))
                    }
                  >
                    <option value="true">Enabled</option>
                    <option value="false">Disabled</option>
                  </select>
                </div>
              </div>

              <div className="rule-field">
                <label>Description</label>
                <textarea
                  value={form.description}
                  placeholder="Explain what this rule detects and when it should trigger."
                  onChange={(event) =>
                    setForm((current) => ({
                      ...current,
                      description: event.target.value,
                    }))
                  }
                />
              </div>

              <div className="rules-conditions">
                <div className="condition-header">
                  <strong>Rule Conditions</strong>
                  <button type="button" className="secondary-btn" onClick={addCondition}>
                    + Add Condition
                  </button>
                </div>

                {form.conditions.map((condition, index) => (
                  <div className="condition-row" key={`${condition.field}-${index}`}>
                    <select
                      value={condition.field}
                      onChange={(event) =>
                        updateCondition(index, "field", event.target.value)
                      }
                    >
                      <option value="message">Message</option>
                      <option value="ip">Source IP</option>
                      <option value="metadata.processName">Process Name</option>
                      <option value="metadata.filePath">File Path</option>
                      <option value="eventType">Event Type</option>
                      <option value="source">Source</option>
                      <option value="metadata.failedAttempts">Failed Attempts</option>
                      <option value="metadata.requestRate">Request Rate</option>
                      <option value="metadata.protocol">Protocol</option>
                      <option value="metadata.dstPort">Destination Port</option>
                    </select>

                    <select
                      value={condition.operator}
                      onChange={(event) =>
                        updateCondition(index, "operator", event.target.value)
                      }
                    >
                      <option value="equals">Equals</option>
                      <option value="contains">Contains</option>
                      <option value="greater_than">Greater Than</option>
                      <option value="less_than">Less Than</option>
                      <option value="exists">Exists</option>
                      <option value="in">In</option>
                    </select>

                    <input
                      value={condition.value}
                      placeholder={
                        condition.operator === "exists"
                          ? "No value needed"
                          : "Value, e.g. failed login"
                      }
                      disabled={condition.operator === "exists"}
                      onChange={(event) =>
                        updateCondition(index, "value", event.target.value)
                      }
                    />

                    <button
                      type="button"
                      className="danger-btn"
                      onClick={() => removeCondition(index)}
                      disabled={form.conditions.length <= 1}
                    >
                      Remove
                    </button>
                  </div>
                ))}
              </div>

              <div className="rules-actions">
                <button
                  type="button"
                  className="primary-btn"
                  disabled={saving || !form.name.trim()}
                  onClick={handleCreate}
                >
                  {saving ? "Deploying..." : "Deploy Rule"}
                </button>
              </div>
            </section>
          )}

          <section className="rules-card">
            <h3>Active Rulebook</h3>
            <p>
              Review existing rules, detection logic, status and hit count from the
              ThreatLens rule engine.
            </p>

            <div className="rules-filter-bar">
              <input
                value={search}
                placeholder="Search rule name, alert type, description, condition..."
                onChange={(event) => setSearch(event.target.value)}
              />

              <select
                value={categoryFilter}
                onChange={(event) => setCategoryFilter(event.target.value)}
              >
                <option value="">All categories</option>
                <option value="custom">Custom</option>
                <option value="network">Network / NIDS</option>
                <option value="host">Host / HIDS</option>
                <option value="auth">Authentication</option>
                <option value="malware">Malware Behavior</option>
                <option value="data">Data Exfiltration</option>
              </select>

              <select
                value={severityFilter}
                onChange={(event) => setSeverityFilter(event.target.value)}
              >
                <option value="">All severities</option>
                <option value="Critical">Critical</option>
                <option value="High">High</option>
                <option value="Medium">Medium</option>
                <option value="Low">Low</option>
              </select>
            </div>

            {filteredRules.length ? (
              <div className="rule-list">
                {filteredRules.map((rule) => {
                  const conditions = normalizeConditions(rule.conditions);

                  return (
                    <div key={rule._id} className="rule-row">
                      <div>
                        <div className="rule-title">
                          <strong>{rule.name}</strong>

                          <span
                            className={`severity-pill ${getSeverityClass(
                              rule.severity
                            )}`}
                          >
                            {rule.severity || "Unknown"}
                          </span>

                          <span
                            className={`status-pill ${
                              rule.enabled ? "status-active" : "status-disabled"
                            }`}
                          >
                            {rule.enabled ? "Active" : "Disabled"}
                          </span>
                        </div>

                        <div className="rule-meta">
                          {rule.category || "custom"} • {conditions.length} condition(s) •{" "}
                          {rule.logic || "AND"} logic • {rule.hitCount || 0} hits
                        </div>

                        {rule.description && (
                          <div className="rule-meta">{rule.description}</div>
                        )}

                        <div className="rule-summary">
                          {formatConditionSummary(rule)}
                        </div>
                      </div>

                      <div>
                        {isAdmin ? (
                          <button
                            type="button"
                            className={rule.enabled ? "danger-btn" : "primary-btn"}
                            onClick={() => handleToggle(rule)}
                          >
                            {rule.enabled ? "Deactivate" : "Activate"}
                          </button>
                        ) : (
                          <span
                            className={`status-pill ${
                              rule.enabled ? "status-active" : "status-disabled"
                            }`}
                          >
                            {rule.enabled ? "Active" : "Disabled"}
                          </span>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            ) : (
              <div className="empty-rules">
                No detection rules found for the selected filters.
              </div>
            )}
          </section>
        </div>
      </div>
    </MainLayout>
  );
};

export default Rules;