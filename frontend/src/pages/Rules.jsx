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
  if (conditions.length === 0) {
    return "No rule conditions configured.";
  }

  return conditions
    .map((condition) => `${condition.field} ${condition.operator} "${condition.value ?? ""}"`)
    .join(` ${rule?.logic || "AND"} `);
};

const Rules = () => {
  const { user } = useAuth();
  const [ruleList, setRuleList] = useState([]);
  const [form, setForm] = useState(emptyRuleForm);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const isAdmin = user?.role === "admin";

  const loadRules = useCallback(async () => {
    try {
      setLoading(true);
      setError("");
      const response = await rules.list();
      setRuleList(response?.data?.data ?? []);
    } catch (fetchError) {
      console.error("Rules fetch error:", fetchError);
      setError("Failed to load detection rules");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadRules();
  }, [loadRules]);

  const handleCreate = async () => {
    try {
      setSaving(true);
      setError("");

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
      await loadRules();
    } catch (saveError) {
      console.error("Rule create error:", saveError);
      setError(saveError?.response?.data?.message || "Failed to create rule");
    } finally {
      setSaving(false);
    }
  };

  const handleToggle = async (rule) => {
    try {
      setError("");
      await rules.update(rule._id, { enabled: !rule.enabled });
      await loadRules();
    } catch (toggleError) {
      console.error("Rule toggle error:", toggleError);
      setError("Failed to update rule");
    }
  };

  const addCondition = () => {
    setForm((current) => ({
      ...current,
      conditions: [...current.conditions, { field: "message", operator: "equals", value: "" }],
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
      conditions: current.conditions.filter((_, conditionIndex) => conditionIndex !== index),
    }));
  };

  const summary = useMemo(
    () =>
      ruleList.reduce(
        (accumulator, rule) => {
          accumulator.total += 1;
          if (rule.enabled) accumulator.enabled += 1;
          if (rule.category === "host" || rule.category === "auth") accumulator.host += 1;
          if (rule.category === "network") accumulator.network += 1;
          return accumulator;
        },
        { total: 0, enabled: 0, host: 0, network: 0 }
      ),
    [ruleList]
  );

  if (loading) {
    return (
      <MainLayout>
        <div className="loading">Loading rules...</div>
      </MainLayout>
    );
  }

  return (
    <MainLayout>
      <section className="command-header">
        <div>
          <div className="command-eyebrow">ThreatLens / Detection policies / tuning workspace</div>
          <h1>Detection Rules</h1>
          <p>Create and manage dynamic detection rules that evaluate telemetry in real time.</p>
        </div>
      </section>

      {error && <div className="error-message">{error}</div>}

      <section className="metrics-grid">
        <div className="metric-card"><span>Total Rules</span><strong>{summary.total}</strong></div>
        <div className="metric-card"><span>Enabled</span><strong>{summary.enabled}</strong></div>
        <div className="metric-card"><span>Host/Auth Rules</span><strong>{summary.host}</strong></div>
        <div className="metric-card"><span>Network Rules</span><strong>{summary.network}</strong></div>
      </section>

      {isAdmin && (
        <div className="card glass animate-in">
          <h3>Rule Builder</h3>
          <div className="form-grid" style={{ gridTemplateColumns: "repeat(3, 1fr)", gap: "16px", marginBottom: "20px" }}>
            <div className="form-group">
              <label className="panel-label">Rule Name</label>
              <input value={form.name} placeholder="e.g. Critical File Access" onChange={(event) => setForm((current) => ({ ...current, name: event.target.value }))} style={{ width: "100%" }} />
            </div>
            <div className="form-group">
              <label className="panel-label">Alert Type</label>
              <input value={form.alertType} placeholder="e.g. Host Compromise" onChange={(event) => setForm((current) => ({ ...current, alertType: event.target.value }))} style={{ width: "100%" }} />
            </div>
            <div className="form-group">
              <label className="panel-label">Severity</label>
              <select value={form.severity} onChange={(event) => setForm((current) => ({ ...current, severity: event.target.value }))} style={{ width: "100%" }}>
                <option value="Low">Low</option>
                <option value="Medium">Medium</option>
                <option value="High">High</option>
                <option value="Critical">Critical</option>
              </select>
            </div>
          </div>

          <div style={{ marginBottom: "20px" }}>
            <label className="panel-label">
              Conditions (Logic:
              <select value={form.logic} onChange={(event) => setForm((current) => ({ ...current, logic: event.target.value }))} style={{ marginLeft: "10px", background: "transparent", border: "none", color: "var(--primary)", fontWeight: "bold" }}>
                <option value="AND">AND</option>
                <option value="OR">OR</option>
              </select>
              )
            </label>
            {form.conditions.map((condition, index) => (
              <div key={`${condition.field}-${index}`} className="flex-between" style={{ gap: "10px", marginBottom: "10px", background: "rgba(0,0,0,0.2)", padding: "10px", borderRadius: "8px" }}>
                <select value={condition.field} onChange={(event) => updateCondition(index, "field", event.target.value)} style={{ flex: 1 }}>
                  <option value="message">Message</option>
                  <option value="ip">Source IP</option>
                  <option value="metadata.processName">Process Name</option>
                  <option value="metadata.filePath">File Path</option>
                  <option value="eventType">Event Type</option>
                  <option value="source">Source</option>
                  <option value="metadata.failedAttempts">Failed Attempts</option>
                  <option value="metadata.requestRate">Request Rate</option>
                </select>
                <select value={condition.operator} onChange={(event) => updateCondition(index, "operator", event.target.value)} style={{ flex: 1 }}>
                  <option value="equals">Equals</option>
                  <option value="contains">Contains</option>
                  <option value="greater_than">Greater Than</option>
                  <option value="exists">Exists</option>
                  <option value="in">In</option>
                </select>
                <input value={condition.value} placeholder="Value" onChange={(event) => updateCondition(index, "value", event.target.value)} style={{ flex: 2 }} />
                <button className="btn-ghost" onClick={() => removeCondition(index)} style={{ padding: "5px" }}>x</button>
              </div>
            ))}
            <button className="btn-outline" onClick={addCondition} style={{ fontSize: "0.8rem", padding: "5px 12px" }}>+ Add Condition</button>
          </div>

          <button className="scan-btn" disabled={saving || !form.name.trim()} onClick={handleCreate}>
            {saving ? "Deploying..." : "Deploy Rule"}
          </button>
        </div>
      )}

      <div className="card glass">
        <h3>Active Rulebook</h3>
        <div className="panel-list">
          {ruleList.map((rule) => {
            const conditions = normalizeConditions(rule.conditions);

            return (
              <div key={rule._id} className="list-row list-row--pill" style={{ marginBottom: "12px" }}>
                <div style={{ flex: 1 }}>
                  <div className="flex-between">
                    <strong style={{ fontSize: "1.1rem" }}>{rule.name}</strong>
                    <span
                      style={{
                        padding: "2px 8px",
                        borderRadius: "4px",
                        background: rule.severity === "Critical" ? "var(--error)" : "var(--bg-main)",
                        fontSize: "0.7rem",
                        fontWeight: "bold",
                      }}
                    >
                      {rule.severity}
                    </span>
                  </div>
                  <div className="list-meta" style={{ marginTop: "8px" }}>
                    {conditions.length} conditions ({rule.logic || "AND"}) • {rule.hitCount || 0} hits
                  </div>
                  <div className="mono" style={{ fontSize: "0.75rem", color: "var(--text-dark)", marginTop: "4px" }}>
                    {formatConditionSummary(rule)}
                  </div>
                </div>
                <div style={{ marginLeft: "20px" }}>
                  {isAdmin ? (
                    <button className={rule.enabled ? "btn-outline" : "btn-primary"} onClick={() => handleToggle(rule)} style={{ fontSize: "0.8rem" }}>
                      {rule.enabled ? "Deactivate" : "Activate"}
                    </button>
                  ) : (
                    <span className={`status-pill ${rule.enabled ? "healthy" : "offline"}`}>{rule.enabled ? "Active" : "Disabled"}</span>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </MainLayout>
  );
};

export default Rules;
