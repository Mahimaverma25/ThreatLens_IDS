const TONE_CLASS = {
  healthy: "tl-soc-badge--healthy",
  green: "tl-soc-badge--healthy",
  critical: "tl-soc-badge--critical",
  red: "tl-soc-badge--critical",
  warning: "tl-soc-badge--warning",
  amber: "tl-soc-badge--warning",
  cyan: "tl-soc-badge--cyan",
  blue: "tl-soc-badge--cyan",
};

const StatusBadge = ({ label, tone = "cyan", pulse = false, compact = false, className = "" }) => (
  <span
    className={[
      "tl-soc-badge",
      TONE_CLASS[tone] || "tl-soc-badge--cyan",
      pulse ? "tl-soc-badge--pulse" : "",
      compact ? "tl-soc-badge--compact" : "",
      className,
    ]
      .filter(Boolean)
      .join(" ")}
  >
    <span className="tl-soc-badge__dot" />
    {label}
  </span>
);

export default StatusBadge;
