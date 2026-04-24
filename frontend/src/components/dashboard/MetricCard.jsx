const MetricCard = ({ title, value, subtitle, tone = "cyan" }) => (
  <div className={`tl-soc-metric tl-soc-metric--${tone}`}>
    <div className="tl-soc-metric__header">
      <span>{title}</span>
    </div>
    <strong>{value}</strong>
    <small>{subtitle}</small>
  </div>
);

export default MetricCard;
