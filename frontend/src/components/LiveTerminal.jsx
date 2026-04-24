import React, { useEffect, useRef } from 'react';

const LiveTerminal = ({ logs }) => {
  const terminalRef = useRef(null);

  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [logs]);

  return (
    <div className="dashboard-panel glass animate-in" style={{ background: '#000', border: '1px solid #333' }}>
      <div className="panel-header" style={{ borderBottom: '1px solid #222', paddingBottom: '8px' }}>
        <h3 style={{ color: '#00ff00', fontFamily: 'monospace' }}>TELEMETRY_STREAM:/$ tail -f /var/log/threatlens.log</h3>
      </div>
      <div 
        ref={terminalRef}
        style={{ 
          height: '300px', 
          overflowY: 'auto', 
          fontFamily: 'JetBrains Mono, monospace', 
          fontSize: '0.75rem', 
          color: '#00ff00',
          padding: '12px',
          lineHeight: '1.4'
        }}
      >
        {logs.length > 0 ? (
          logs.map((log, index) => (
            <div key={index} style={{ marginBottom: '4px' }}>
              <span style={{ color: '#888' }}>[{new Date(log.timestamp).toLocaleTimeString()}]</span>{' '}
              <span style={{ color: '#00d4ff' }}>{log.source?.toUpperCase()}</span>:{' '}
              {log.message}
            </div>
          ))
        ) : (
          <div className="pulse">System initialized. Waiting for telemetry data...</div>
        )}
      </div>
    </div>
  );
};

export default LiveTerminal;