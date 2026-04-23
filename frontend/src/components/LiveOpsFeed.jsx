import React from 'react';

const LiveOpsFeed = ({ events }) => {
  return (
    <div className="dashboard-panel glass animate-in">
      <div className="panel-header">
        <h3>Live Operations Feed</h3>
        <span className="pulse status-dot status-online"></span>
      </div>
      <div className="panel-list mono" style={{ maxHeight: '400px', overflowY: 'auto', fontSize: '0.85rem' }}>
        {events.length > 0 ? (
          events.map((event, index) => (
            <div key={event.id || index} className="list-row list-row--pill" style={{ marginBottom: '8px', borderLeft: '2px solid var(--primary)' }}>
              <div style={{ flex: 1 }}>
                <div className="flex-between">
                  <strong style={{ color: 'var(--primary)' }}>{event.label}</strong>
                  <span style={{ color: 'var(--text-dark)', fontSize: '0.75rem' }}>
                    {new Date(event.timestamp).toLocaleTimeString()}
                  </span>
                </div>
                <div style={{ color: 'var(--text-dim)', marginTop: '4px' }}>{event.meta}</div>
              </div>
            </div>
          ))
        ) : (
          <div className="list-row" style={{ color: 'var(--text-dark)', textAlign: 'center' }}>
            Waiting for telemetry...
          </div>
        )}
      </div>
      <div className="panel-footnote">
        Real-time subscription active. Events are pushed via Socket.IO.
      </div>
    </div>
  );
};

export default LiveOpsFeed;
