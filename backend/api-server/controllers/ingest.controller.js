/**
 * Ingest Controller
 * Handles incoming events from ThreatLens agents
 * Stores raw events, queues for processing
 */

const { v4: uuidv4 } = require("uuid");
const Event = require("../models/Event");
const AuditLog = require("../models/AuditLog");

/**
 * POST /api/ingest/v1/ingest
 */
const ingestEvents = async (req, res) => {
  const { events } = req.body;

  // FIX: use req.org (set by middleware)
  const orgId = req.org?._id;
  const assetId = req.assetId;

  if (!orgId) {
    return res.status(400).json({ error: "Organization context missing" });
  }

  const batchId = uuidv4();

  try {
    const enrichedEvents = events.map((event) => ({
      ...event,
      _org_id: orgId,
      _asset_id: assetId,
      _batch_id: batchId,
      _ingested_at: new Date(),
    }));

    await Event.insertMany(enrichedEvents, { ordered: false });

    console.log(
      `[Ingest] Batch ${batchId}: Accepted ${events.length} events`
    );

    await AuditLog.create({
      _org_id: orgId,
      action: "ingest_batch_received",
      metadata: {
        batch_id: batchId,
        event_count: events.length,
        asset_id: assetId,
      },
      success: true,
      ip: req.ip,
    });

    res.status(202).json({
      status: "accepted",
      batch_id: batchId,
      events_accepted: events.length,
      events_rejected: 0,
    });

  } catch (err) {
    console.error("[Ingest Error]", err);

    await AuditLog.create({
      _org_id: orgId,
      action: "ingest_batch_failed",
      metadata: {
        error: err.message,
        event_count: events?.length || 0,
      },
      success: false,
      ip: req.ip,
    });

    res.status(500).json({
      error: "Ingestion failed",
      details: err.message,
    });
  }
};

const healthCheck = (req, res) => {
  res.json({
    status: "ok",
    timestamp: new Date().toISOString(),
    service: "ingest-api",
  });
};

const getIngestStats = async (req, res) => {
  const orgId = req.org?._id;

  try {
    const eventCount = await Event.countDocuments({ _org_id: orgId });
    const unprocessedCount = await Event.countDocuments({
      _org_id: orgId,
      _processed: false,
    });

    res.json({
      total_events: eventCount,
      unprocessed_events: unprocessedCount,
      org_id: orgId,
    });

  } catch (err) {
    res.status(500).json({ error: "Failed to fetch stats" });
  }
};

module.exports = {
  ingestEvents,
  healthCheck,
  getIngestStats,
};