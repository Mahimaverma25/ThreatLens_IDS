const Asset = require("../models/Asset");
const AuditLog = require("../models/AuditLog");
const { v4: uuidv4 } = require("uuid");

/**
 * Create new asset to monitor
 * POST /api/assets
 * Body: { asset_name, asset_type, asset_criticality, hostname, ip_address }
 */
const createAsset = async (req, res) => {
  try {
    const {
      asset_name,
      asset_type,
      asset_criticality,
      hostname,
      ip_address,
      host_platform,
      telemetry_types,
    } = req.body;

    if (!asset_name || !asset_type) {
      return res.status(400).json({ message: "asset_name and asset_type are required" });
    }

    // Generate unique asset_id
    const asset_id = `asset-${uuidv4().slice(0, 8)}`;

    const asset = await Asset.create({
      asset_id,
      asset_name,
      asset_type,
      asset_criticality: asset_criticality || "medium",
      hostname: hostname || asset_name,
      ip_address: ip_address || null,
      host_platform: host_platform || "",
      telemetry_types: Array.isArray(telemetry_types) ? telemetry_types : [],
      _org_id: req.orgId,
      status: "active",
      agent_status: "offline",
      baseline: {
        avg_requests_per_minute: 0,
        avg_errors_per_minute: 0,
        typical_users: [],
        typical_geographies: [],
        working_hours: {
          days: [],
          start_hour: 0,
          end_hour: 23,
          timezone: "UTC"
        }
      },
      suppression_rules: []
    });

    // Audit log
    await AuditLog.create({
      action: "asset.create",
      userId: req.user.sub,
      _org_id: req.orgId,
      ip: req.ip,
      success: true,
      metadata: {
        asset_id: asset._id.toString(),
        asset_name,
        asset_type
      }
    });

    return res.status(201).json({
      message: "Asset created successfully",
      asset: {
        _id: asset._id,
        asset_id: asset.asset_id,
        asset_name: asset.asset_name,
        asset_type: asset.asset_type,
        hostname: asset.hostname,
        ip_address: asset.ip_address,
        asset_status: asset.status,
        agent_status: asset.agent_status,
        host_platform: asset.host_platform,
        telemetry_types: asset.telemetry_types || [],
        created_at: asset.created_at
      }
    });
  } catch (error) {
    console.error("CREATE ASSET ERROR:", error);
    return res.status(500).json({ message: "Failed to create asset" });
  }
};

/**
 * List all assets for organization
 * GET /api/assets
 */
const listAssets = async (req, res) => {
  try {
    const { status, agent_status } = req.query;
    const filters = { _org_id: req.orgId };

    if (status) filters.status = status;
    if (agent_status) filters.agent_status = agent_status;

    const assets = await Asset.find(filters)
      .select("-baseline -suppression_rules") // Exclude detailed data for list
      .sort({ created_at: -1 });

    return res.json({
      data: assets.map(asset => ({
        _id: asset._id,
        asset_id: asset.asset_id,
        asset_name: asset.asset_name,
        asset_type: asset.asset_type,
        asset_criticality: asset.asset_criticality,
        hostname: asset.hostname,
        ip_address: asset.ip_address,
        asset_status: asset.status,
        agent_status: asset.agent_status,
        host_platform: asset.host_platform,
        telemetry_types: asset.telemetry_types || [],
        last_activity: asset.agent_last_seen,
        created_at: asset.created_at
      })),
      total: assets.length
    });
  } catch (error) {
    console.error("LIST ASSETS ERROR:", error);
    return res.status(500).json({ message: "Failed to fetch assets" });
  }
};

/**
 * Get asset details (including baseline and suppression rules)
 * GET /api/assets/:id
 */
const getAsset = async (req, res) => {
  try {
    const { id } = req.params;

    const asset = await Asset.findOne({
      _id: id,
      _org_id: req.orgId
    });

    if (!asset) {
      return res.status(404).json({ message: "Asset not found" });
    }

    return res.json({
      _id: asset._id,
      asset_id: asset.asset_id,
      asset_name: asset.asset_name,
      asset_type: asset.asset_type,
      asset_criticality: asset.asset_criticality,
      hostname: asset.hostname,
      ip_address: asset.ip_address,
      asset_status: asset.status,
      agent_status: asset.agent_status,
      host_platform: asset.host_platform,
      telemetry_types: asset.telemetry_types || [],
      baseline: asset.baseline,
      suppression_rules: asset.suppression_rules,
      last_activity: asset.agent_last_seen,
      created_at: asset.created_at
    });
  } catch (error) {
    console.error("GET ASSET ERROR:", error);
    return res.status(500).json({ message: "Failed to fetch asset" });
  }
};

/**
 * Update asset metadata
 * PATCH /api/assets/:id
 * Body: { asset_name, asset_criticality, hostname, ip_address, asset_status }
 */
const updateAsset = async (req, res) => {
  try {
    const { id } = req.params;
    const {
      asset_name,
      asset_criticality,
      hostname,
      ip_address,
      asset_status,
      status,
      host_platform,
      telemetry_types,
    } = req.body;

    const updates = {};
    if (asset_name) updates.asset_name = asset_name;
    if (asset_criticality) updates.asset_criticality = asset_criticality;
    if (hostname) updates.hostname = hostname;
    if (ip_address !== undefined) updates.ip_address = ip_address;
    if (asset_status) updates.status = asset_status;
    if (status) updates.status = status;
    if (host_platform !== undefined) updates.host_platform = host_platform;
    if (telemetry_types !== undefined) updates.telemetry_types = telemetry_types;

    const asset = await Asset.findOneAndUpdate(
      { _id: id, _org_id: req.orgId },
      { $set: updates },
      { new: true }
    );

    if (!asset) {
      return res.status(404).json({ message: "Asset not found" });
    }

    // Audit log
    await AuditLog.create({
      action: "asset.update",
      userId: req.user.sub,
      _org_id: req.orgId,
      ip: req.ip,
      success: true,
      metadata: {
        asset_id: asset._id.toString(),
        asset_name: asset.asset_name,
        changes: Object.keys(updates)
      }
    });

    return res.json({
      message: "Asset updated successfully",
      asset: {
        _id: asset._id,
        asset_id: asset.asset_id,
        asset_name: asset.asset_name,
        asset_type: asset.asset_type,
        hostname: asset.hostname,
        ip_address: asset.ip_address,
        asset_status: asset.status,
        agent_status: asset.agent_status,
        host_platform: asset.host_platform,
        telemetry_types: asset.telemetry_types || []
      }
    });
  } catch (error) {
    console.error("UPDATE ASSET ERROR:", error);
    return res.status(500).json({ message: "Failed to update asset" });
  }
};

/**
 * Delete asset
 * DELETE /api/assets/:id
 */
const deleteAsset = async (req, res) => {
  try {
    const { id } = req.params;

    const asset = await Asset.findOneAndDelete({
      _id: id,
      _org_id: req.orgId
    });

    if (!asset) {
      return res.status(404).json({ message: "Asset not found" });
    }

    // Audit log
    await AuditLog.create({
      action: "asset.delete",
      userId: req.user.sub,
      _org_id: req.orgId,
      ip: req.ip,
      success: true,
      metadata: {
        asset_id: asset._id.toString(),
        asset_name: asset.asset_name
      }
    });

    return res.json({
      message: "Asset deleted successfully",
      asset_id: asset.asset_id,
      asset_name: asset.asset_name
    });
  } catch (error) {
    console.error("DELETE ASSET ERROR:", error);
    return res.status(500).json({ message: "Failed to delete asset" });
  }
};

/**
 * Add suppression rule to asset
 * POST /api/assets/:id/suppression-rules
 * Body: { rule_type, condition, reason }
 */
const addSuppressionRule = async (req, res) => {
  try {
    const { id } = req.params;
    const { rule_type, condition, reason } = req.body;

    if (!rule_type || !condition) {
      return res.status(400).json({ message: "rule_type and condition are required" });
    }

    const asset = await Asset.findOneAndUpdate(
      { _id: id, _org_id: req.orgId },
      {
        $push: {
          suppression_rules: {
            _id: uuidv4(),
            rule_type,
            condition,
            reason: reason || ""
          }
        }
      },
      { new: true }
    );

    if (!asset) {
      return res.status(404).json({ message: "Asset not found" });
    }

    return res.json({
      message: "Suppression rule added successfully",
      suppression_rules: asset.suppression_rules
    });
  } catch (error) {
    console.error("ADD SUPPRESSION RULE ERROR:", error);
    return res.status(500).json({ message: "Failed to add suppression rule" });
  }
};

/**
 * Remove suppression rule from asset
 * DELETE /api/assets/:id/suppression-rules/:rule_id
 */
const removeSuppressionRule = async (req, res) => {
  try {
    const { id, rule_id } = req.params;

    const asset = await Asset.findOneAndUpdate(
      { _id: id, _org_id: req.orgId },
      { $pull: { suppression_rules: { _id: rule_id } } },
      { new: true }
    );

    if (!asset) {
      return res.status(404).json({ message: "Asset not found" });
    }

    return res.json({
      message: "Suppression rule removed successfully",
      suppression_rules: asset.suppression_rules
    });
  } catch (error) {
    console.error("REMOVE SUPPRESSION RULE ERROR:", error);
    return res.status(500).json({ message: "Failed to remove suppression rule" });
  }
};

module.exports = {
  createAsset,
  listAssets,
  getAsset,
  updateAsset,
  deleteAsset,
  addSuppressionRule,
  removeSuppressionRule
};
