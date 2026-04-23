const { upsertIncidentFromAlert, syncOpenIncidentsForOrganization } = require("./incident.service");
const { upsertCorrelatedAlert } = require("./alert.service");

module.exports = {
  upsertIncidentFromAlert,
  syncOpenIncidentsForOrganization,
  upsertCorrelatedAlert,
};
