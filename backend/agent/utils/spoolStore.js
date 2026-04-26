const fs = require("fs");
const path = require("path");

const logger = require("./logger");

const toLines = (events = []) =>
  events.map((event) => JSON.stringify(event)).join("\n");

class SpoolStore {
  constructor(filePath) {
    this.filePath = filePath;
  }

  ensureDirectory() {
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
  }

  load() {
    try {
      if (!fs.existsSync(this.filePath)) {
        return [];
      }

      const content = fs.readFileSync(this.filePath, "utf8");
      return content
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter(Boolean)
        .map((line) => JSON.parse(line));
    } catch (error) {
      logger.warn(`Failed to load spool file ${this.filePath}: ${error.message}`);
      return [];
    }
  }

  persist(events = []) {
    try {
      this.ensureDirectory();

      if (!events.length) {
        if (fs.existsSync(this.filePath)) {
          fs.unlinkSync(this.filePath);
        }
        return;
      }

      const tempPath = `${this.filePath}.tmp`;
      fs.writeFileSync(tempPath, `${toLines(events)}\n`, "utf8");
      fs.renameSync(tempPath, this.filePath);
    } catch (error) {
      logger.warn(`Failed to persist spool file ${this.filePath}: ${error.message}`);
    }
  }
}

module.exports = SpoolStore;
