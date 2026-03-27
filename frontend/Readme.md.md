
# ThreatLens Architecture & Tech Stack

## Architecture Overview

Network Traffic (simulated)
        ↓
Packet Analyzer (Backend)
        ↓
Detection Rules / ML (Python IDS Engine)
        ↓
MongoDB (Logs + Alerts)
        ↓
REST API / WebSocket (Node.js Backend)
        ↓
React Dashboard (Real-time UI)

## Frontend Tech
| Purpose           | Technology                      |
| ----------------- | ------------------------------- |
| UI                | React.js                        |
| Language          | JavaScript                      |
| Styling           | CSS / Tailwind / MUI (optional) |
| Data Fetching     | Axios                           |
| Real-time         | WebSockets / Socket.IO          |

## Backend Tech
| Purpose           | Technology                |
| ----------------- | ------------------------- |
| Server            | Node.js                   |
| Framework         | Express.js                |
| API Type          | REST API                  |
| Real-time         | Socket.IO                 |
| Security Logic    | Custom JS + ML (optional) |

## Database Tech
| Purpose     | Technology                    |
| ----------- | ----------------------------- |
| Database    | MongoDB                       |
| ODM         | Mongoose                      |
| Data Stored | Alerts, Logs, Traffic Records |

## Integration Notes
- The backend Node.js API connects to the Python IDS engine for detection.
- The frontend React dashboard communicates with the backend via REST and WebSocket.
- The agent collects and forwards logs/events to the backend for analysis.
