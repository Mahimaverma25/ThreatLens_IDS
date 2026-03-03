# real architecture

Network Traffic (simulated)
        ↓
Packet Analyzer (Backend)
        ↓
Detection Rules / ML
        ↓
MongoDB (Logs + Alerts)
        ↓
REST API / WebSocket
        ↓
React Dashboard (Real-time UI)

# Frontend tech

| Purpose           | Technology                      |
| ----------------- | ------------------------------- |
| UI                | React.js                        |
| Language          | JavaScript                      |
| Styling           | CSS / Tailwind / MUI (optional) |
| Data Fetching     | Axios                           |
| Real-time (later) | WebSockets / Socket.IO          |


# Backend tech

| Purpose           | Technology                |
| ----------------- | ------------------------- |
| Server            | Node.js                   |
| Framework         | Express.js                |
| API Type          | REST API                  |
| Real-time (later) | Socket.IO                 |
| Security Logic    | Custom JS + ML (optional) |


# database tech

| Purpose     | Technology                    |
| ----------- | ----------------------------- |
| Database    | MongoDB                       |
| ODM         | Mongoose                      |
| Data Stored | Alerts, Logs, Traffic Records |
