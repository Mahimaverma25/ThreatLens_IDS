import { useMemo, useState } from "react";
import MainLayout from "../layout/MainLayout";

const initialUsers = [
  {
    id: 1,
    username: "admin",
    email: "admin@threatlens.com",
    role: "Admin",
    status: "Active",
    createdAt: "2026-04-20 10:30:00",
  },
  {
    id: 2,
    username: "analyst",
    email: "analyst@threatlens.com",
    role: "Analyst",
    status: "Active",
    createdAt: "2026-04-21 12:10:00",
  },
  {
    id: 3,
    username: "viewer",
    email: "viewer@threatlens.com",
    role: "Viewer",
    status: "Inactive",
    createdAt: "2026-04-22 09:40:00",
  },
  {
    id: 4,
    username: "security-user",
    email: "user@threatlens.com",
    role: "User",
    status: "Active",
    createdAt: "2026-04-23 14:02:45",
  },
];

const Users = () => {
  const [users, setUsers] = useState(initialUsers);
  const [search, setSearch] = useState("");
  const [status, setStatus] = useState("all");
  const [sortBy, setSortBy] = useState("date");
  const [order, setOrder] = useState("desc");

  const filteredUsers = useMemo(() => {
    let result = [...users];

    if (search.trim()) {
      const keyword = search.toLowerCase();
      result = result.filter(
        (user) =>
          user.username.toLowerCase().includes(keyword) ||
          user.email.toLowerCase().includes(keyword) ||
          user.role.toLowerCase().includes(keyword)
      );
    }

    if (status !== "all") {
      result = result.filter((user) => user.status.toLowerCase() === status);
    }

    result.sort((a, b) => {
      const valueA = sortBy === "name" ? a.username : a.createdAt;
      const valueB = sortBy === "name" ? b.username : b.createdAt;

      if (order === "asc") {
        return valueA.localeCompare(valueB);
      }

      return valueB.localeCompare(valueA);
    });

    return result;
  }, [users, search, status, sortBy, order]);

  const totalUsers = users.length;
  const activeUsers = users.filter((user) => user.status === "Active").length;
  const inactiveUsers = users.filter((user) => user.status === "Inactive").length;
  const registeredToday = 0;

  const clearFilters = () => {
    setSearch("");
    setStatus("all");
    setSortBy("date");
    setOrder("desc");
  };

  const toggleStatus = (id) => {
    setUsers((currentUsers) =>
      currentUsers.map((user) =>
        user.id === id
          ? {
              ...user,
              status: user.status === "Active" ? "Inactive" : "Active",
            }
          : user
      )
    );
  };

  const deleteUser = (id) => {
    const confirmDelete = window.confirm("Are you sure you want to delete this user?");
    if (!confirmDelete) return;

    setUsers((currentUsers) => currentUsers.filter((user) => user.id !== id));
  };

  return (
    <MainLayout>
      <div className="tl-users-page">
        <div className="tl-users-header">
          <div>
            <h2>👥 User Management</h2>
            <p>Manage ThreatLens admins, analysts, viewers, and SOC users.</p>
          </div>

          <button className="tl-create-user-btn" type="button">
            Create User
          </button>
        </div>

        <section className="tl-user-stats-grid">
          <div className="tl-user-stat-card blue">
            <span>👥</span>
            <strong>{totalUsers}</strong>
            <p>Total Users</p>
          </div>

          <div className="tl-user-stat-card green">
            <span>🟢</span>
            <strong>{activeUsers}</strong>
            <p>Active Users</p>
          </div>

          <div className="tl-user-stat-card red">
            <span>🔴</span>
            <strong>{inactiveUsers}</strong>
            <p>Inactive Users</p>
          </div>

          <div className="tl-user-stat-card orange">
            <span>➕</span>
            <strong>{registeredToday}</strong>
            <p>Registered Today</p>
          </div>
        </section>

        <section className="tl-filter-panel">
          <div className="tl-panel-orange-title">Filter and Search</div>

          <div className="tl-filter-body">
            <div className="tl-form-group">
              <label>Search User</label>
              <input
                type="text"
                placeholder="Username, email, or role"
                value={search}
                onChange={(event) => setSearch(event.target.value)}
              />
            </div>

            <div className="tl-form-group">
              <label>Status</label>
              <select value={status} onChange={(event) => setStatus(event.target.value)}>
                <option value="all">All Status</option>
                <option value="active">Active</option>
                <option value="inactive">Inactive</option>
              </select>
            </div>

            <div className="tl-form-group">
              <label>Sort By</label>
              <select value={sortBy} onChange={(event) => setSortBy(event.target.value)}>
                <option value="date">Date</option>
                <option value="name">Username</option>
              </select>
            </div>

            <div className="tl-form-group">
              <label>Order</label>
              <select value={order} onChange={(event) => setOrder(event.target.value)}>
                <option value="desc">Descending</option>
                <option value="asc">Ascending</option>
              </select>
            </div>

            <button className="tl-search-btn" type="button">
              🔍
            </button>
          </div>

          <button className="tl-clear-filter" type="button" onClick={clearFilters}>
            ✕ Clear Filters
          </button>
        </section>

        <section className="tl-users-table-card">
          <div className="tl-table-title">
            <h3>▦ Users List</h3>
            <span>{filteredUsers.length} users found</span>
          </div>

          <div className="tl-users-table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Username</th>
                  <th>Email</th>
                  <th>Role</th>
                  <th>Registration Date</th>
                  <th>Status</th>
                  <th>Actions</th>
                </tr>
              </thead>

              <tbody>
                {filteredUsers.map((user) => (
                  <tr key={user.id}>
                    <td>#{user.id}</td>
                    <td>
                      <div className="tl-user-name">
                        <span>{user.username.charAt(0).toUpperCase()}</span>
                        {user.username}
                      </div>
                    </td>
                    <td>{user.email}</td>
                    <td>{user.role}</td>
                    <td>{user.createdAt}</td>
                    <td>
                      <span
                        className={`tl-user-status ${
                          user.status === "Active" ? "active" : "inactive"
                        }`}
                      >
                        {user.status}
                      </span>
                    </td>
                    <td>
                      <div className="tl-user-actions">
                        <button type="button" onClick={() => toggleStatus(user.id)}>
                          {user.status === "Active" ? "Pause" : "Enable"}
                        </button>
                        <button type="button" onClick={() => deleteUser(user.id)}>
                          Delete
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}

                {filteredUsers.length === 0 && (
                  <tr>
                    <td colSpan="7" className="tl-empty-users">
                      No users found.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </section>
      </div>
    </MainLayout>
  );
};

export default Users;