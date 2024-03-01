package grafana

const (
	// RoleViewer represents the 'Viewer' role in Grafana, typically with read-only access.
	RoleViewer = "Viewer"

	// RoleEditor represents the 'Editor' role in Grafana, allowing for data modification.
	RoleEditor = "Editor"

	// RoleAdmin represents the 'Admin' role in Grafana, with access to all aspects of a project or dashboard.
	RoleAdmin = "Admin"

	// RoleGrafanaAdmin represents the 'GrafanaAdmin' role, indicating full administrative access to the entire Grafana instance.
	RoleGrafanaAdmin = "GrafanaAdmin"
)
