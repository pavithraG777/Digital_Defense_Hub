import { useEffect, useState } from "react";
import { api } from "../lib/api";

interface ModulePageProps {
  title: string;
  description: string;
  path: string;
  emptyMessage?: string;
}

export function ModulesPage({ title, description, path, emptyMessage }: ModulePageProps) {
  const [items, setItems] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function load() {
      try {
        const response = await api.get<unknown>(path);
        if (Array.isArray(response)) {
          setItems(response);
        } else if (response && typeof response === "object" && "data" in response && Array.isArray((response as { data?: unknown }).data)) {
          setItems((response as { data: unknown[] }).data);
        } else {
          setItems([]);
        }
      } catch {
        setItems([]);
      } finally {
        setLoading(false);
      }
    }
    load();
  }, [path]);

  return (
    <div className="page">
      <div className="hero">
        <div>
          <h1>{title}</h1>
          <p>{description}</p>
        </div>
        <span className="badge">Backend-backed</span>
      </div>
      {loading ? <p>Loading records…</p> : items.length === 0 ? <p>{emptyMessage || "No records available yet."}</p> : (
        <table className="table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Status</th>
              <th>Details</th>
            </tr>
          </thead>
          <tbody>
            {items.map((item, index) => (
              <tr key={item.id || `${title}-${index}`}>
                <td>{item.name || item.username || item.title || item.display_name || item.id}</td>
                <td>{item.status || item.account_status || item.severity || item.user_type || "—"}</td>
                <td>{item.description || item.official_email || item.assignee || item.created_at || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
