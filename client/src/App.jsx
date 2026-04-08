import React, { useState } from "react";

const API_BASE = import.meta.env.VITE_API_BASE || "http://localhost:5174";

const initialState = {
  kode_group: "",
  kode_jenis: "",
  nama_barang: "",
  berat: "",
  nama_atribut: "",
  berat_atribut: ""
};

export default function App() {
  const [activeMenu, setActiveMenu] = useState("input");
  const [theme, setTheme] = useState("dark");
  const [form, setForm] = useState(initialState);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState(null);
  const [decryptResult, setDecryptResult] = useState(null);
  const [items, setItems] = useState([]);
  const [selectedId, setSelectedId] = useState("");
  const [listLoading, setListLoading] = useState(false);
  const [idInput, setIdInput] = useState("");
  const [textEncryptInput, setTextEncryptInput] = useState("");
  const [textEncryptResult, setTextEncryptResult] = useState(null);
  const [textDecryptInput, setTextDecryptInput] = useState({
    combined: ""
  });
  const [textDecryptResult, setTextDecryptResult] = useState(null);

  const copyText = async (value) => {
    try {
      await navigator.clipboard.writeText(value || "");
    } catch (err) {
      setError("Gagal copy ke clipboard.");
    }
  };

  const copyJson = async (value) => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(value || {}, null, 2));
    } catch (err) {
      setError("Gagal copy ke clipboard.");
    }
  };
  const [patchForm, setPatchForm] = useState({
    kode_group: "",
    kode_jenis: "",
    nama_barang: "",
    berat: "",
    nama_atribut: "",
    berat_atribut: ""
  });

  const onChange = (e) => {
    setForm((prev) => ({ ...prev, [e.target.name]: e.target.value }));
  };

  const onSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError("");
    setResult(null);
    try {
      const res = await fetch(`${API_BASE}/api/items`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(form)
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Request failed");
      setResult(data);
      setDecryptResult(null);
    } catch (err) {
      setError(String(err.message || err));
    } finally {
      setLoading(false);
    }
  };

  const onDecrypt = async () => {
    if (!result?.id) return;
    setLoading(true);
    setError("");
    try {
      const res = await fetch(`${API_BASE}/api/items/${result.id}/decrypt`);
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Decrypt failed");
      setDecryptResult(data);
    } catch (err) {
      setError(String(err.message || err));
    } finally {
      setLoading(false);
    }
  };

  const loadList = async () => {
    setListLoading(true);
    setError("");
    try {
      const res = await fetch(`${API_BASE}/api/items?view=plain&limit=50`);
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Load list failed");
      setItems(data);
    } catch (err) {
      setError(String(err.message || err));
    } finally {
      setListLoading(false);
    }
  };

  const loadById = async (docId) => {
    if (!docId) return;
    setLoading(true);
    setError("");
    setDecryptResult(null);
    try {
      const res = await fetch(`${API_BASE}/api/items/${docId}`);
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Load data failed");
      setResult({ id: data._id || docId, stored: data });
    } catch (err) {
      setError(String(err.message || err));
    } finally {
      setLoading(false);
    }
  };

  const onPatchChange = (e) => {
    setPatchForm((prev) => ({ ...prev, [e.target.name]: e.target.value }));
  };

  const onPatch = async (e) => {
    e.preventDefault();
    if (!result?.id) return;
    setLoading(true);
    setError("");
    try {
      const patchPayload = Object.entries(patchForm).reduce((acc, [key, val]) => {
        if (val !== "" && val !== null && val !== undefined) {
          acc[key] = val;
        }
        return acc;
      }, {});
      if (Object.keys(patchPayload).length === 0) {
        throw new Error("Isi minimal 1 field untuk patch.");
      }
      const res = await fetch(`${API_BASE}/api/items/${result.id}`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(patchPayload)
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Patch failed");
      setResult({
        id: result.id,
        stored: data.updated
      });
      setDecryptResult(null);
    } catch (err) {
      setError(String(err.message || err));
    } finally {
      setLoading(false);
    }
  };


  const runTextEncrypt = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError("");
    try {
      const res = await fetch(`${API_BASE}/api/tools/encrypt-text`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text: textEncryptInput })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Encrypt text failed");
      const combined =
        data?.combined ||
        (data?.kem && data?.payload_pqc ? `${data.kem}||${data.payload_pqc}` : "");
      setTextEncryptResult({ ...data, combined });
      if (!combined) {
        setError("Encrypt berhasil, tapi output kosong. Coba ulangi atau restart server.");
      }
    } catch (err) {
      setError(String(err.message || err));
    } finally {
      setLoading(false);
    }
  };

  const runTextDecrypt = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError("");
    try {
      const trimmed = String(textDecryptInput.combined || "").trim();
      const res = await fetch(`${API_BASE}/api/tools/decrypt-text`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ combined: trimmed })
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Decrypt text failed");
      setTextDecryptResult(data);
    } catch (err) {
      setError(String(err.message || err));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className={`layout theme-${theme}`}>
      <aside className="sidebar">
        <div className="brand-row">
          <button
            type="button"
            className="theme-toggle"
            onClick={() => setTheme((prev) => (prev === "dark" ? "light" : "dark"))}
            aria-label="Toggle theme"
            title="Toggle theme"
          >
            {theme === "dark" ? (
              <svg viewBox="0 0 24 24" aria-hidden="true">
                <path
                  fill="currentColor"
                  d="M12 4.5a1 1 0 0 1 1 1v1.2a1 1 0 0 1-2 0V5.5a1 1 0 0 1 1-1zm0 12.3a1 1 0 0 1 1 1v1.2a1 1 0 1 1-2 0v-1.2a1 1 0 0 1 1-1zm7.5-4.3a1 1 0 0 1 1 1 1 1 0 0 1-1 1h-1.2a1 1 0 1 1 0-2h1.2zM6.7 12.5a1 1 0 0 1-1 1H4.5a1 1 0 1 1 0-2h1.2a1 1 0 0 1 1 1zm9.3-4.8a1 1 0 0 1 1.4 0l.9.9a1 1 0 1 1-1.4 1.4l-.9-.9a1 1 0 0 1 0-1.4zM6.1 16.1a1 1 0 0 1 1.4 0l.9.9a1 1 0 1 1-1.4 1.4l-.9-.9a1 1 0 0 1 0-1.4zM16.1 17.9a1 1 0 0 1 1.4-1.4l.9.9a1 1 0 1 1-1.4 1.4l-.9-.9zM6.1 7.5a1 1 0 0 1 1.4-1.4l.9.9A1 1 0 1 1 7 8.4l-.9-.9zM12 8a4 4 0 1 1 0 8 4 4 0 0 1 0-8z"
                />
              </svg>
            ) : (
              <svg viewBox="0 0 24 24" aria-hidden="true">
                <path
                  fill="currentColor"
                  d="M12.8 3.2a1 1 0 0 1 .6 1.3 7.5 7.5 0 0 0 7.1 10.2 1 1 0 0 1 .5 1.9 9 9 0 1 1-8.2-13.4z"
                />
              </svg>
            )}
          </button>
          <div className="brand">PQC Demo</div>
        </div>
        <nav>
          <button
            className={`nav-btn ${activeMenu === "input" ? "active" : ""}`}
            onClick={() => setActiveMenu("input")}
          >
            <svg viewBox="0 0 24 24" aria-hidden="true">
              <path
                fill="currentColor"
                d="M4 5h16a2 2 0 0 1 2 2v10a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V7a2 2 0 0 1 2-2zm8 3a1 1 0 0 0-1 1v2H9a1 1 0 1 0 0 2h2v2a1 1 0 1 0 2 0v-2h2a1 1 0 1 0 0-2h-2V9a1 1 0 0 0-1-1z"
              />
            </svg>
            Input Barang
          </button>
          <button
            className={`nav-btn ${activeMenu === "report" ? "active" : ""}`}
            onClick={() => setActiveMenu("report")}
          >
            <svg viewBox="0 0 24 24" aria-hidden="true">
              <path
                fill="currentColor"
                d="M4 4h16a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2zm0 4v10h16V8H4zm2 2h4v2H6v-2zm0 4h8v2H6v-2z"
              />
            </svg>
            Laporan Input Barang
          </button>
          <button
            className={`nav-btn ${activeMenu === "tools" ? "active" : ""}`}
            onClick={() => setActiveMenu("tools")}
          >
            <svg viewBox="0 0 24 24" aria-hidden="true">
              <path
                fill="currentColor"
                d="M14.7 5.3a1 1 0 0 1 1.4 0l2.6 2.6a1 1 0 0 1 0 1.4l-1.3 1.3 2.3 2.3a3 3 0 0 1 0 4.2l-1.6 1.6a3 3 0 0 1-4.2 0l-2.3-2.3-1.3 1.3a1 1 0 0 1-1.4 0l-2.6-2.6a1 1 0 0 1 0-1.4l1.3-1.3-2.3-2.3a3 3 0 0 1 0-4.2L6.8 4a3 3 0 0 1 4.2 0l2.3 2.3 1.4-1z"
              />
            </svg>
            Tools Encrypt/Decrypt
          </button>
        </nav>
      </aside>

      <main className="page">
        <header className="header">
          <div>
            <h1>Tambah Barang (PQC Demo)</h1>
            <p>Input barang → enkripsi NAGAGOLD + PQC → simpan ke Mongo</p>
          </div>
        </header>

        {activeMenu === "input" && (
          <div className="grid">
            <form className="card" onSubmit={onSubmit}>
              <h2>Form Input</h2>
              <label>
                Kode Group
                <input name="kode_group" value={form.kode_group} onChange={onChange} required />
              </label>
              <label>
                Kode Jenis
                <input name="kode_jenis" value={form.kode_jenis} onChange={onChange} required />
              </label>
              <label>
                Nama Barang
                <input name="nama_barang" value={form.nama_barang} onChange={onChange} required />
              </label>
              <label>
                Berat
                <input name="berat" value={form.berat} onChange={onChange} required />
              </label>
              <label>
                Nama Atribut
                <input name="nama_atribut" value={form.nama_atribut} onChange={onChange} required />
              </label>
              <label>
                Berat Atribut
                <input name="berat_atribut" value={form.berat_atribut} onChange={onChange} required />
              </label>

              <button type="submit" disabled={loading}>
                {loading ? "Menyimpan..." : "Simpan"}
              </button>
              {error && <div className="error">{error}</div>}
              {result?.id && <div className="success">Tersimpan dengan ID: {result.id}</div>}
            </form>
          </div>
        )}

        {activeMenu === "report" && (
          <div className="card">
            <div className="actions">
              <button type="button" onClick={loadList} disabled={listLoading}>
                {listLoading ? "Loading..." : "Load Data"}
              </button>
            </div>
            {error && <div className="error">{error}</div>}
            <div className="table-wrapper">
              <table>
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Created</th>
                    <th>Kode Group</th>
                    <th>Kode Jenis</th>
                    <th>Nama Barang</th>
                    <th>Berat</th>
                    <th>Nama Atribut</th>
                    <th>Berat Atribut</th>
                  </tr>
                </thead>
                <tbody>
                  {items.length === 0 && (
                    <tr>
                      <td colSpan="8">Belum ada data.</td>
                    </tr>
                  )}
                  {items.map((it) => (
                    <tr key={it.id}>
                      <td>{it.id}</td>
                      <td>{it.createdAt || "-"}</td>
                      <td>{it.payload_plain?.kode_group || "-"}</td>
                      <td>{it.payload_plain?.kode_jenis || "-"}</td>
                      <td>{it.payload_plain?.nama_barang || "-"}</td>
                      <td>{it.payload_plain?.berat || "-"}</td>
                      <td>{it.payload_plain?.nama_atribut || "-"}</td>
                      <td>{it.payload_plain?.berat_atribut || "-"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Patch Data menu hidden for now */}

        {activeMenu === "tools" && (
          <div className="tools-layout">
            <div className="tools-row">
            <form className="card" onSubmit={runTextEncrypt}>
              <h2>Encrypt Text Bebas</h2>
              <label>
                Teks Bebas
                  <textarea
                    value={textEncryptInput}
                    onChange={(e) => setTextEncryptInput(e.target.value)}
                  />
                </label>
                <button type="submit" disabled={loading}>Encrypt Text</button>
                {error && <div className="error">{error}</div>}
              </form>

            <div className="card result">
              <h2>Encrypt Text Result</h2>
              {textEncryptResult ? (
                <div className="copy-block">
                  <div className="copy-row">
                    <span>combined (kem||payload_pqc)</span>
                    <button type="button" onClick={() => copyText(textEncryptResult.combined)}>Copy</button>
                  </div>
                  <pre>{textEncryptResult.combined}</pre>
                </div>
              ) : (
                <pre>Belum ada hasil.</pre>
              )}
            </div>
            </div>

            <div className="tools-row">
            <form className="card" onSubmit={runTextDecrypt}>
              <h2>Decrypt Text Bebas</h2>
              <label>
                combined (kem||payload_pqc)
                <textarea
                  value={textDecryptInput.combined}
                  onChange={(e) => setTextDecryptInput((p) => ({ ...p, combined: e.target.value }))}
                />
              </label>
              <button type="submit" disabled={loading}>Decrypt Text</button>
                {error && <div className="error">{error}</div>}
              </form>

            <div className="card result">
              <h2>Decrypt Text Result</h2>
              {textDecryptResult ? (
                <div className="copy-block">
                  <div className="copy-row">
                    <span>payload_plain</span>
                    {typeof textDecryptResult.payload_plain === "string" ? (
                      <button type="button" onClick={() => copyText(textDecryptResult.payload_plain)}>
                        Copy
                      </button>
                    ) : textDecryptResult.payload_plain ? (
                      <button type="button" onClick={() => copyJson(textDecryptResult.payload_plain)}>
                        Copy
                      </button>
                    ) : (
                      <button type="button" onClick={() => copyText(textDecryptResult.text || "")}>
                        Copy
                      </button>
                    )}
                  </div>
                  {textDecryptResult.payload_plain ? (
                    <div className="table-wrapper">
                      {typeof textDecryptResult.payload_plain === "object" &&
                      !Array.isArray(textDecryptResult.payload_plain) ? (
                        <table>
                          <tbody>
                            {Object.entries(textDecryptResult.payload_plain).map(([k, v]) => (
                              <tr key={k}>
                                <th>{k}</th>
                                <td>{String(v)}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      ) : (
                        <pre>{JSON.stringify(textDecryptResult.payload_plain)}</pre>
                      )}
                    </div>
                  ) : (
                    <pre>{textDecryptResult.text || JSON.stringify(textDecryptResult, null, 2)}</pre>
                  )}
                </div>
              ) : (
                <pre>Belum ada hasil.</pre>
              )}
            </div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}
