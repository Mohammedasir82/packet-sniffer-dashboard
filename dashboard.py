from flask import Flask, render_template, jsonify, Response, request
import sqlite3

app = Flask(__name__)
DB_FILE = "packets_old.db"

def query_db(query, args=(), one=False):
    con = sqlite3.connect(DB_FILE)
    con.row_factory = sqlite3.Row
    cur = con.execute(query, args)
    rows = cur.fetchall()
    con.close()
    return rows[0] if one and rows else rows

def build_where_and_args(proto: str | None, src: str | None, dst: str | None):
    clauses, args = [], []
    if proto:
        clauses.append("protocol = ?")
        args.append(proto)
    if src:
        clauses.append("src_ip = ?")
        args.append(src)
    if dst:
        clauses.append("dst_ip = ?")
        args.append(dst)
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    return where, args

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/.well-known/appspecific/com.chrome.devtools.json")
def chrome_probe_fix():
    return {}, 204

@app.route("/api/packets")
def api_packets():
    try:
        proto = request.args.get("proto") or None
        src = request.args.get("src") or None
        dst = request.args.get("dst") or None
        where, args = build_where_and_args(proto, src, dst)
        query = f"""
            SELECT id, timestamp, src_ip, dst_ip, protocol, sport, dport, length
            FROM packets {where}
            ORDER BY id DESC
            LIMIT 100
        """
        rows = query_db(query, args)
        packets = [
            {
                "id": r["id"],
                "timestamp": r["timestamp"],
                "src": r["src_ip"],
                "dst": r["dst_ip"],
                "proto": r["protocol"],
                "sport": r["sport"],
                "dport": r["dport"],
                "length": r["length"],
            }
            for r in rows
        ]
        return jsonify(packets)
    except sqlite3.Error as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/stats")
def api_stats():
    try:
        proto = request.args.get("proto") or None
        src = request.args.get("src") or None
        dst = request.args.get("dst") or None
        where, args = build_where_and_args(proto, src, dst)
        q_proto = f"SELECT protocol, COUNT(*) AS count FROM packets {where} GROUP BY protocol"
        proto_stats = {r["protocol"]: r["count"] for r in query_db(q_proto, args)}
        q_src = f"""
            SELECT src_ip AS src, COUNT(*) AS count
            FROM packets {where}
            GROUP BY src_ip
            ORDER BY count DESC
            LIMIT 10
        """
        top_src = [dict(r) for r in query_db(q_src, args)]
        q_dst = f"""
            SELECT dst_ip AS dst, COUNT(*) AS count
            FROM packets {where}
            GROUP BY dst_ip
            ORDER BY count DESC
            LIMIT 10
        """
        top_dst = [dict(r) for r in query_db(q_dst, args)]
        return jsonify({
            "protocols": proto_stats,
            "top_src": top_src,
            "top_dst": top_dst
        })
    except sqlite3.Error as e:
        return jsonify({"error": str(e)}), 500

@app.route("/export/csv")
def export_csv():
    proto = request.args.get("proto") or None
    src = request.args.get("src") or None
    dst = request.args.get("dst") or None
    where, args = build_where_and_args(proto, src, dst)
    q = f"""
        SELECT id, timestamp, src_ip, dst_ip, protocol, sport, dport, length
        FROM packets {where}
        ORDER BY id DESC
    """
    rows = query_db(q, args)
    def generate():
        yield "id,timestamp,src_ip,dst_ip,protocol,sport,dport,length\n"
        for r in rows:
            yield f'{r["id"]},{r["timestamp"]},{r["src_ip"]},{r["dst_ip"]},{r["protocol"]},{r["sport"]},{r["dport"]},{r["length"]}\n'
    return Response(
        generate(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=packets.csv"}
    )

if __name__ == "__main__":
    app.run(debug=True)
