/* SPDX-License-Identifier: GPL-2.0-or-later */
package org.strongswan.android.evgenium;
import android.content.Context;
import android.os.Build;
import android.util.AtomicFile;
import org.json.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
/** Explicit field allowlist; never uploads raw logs, profiles, keys or tokens. */
public final class DiagnosticReports {
  public static volatile boolean sending;
  public static volatile String progress = "";
  static final String[] COUNTERS = {"sent_bytes", "received_bytes", "enqueued", "sent_packets",
      "received_packets", "queue_drops", "stale_drops", "sequence_gaps", "queue_depth",
      "heartbeat_rtt_ms", "heartbeat_timeouts", "max_queue_ms", "max_write_ms", "write_timeouts",
      "write_ms", "flushes", "reconnects", "udp_receive_buffer", "batch_packets", "max_age_ms",
      "dial_attempts", "connect_ms", "tcp_send_buffer", "tcp_receive_buffer", "started_at"};
  private static final Set<String> PHASES = new HashSet<>(Arrays.asList("start", "connected",
      "health_ok", "health_failed", "failed", "failover", "network_changed", "candidate_failed",
      "flow", "flow_health", "rank", "measurement", "packet", "packet_server", "dns", "baseline", "load", "transfer"));
  private static File file(Context c) {
    return new File(c.getFilesDir(), "support-preview.json");
  }
  public static boolean exists(Context c) {
    return file(c).isFile();
  }
  public static JSONObject preview(Context c) throws Exception {
    try (InputStream in = new AtomicFile(file(c)).openRead()) {
      return new JSONObject(new String(Credentials.read(in, 131072), StandardCharsets.UTF_8));
    }
  }
  static String error(String s) {
    return DiagnosticErrors.classify(s);
  }

  static String path(String s) {
    return Arrays.asList(Engine.IDS).contains(s) ? s : "";
  }
  private static String word(String s) {
    return s.replaceAll("[^A-Za-z0-9 ._()+-]", "_").substring(0, Math.min(64, s.length()));
  }
  private static void metric(JSONObject out, String key, Object v) throws Exception {
    if (v instanceof Number) {
      double n = ((Number) v).doubleValue();
      if (Double.isFinite(n) && n >= 0 && n <= 1e18)
        out.put(key, v);
    }
  }
  private static JSONObject counters(JSONObject source) throws Exception {
    JSONObject out = new JSONObject();
    if (source != null)
      for (String k : COUNTERS) metric(out, k, source.opt(k));
    return out;
  }
  private static JSONObject values(JSONObject source) throws Exception {
    JSONObject out = new JSONObject();
    if (source == null)
      return out;
    for (String k : new String[] {"down", "up", "latency", "connect_ms", "elapsed_ms", "score",
             "losses", "bytes_per_direction", "size", "burst", "sent", "received", "duplicates",
             "reordered", "invalid", "loss_percent", "rtt_p50_ms", "rtt_p95_ms", "rtt_max_ms",
             "jitter_ms", "control_ms", "server_received", "server_replies", "server_duplicates",
             "dns_queries", "dns_success", "dns_timeouts", "dns_total_ms", "tcp_attempts",
             "tcp_success", "tcp_failed", "tcp_pending", "tcp_cancelled", "tcp_p50_ms", "tcp_p95_ms", "tcp_max_ms",
             "down_max_read_ms", "up_max_write_ms", "discord_ms", "down_setup_ms", "down_body_ms",
             "up_setup_ms", "up_write_ms", "up_body_ack_ms", "stage", "flow_size", "flow_client_written", "flow_write_ms", "flow_ack_ms", "flow_server_received", "flow_server_complete", "flow_server_ms", "flow_server_max_read_ms", "flow_result_available", "flow_endpoint"})
      metric(out, k, source.opt(k));
    if (source.optString("flow_id").matches("[a-f0-9]{32}")) out.put("flow_id", source.getString("flow_id"));
    if (source.has("discord"))
      out.put("discord_ok", "ok".equals(source.optString("discord")));
    JSONObject m = source.optJSONObject("metrics");
    if (m != null)
      out.put("metrics", values(m));
    return out;
  }
  public static void prepare(Context context, String outcome) throws Exception {
    prepare(context, outcome, "");
  }
  public static synchronized void prepare(Context context, String outcome, String runId) throws Exception {
    if (sending)
      throw new IOException("report_sending");
    Context c = context.getApplicationContext();
    ArrayDeque<JSONObject> tail = new ArrayDeque<>();
    for (String name : new String[] {"diagnostics.previous.jsonl", "diagnostics.jsonl"}) {
      File f = new File(c.getFilesDir(), name);
      if (!f.isFile() || f.length() > 2 * 1024 * 1024)
        continue;
      try (BufferedReader in = new BufferedReader(
               new InputStreamReader(new FileInputStream(f), StandardCharsets.UTF_8))) {
        String line;
        while ((line = in.readLine()) != null) {
          if (line.length() > 32768)
            continue;
          try {
            JSONObject r = new JSONObject(line);
            if (PHASES.contains(r.optString("phase"))
                && (runId.isEmpty() || runId.equals(r.optString("run_id")))) {
              tail.add(r);
              while (tail.size() > 128) tail.removeFirst();
            }
          } catch (JSONException ignored) {
          }
        }
      }
    }
    JSONArray samples = new JSONArray(), events = new JSONArray();
    for (JSONObject r : tail) {
      String phase = r.optString("phase"), err = error(r.optString("error"));
      if ("rank".equals(phase) && "none".equals(err) && r.optJSONObject("values") != null)
        err = error(r.getJSONObject("values").optString(
            "error", r.getJSONObject("values").optString("warning", "")));
      JSONObject row = new JSONObject()
                           .put("time", Math.max(0, r.optLong("time")) / 1000)
                           .put("phase", phase)
                           .put("path", path(r.optString("route")))
                           .put("network",
                               Arrays.asList("wifi", "cellular").contains(r.optString("network"))
                                   ? r.optString("network")
                                   : "unknown")
                           .put("error", err)
                           .put("screen_on", r.optBoolean("screen_on"))
                           .put("device_idle", r.optBoolean("device_idle"))
                           .put("carrier", counters(r.optJSONObject("carrier")))
                           .put("values", values(r.optJSONObject("values")));
      samples.put(row);
      events.put(new JSONObject()
              .put("time", row.getLong("time"))
              .put("phase",
                  phase.equals("connected")       ? "connected"
                      : phase.equals("rank")      ? "ranking"
                      : phase.equals("health_ok") ? "health"
                      : phase.equals("start")     ? "starting"
                                                  : "checking")
              .put("path", row.getString("path"))
              .put("code", err.equals("none") ? "" : "other")
              .put("active", phase.equals("connected") || phase.equals("health_ok")));
    }
    JSONObject paths = new JSONObject(), rankings = new JSONObject();
    for (String kind : new String[] {"wifi", "cellular"})
      try (InputStream in = c.openFileInput("ranking-" + kind + ".json")) {
        JSONObject rank =
            new JSONObject(new String(Credentials.read(in, 65536), StandardCharsets.UTF_8));
        if (!runId.isEmpty() && !runId.equals(rank.optString("run_id"))) continue;
        JSONArray safe = new JSONArray(), rows = rank.getJSONArray("paths");
        for (int i = 0; i < Math.min(rows.length(), 5); i++) {
          JSONObject r = rows.getJSONObject(i);
          String id = path(r.optString("id"));
          if (id.isEmpty())
            continue;
          JSONObject m = values(r);
          m.put("id", id).put("error", error(r.optString("error", r.optString("warning", ""))));
          safe.put(m);
          JSONObject stats = new JSONObject(), speed = r.optJSONObject("metrics");
          if (speed != null) {
            metric(stats, "download_mbps", speed.opt("down"));
            metric(stats, "upload_mbps", speed.opt("up"));
            metric(stats, "latency_ms", speed.opt("latency"));
          }
          metric(stats, "score", r.opt("score"));
          metric(stats, "losses", r.opt("losses"));
          paths.put(id, stats);
        }
        rankings.put(kind,
            new JSONObject()
                .put("created", Math.max(0, rank.optLong("created")) / 1000)
                .put("paths", safe));
      } catch (Exception ignored) {
      }
    String version =
        c.getPackageManager().getPackageInfo(c.getPackageName(), 0).versionName.split("-", 2)[0];
    String arch = Build.SUPPORTED_ABIS[0].equals("arm64-v8a") ? "aarch64"
        : Build.SUPPORTED_ABIS[0].equals("x86_64")            ? "x86_64"
                                                              : "other";
    JSONObject report = new JSONObject()
                            .put("schema", 1)
                            .put("event", "support_bundle")
                            .put("consent", false)
                            .put("report_id", UUID.randomUUID().toString().replace("-", ""))
                            .put("manager", version)
                            .put("system", "android")
                            .put("architecture", arch)
                            .put("time", System.currentTimeMillis() / 1000)
                            .put("events", events)
                            .put("paths", paths)
                            .put("counters", new JSONObject())
                            .put("state", new JSONObject().put("active", Engine.verified))
                            .put("android",
                                new JSONObject()
                                    .put("sdk", Build.VERSION.SDK_INT)
                                    .put("always_on", Protection.alwaysOn(context))
                                    .put("lockdown", Protection.lockdown(context))
                                    .put("manufacturer", word(Build.MANUFACTURER))
                                    .put("model", word(Build.MODEL))
                                    .put("outcome", outcome)
                                    .put("samples", samples)
                                    .put("rankings", rankings));
    report.put("local_identity", Credentials.profile(c).getString("identity"));
    byte[] data = report.toString().getBytes(StandardCharsets.UTF_8);
    if (data.length > 131072)
      throw new IOException("report_size");
    AtomicFile af = new AtomicFile(file(c));
    FileOutputStream out = af.startWrite();
    try {
      out.write(data);
      af.finishWrite(out);
    } catch (Exception e) {
      af.failWrite(out);
      throw e;
    }
    progress = "Отчёт сохранён.";
  }
  public static boolean pendingUpload(Context c) {
    try {
      JSONObject report = preview(c);
      if (!DiagnosticFlow.sameOwner(Credentials.profile(c).getString("identity"), report.optString("local_identity"))) return false;
      String id = report.getString("report_id");
      android.content.SharedPreferences prefs = c.getSharedPreferences("evgenium-reports", 0);
      return id.equals(prefs.getString("pending", ""))
          && !id.equals(prefs.getString("acknowledged", ""));
    } catch (Exception e) {
      return false;
    }
  }
  public static String summary(Context c) {
    if (Engine.diagnosing)
      return "Проверка идёт…\n" + Engine.status;
    if (sending)
      return "Отправляем отчёт…";
    try {
      JSONObject r = preview(c);
      String saved = c.getSharedPreferences("evgenium-reports", 0).getString("acknowledged", "");
      return (progress.isEmpty()
                     ? (r.getString("report_id").equals(saved)
                               ? "Сервер подтвердил получение отчёта."
                               : pendingUpload(c) ? "Отчёт не отправлен. Повторите отправку."
                                                  : "Сохранён отчёт")
                     : progress)
          + "\n"
          + java.text.DateFormat.getDateTimeInstance().format(new Date(r.getLong("time") * 1000))
          + "\n№ " + r.getString("report_id");
    } catch (Exception e) {
      return progress.isEmpty() ? "Отчётов пока нет." : progress;
    }
  }
  private static JSONObject upload(Context c, String host, JSONObject report) throws Exception {
    byte[] payload = report.toString().getBytes(StandardCharsets.UTF_8);
    if (payload.length > 131072)
      throw new IOException("report_size");
    // Ordinary unprotected socket: an active VPN/kill switch remains authoritative.
    try (java.net.Socket raw = new java.net.Socket();
        SocketDeadline deadline = new SocketDeadline(raw, 20000)) {
      raw.connect(new java.net.InetSocketAddress(host, 8443), 8000);
      raw.setSoTimeout(10000);
      try (javax.net.ssl.SSLSocket tls =
               (javax.net.ssl.SSLSocket) Credentials.tls(c, true).getSocketFactory().createSocket(
                   raw, host, 8443, true)) {
        javax.net.ssl.SSLParameters params = tls.getSSLParameters();
        params.setEndpointIdentificationAlgorithm("HTTPS");
        tls.setSSLParameters(params);
        tls.startHandshake();
        OutputStream out = tls.getOutputStream();
        out.write(("POST /report HTTP/1.0\r\nHost: " + host
            + "\r\nContent-Type: application/json\r\nContent-Length: " + payload.length
            + "\r\nConnection: close\r\n\r\n")
                .getBytes(StandardCharsets.US_ASCII));
        out.write(payload);
        out.flush();
        String reply =
            new String(Credentials.read(tls.getInputStream(), 65536), StandardCharsets.UTF_8);
        int split = reply.indexOf("\r\n\r\n");
        if (split < 0 || !(reply.startsWith("HTTP/1.0 200 ") || reply.startsWith("HTTP/1.1 200 ")))
          throw new IOException("report_http");
        return new JSONObject(reply.substring(split + 4));
      }
    }
  }
  public static synchronized void send(Context context) {
    if (sending || Engine.diagnosing)
      return;
    Context c = context.getApplicationContext();
    final JSONObject r;
    try {
      r = preview(c);
      if (!DiagnosticFlow.sameOwner(Credentials.profile(c).getString("identity"), r.optString("local_identity")))
        throw new IOException("report_owner_changed");
      r.remove("local_identity"); // local binding is never uploaded
      r.put("consent", true);
      if (!c.getSharedPreferences("evgenium-reports", 0)
              .edit()
              .putString("pending", r.getString("report_id"))
              .commit())
        throw new IOException("pending_not_saved");
    } catch (Exception e) {
      progress = "Не удалось подготовить отчёт к отправке. Повторите проверку.";
      return;
    }
    sending = true;
    new Thread(() -> {
      try {
        JSONObject reply = upload(c, Engine.running ? "10.77.0.1" : Credentials.RU, r);
        if (!reply.optBoolean("accepted")
            || !r.getString("report_id").equals(reply.optString("report_id")))
          throw new IOException("ack_mismatch");
        c.getSharedPreferences("evgenium-reports", 0)
            .edit()
            .putString("acknowledged", r.getString("report_id"))
            .remove("pending")
            .apply();
        progress = "Сервер подтвердил получение отчёта.";
      } catch (Exception e) {
        progress = "Не удалось отправить. Отчёт сохранён. Нажмите «Повторить отправку отчёта» "
            + "после восстановления сети.";
      } finally {
        sending = false;
      }
    }, "evgenium-report-send").start();
  }
}
