/* SPDX-License-Identifier: GPL-2.0-or-later */
package org.strongswan.android.evgenium;
import android.app.*;
import android.content.*;
import android.net.*;
import android.os.*;
import android.util.Log;
import org.json.*;
import org.strongswan.android.data.*;
import org.strongswan.android.logic.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.*;
import javax.net.ssl.HttpsURLConnection;

/**
 * Single owner of connection orchestration; UI only sends commands and
 * displays state.
 */
public class Engine extends Service {
  public static final String[] IDS = {"ru-udp", "ee-udp", "ee-tls", "ee-evgt", "ee-evgt-ru"};
  public static final String[] LABELS = {"HSVDS → Эстония", "Эстония · UDP", "Эстония · TLS",
      "Эстония · EvgeniumTunnel", "EvgeniumTunnel · HSVDS → Эстония"};
  public static volatile String status = "Не подключено";
  public static volatile String current = "";
  public static volatile boolean running, verified, diagnosing;
  private static volatile Engine instance;
  public static boolean working() {
    Engine e = instance;
    return e != null && e.busy;
  }
  private volatile VpnStateService vpn;
  private volatile boolean cancel;
  private final ExecutorService worker = Executors.newSingleThreadExecutor();
  private final Handler handler = new Handler(Looper.getMainLooper());
  private Network connectedNetwork;
  private Network operationNetwork;
  private String operationKind = "unknown";
  private volatile long generation;
  private int consecutive;
  private long nextHealthAt;
  private android.os.PowerManager.WakeLock labWake;
  private volatile boolean busy;
  private volatile boolean exhausted;
  private final ServiceConnection connection = new ServiceConnection() {
    public void onServiceConnected(ComponentName n, IBinder b) {
      vpn = ((VpnStateService.LocalBinder) b).getService();
    }
    public void onServiceDisconnected(ComponentName n) {
      vpn = null;
    }
  };
  @Override
  public void onCreate() {
    super.onCreate();
    instance = this;
    bindService(new Intent(this, VpnStateService.class), connection, BIND_AUTO_CREATE);
    NotificationManager nm = getSystemService(NotificationManager.class);
    nm.createNotificationChannel(new NotificationChannel(
        "evgenium-engine", "Evgenium · подключение", NotificationManager.IMPORTANCE_LOW));
    PendingIntent pi = PendingIntent.getActivity(
        this, 0, new Intent(this, HomeActivity.class), PendingIntent.FLAG_IMMUTABLE);
    startForeground(200,
        new Notification.Builder(this, "evgenium-engine")
            .setSmallIcon(android.R.drawable.stat_sys_upload)
            .setContentTitle("Evgenium Network · тестовая версия")
            .setContentText("Управление защищённым подключением")
            .setContentIntent(pi)
            .setOngoing(true)
            .build());
  }
  @Override
  public IBinder onBind(Intent i) {
    return null;
  }
  @Override
  public int onStartCommand(Intent i, int f, int id) {
    if (i == null) {
      if (!getSharedPreferences("evgenium", 0).getBoolean("connection-wanted", false)) {
        stopSelf(); return START_NOT_STICKY;
      }
      i = new Intent().putExtra("command", "connect").putExtra("route",
          getSharedPreferences("evgenium", 0).getInt("wanted-route", -1));
    }
    if ((getApplicationInfo().flags & android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0) {
      if (getSharedPreferences("evgenium", 0).getBoolean("lab-wake", false)) {
        if (labWake == null) {
          labWake =
              getSystemService(android.os.PowerManager.class)
                  .newWakeLock(android.os.PowerManager.PARTIAL_WAKE_LOCK, "Evgenium:lab-transfer");
          labWake.setReferenceCounted(false);
        }
        labWake.acquire(300000);
      } else if (labWake != null && labWake.isHeld())
        labWake.release();
    }
    String cmd = i.getStringExtra("command");
    int route = i.getIntExtra("route", -1);
    if ("stop".equals(cmd)) {
      getSharedPreferences("evgenium", 0).edit().putBoolean("connection-wanted", false).commit();
      running = false;
      verified = false;
      cancel = true;
      generation++;
      handler.removeCallbacksAndMessages(null);
      startService(
          new Intent(this, CharonVpnService.class).setAction(CharonVpnService.DISCONNECT_ACTION));
      current = "";
      status = "Отключено";
      stopForeground(STOP_FOREGROUND_REMOVE);
      stopSelf();
      return START_NOT_STICKY;
    }
    if (busy) {
      set("Проверка уже идёт. Для отмены нажмите «Отключить».");
      return START_STICKY;
    }
    getSharedPreferences("evgenium", 0).edit().putBoolean("connection-wanted", true)
        .putInt("wanted-route", route).commit();
    running = true;
    if (!"measure".equals(cmd))
      verified = false;
    diagnosing = DiagnosticFlow.isDiagnostic(cmd);
    busy = true;
    cancel = false;
    exhausted = false;
    consecutive = 0;
    long mine = ++generation;
    worker.execute(() -> {
      try {
        beginNetwork();
        if ("measure".equals(cmd)
            && (getApplicationInfo().flags & android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE)
                != 0) {
          checkNetwork();
          if (!Credentials.EE.equals(ExitProbe.get(this)))
            throw new IOException("unexpected_exit");
          JSONObject m = measure();
          checkNetwork();
          record
          ("measurement", current, m, "");
          set("Замер завершён: " + label(current));
        } else if ("rank".equals(cmd) || DiagnosticFlow.isDiagnostic(cmd)
            || (route < 0 && !hasRanking()))
          rank();
        else if (route >= 0)
          connectRoute(route);
        else
          connectRanked(best());
      } catch (NetworkChanged e) {
        verified = false;
        connectedNetwork = null;
        set("Сеть изменилась. Ожидаю подключение…");
      } catch (Exception e) {
        verified = false;
        if (!cancel)
          set("Ошибка: " + safe(e));
        record
        ("failed", current, new JSONObject(), safe(e));
      } finally {
        if (DiagnosticFlow.isDiagnostic(cmd)) {
          diagnosing = false;
          try {
            DiagnosticFlow.finish(cmd,
                ()
                    -> DiagnosticReports.prepare(this,
                        cancel         ? "cancelled"
                            : verified ? "completed"
                                       : "incomplete"),
                () -> !cancel && mine == generation, () -> DiagnosticReports.send(this));
          } catch (Exception reportError) {
            DiagnosticReports.progress = "Не удалось сохранить отчёт. Повторите проверку.";
          }
        }
        busy = false;
        if (!cancel && mine == generation) {
          nextHealthAt = SystemClock.elapsedRealtime() + 15000;
          handler.postDelayed(() -> monitorTick(mine), 1000);
        }
      }
    });
    return START_STICKY;
  }
  private void monitorTick(long mine) {
    if (cancel || exhausted || mine != generation)
      return;
    if (!busy
        && (SystemClock.elapsedRealtime() >= nextHealthAt
            || TunnelCarrier.offlineMillis() >= 3000)) {
      monitor(mine);
    } else
      handler.postDelayed(() -> monitorTick(mine), 1000);
  }
  private void monitor(long mine) {
    if (cancel || exhausted || mine != generation)
      return;
    if (busy) {
      handler.postDelayed(() -> monitorTick(mine), 1000);
      return;
    }
    busy = true;
    worker.execute(() -> {
      try {
        beginNetwork();
        if (!operationNetwork.equals(connectedNetwork)) {
          consecutive = 0;
          record
          ("network_changed", current, new JSONObject(), "");
          if (hasRanking())
            connectRanked(best());
          else
            rank();
          return;
        }
        if (TunnelCarrier.offlineMillis() >= 3000)
          throw new IOException("carrier_unavailable");
        if (vpn != null && vpn.getState() == VpnStateService.State.CONNECTED
            && Credentials.EE.equals(ExitProbe.get(this))) {
          checkNetwork();
          Credentials.ensureFresh(this);
          consecutive = 0;
          record
          ("health_ok", current, new JSONObject(), "");
          if (cancel || instance != this)
            throw new InterruptedException();
          verified = true;
          set("Подключено: " + label(current));
          return;
        }
        throw new IOException("health_failed");
      } catch (Exception e) {
        if (cancel || !sameNetwork()) {
          verified = false;
          connectedNetwork = null;
          consecutive = 0;
          set("Ожидаю доступную сеть");
          return;
        }
        verified = false;
        record
        ("health_failed", current, new JSONObject(), safe(e));
        if (++consecutive >= 2 || TunnelCarrier.offlineMillis() >= 3000) {
          consecutive = 0;
          try {
            lose(current);
            int next = next(current);
            record
            ("failover", current, new JSONObject(), safe(e));
            if (next >= 0)
              connectRanked(next);
            else
              noRoutes();
          } catch (Exception fail) {
            set("Восстановление: " + safe(fail));
          }
        }
      } finally {
        busy = false;
        if (!cancel && mine == generation) {
          nextHealthAt = SystemClock.elapsedRealtime() + (consecutive > 0 ? 3000 : 15000);
          handler.postDelayed(() -> monitorTick(mine), 1000);
        }
      }
    });
  }
  private void set(String s) {
    status = s;
    Log.i("Evgenium", s);
  }
  private static String label(String id) {
    for (int i = 0; i < IDS.length; i++)
      if (IDS[i].equals(id))
        return LABELS[i];
    return id;
  }
  private void connectRoute(int route) throws Exception {
    verified = false;
    if (cancel)
      throw new InterruptedException();
    checkNetwork();
    if (route < 0 || route >= IDS.length)
      throw new IOException("no_available_route");
    Credentials.ensureFresh(this);
    JSONObject credentials = Credentials.profile(this);
    Credentials.certificate(this).checkValidity();
    VpnProfileSource src = new VpnProfileSource(this);
    src.open();
    UUID uuid =
        UUID.nameUUIDFromBytes(("evgenium-android-" + IDS[route]).getBytes(StandardCharsets.UTF_8));
    try {
      VpnProfile p = src.getVpnProfile(uuid.toString());
      boolean exists = p != null;
      if (!exists) {
        p = new VpnProfile();
        p.setUUID(uuid);
      }
      p.setName(LABELS[route]);
      p.setVpnType(VpnType.IKEV2_EAP_TLS);
      p.setGateway(route == 0 ? Credentials.RU : route == 1 ? Credentials.EE : "127.0.0.1");
      int directPort = 443;
      if ((getApplicationInfo().flags & android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0)
        directPort = getSharedPreferences("evgenium", 0).getInt("lab-udp-port", 443);
      p.setPort(route == 0 ? 24550 : route == 1 ? directPort : 24573);
      p.setRemoteId(route == 0 ? Credentials.RU : Credentials.EE);
      p.setLocalId(credentials.getString("identity"));
      p.setUserCertificateAlias(Credentials.ALIAS);
      p.setCertificateAlias(Credentials.ALIAS);
      p.setMTU(1280);
      p.setNATKeepAlive(20);
      p.setIkeProposal("aes256gcm16-prfsha384-ecp384");
      p.setEspProposal("chacha20poly1305");
      p.setSplitTunneling(VpnProfile.SPLIT_TUNNELING_BLOCK_IPV6);
      p.setDnsServers("1.1.1.1 9.9.9.9");
      if (exists)
        src.updateVpnProfile(p);
      else
        src.insertProfile(p);
    } finally {
      src.close();
    }
    current = IDS[route];
    getSharedPreferences("evgenium", 0).edit().putString("route", current).commit();
    set("Подключаю: " + LABELS[route]);
    long start = SystemClock.elapsedRealtime();
    record
    ("start", current, new JSONObject(), "");
    startService(new Intent(this, CharonVpnService.class)
            .putExtra(VpnProfileDataSource.KEY_UUID, uuid.toString()));
    while (SystemClock.elapsedRealtime() - start < 45000) {
      if (cancel)
        throw new InterruptedException();
      Thread.sleep(250);
      checkNetwork();
      VpnStateService v = vpn;
      if (v == null || v.getProfile() == null || !uuid.equals(v.getProfile().getUUID()))
        continue;
      if (v.getState() == VpnStateService.State.CONNECTED) {
        String ip = ExitProbe.get(this);
        if (!Credentials.EE.equals(ip))
          throw new IOException("unexpected_exit");
        checkNetwork();
        connectedNetwork = operationNetwork;
        if (cancel || instance != this)
          throw new InterruptedException();
        verified = true;
        set("Подключено: " + LABELS[route]);
        record
        ("connected", current,
            new JSONObject()
                .put("connect_ms", SystemClock.elapsedRealtime() - start)
                .put("exit", ip),
            "");
        return;
      }
      if (v.getErrorState() != VpnStateService.ErrorState.NO_ERROR)
        throw new IOException("ike_" + v.getErrorState().name());
    }
    throw new IOException("ike_timeout");
  }
  private void noRoutes() {
    verified = false;
    exhausted = true;
    TunnelCarrier.stopCurrent();
    set("Маршруты исчерпаны. Нажмите «Проверить маршруты» или «Отключить».");
  }
  private void connectRanked(int route) throws Exception {
    for (int attempts = 0; route >= 0 && attempts < IDS.length && !cancel; attempts++) {
      try {
        connectRoute(route);
        return;
      } catch (Exception e) {
        if (cancel)
          throw e;
        checkNetwork();
        lose(IDS[route]);
        record
        ("candidate_failed", IDS[route], new JSONObject(), safe(e));
        route = next(IDS[route]);
      }
    }
    if (!cancel)
      noRoutes();
  }
  private void rank() throws Exception {
    JSONObject ranking =
        new JSONObject().put("created", System.currentTimeMillis()).put("network", operationKind);
    JSONArray results = new JSONArray();
    for (int i = 0; i < IDS.length && !cancel; i++) {
      JSONObject r = new JSONObject().put("id", IDS[i]).put("losses", 0);
      long start = SystemClock.elapsedRealtime();
      try {
        connectRoute(i);
        if (diagnosing) {
          set("Пакетная диагностика: " + LABELS[i]);
          try {
            PacketDiagnostics.run(this, () -> {
              if (cancel)
                throw new InterruptedException();
              checkNetwork();
            }, (phase, values, error) -> record(phase, current, values, error));
          } catch (Exception diagnosticError) {
            if (cancel)
              throw diagnosticError;
            checkNetwork();
            record
            ("packet", current, new JSONObject(), safe(diagnosticError));
          }
        }
        set("Измеряю: " + LABELS[i]);
        JSONObject m;
        try {
          m = measure();
        } catch (Exception benchmark) {
          checkNetwork();
          if (!Credentials.EE.equals(ExitProbe.get(this)))
            throw benchmark;
          r.put("score", 0.001).put("warning", "speed_test_unavailable:" + safe(benchmark));
          m = null;
        }
        if (m != null)
          r.put("metrics", m)
              .put("score",
                  2 * m.getDouble("down") * m.getDouble("up")
                      / (m.getDouble("down") + m.getDouble("up"))
                      / (1 + m.getDouble("latency") / 200));
      } catch (Exception e) {
        if (cancel)
          throw e;
        checkNetwork();
        r.put("score", 0).put("losses", 1).put("error", safe(e));
      }
      checkNetwork();
      r.put("elapsed_ms", SystemClock.elapsedRealtime() - start);
      results.put(r);
      record
      ("rank", IDS[i], r, r.optString("error", r.optString("warning", "")));
    }
    if (!cancel) {
      checkNetwork();
      ranking.put("paths", results);
      saveRanking(ranking);
      if (best() < 0)
        noRoutes();
      else
        connectRanked(best());
    }
  }
  private JSONObject measure() throws Exception {
    Future<JSONObject> task = requests.submit(this::measureBlocking);
    long deadline = SystemClock.elapsedRealtime() + 70000;
    try {
      while (SystemClock.elapsedRealtime() < deadline) {
        if (cancel)
          throw new InterruptedException();
        checkNetwork();
        try {
          return task.get(500, TimeUnit.MILLISECONDS);
        } catch (TimeoutException pending) { /* Check network/cancellation again. */
        }
      }
      throw new IOException("measurement_deadline");
    } finally {
      task.cancel(true);
    }
  }
  private JSONObject measureBlocking() throws Exception {
    final String measuredRoute = current;
    final boolean detailed = diagnosing;
    final long measurementStart = SystemClock.elapsedRealtime();
    JSONObject timing = new JSONObject();
    LoadProbe load = null;
    int stage = 1;
    String transferError = "";
    try {
      final int size = 4 * 1024 * 1024;
      boolean privateLab =
          (getApplicationInfo().flags & android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0
          && getSharedPreferences("evgenium", 0).getBoolean("lab-private-speed", false);
      String origin = privateLab ? "https://10.77.0.1:24583" : "https://speed.cloudflare.com";
      long t = SystemClock.elapsedRealtime();
      String discord = "ok";
      try {
        textGet("https://discord.com/api/v10/gateway", 4096);
      } catch (Exception e) {
        discord = safe(e); // An individual service outage is not a broken VPN route.
      }
      timing.put("discord_ms", SystemClock.elapsedRealtime() - t);
      stage = 2;
      if (Thread.currentThread().isInterrupted())
        throw new InterruptedException();
      long latency;
      try (Socket probe = new Socket()) {
        t = SystemClock.elapsedRealtime();
        probe.connect(new InetSocketAddress("1.1.1.1", 443), 5000);
        latency = SystemClock.elapsedRealtime() - t;
      }
      stage = 3;
      t = SystemClock.elapsedRealtime();
      HttpsURLConnection down =
          (HttpsURLConnection) new URL(origin + "/__down?bytes=" + size).openConnection();
      if (privateLab)
        down.setSSLSocketFactory(Credentials.tls(this, true).getSocketFactory());
      down.setConnectTimeout(5000);
      down.setReadTimeout(10000);
      down.setInstanceFollowRedirects(false);
      int count;
      long downMaxReadMs = 0, upMaxWriteMs = 0;
      ScheduledFuture<?> downDeadline =
          httpDeadlines.schedule(down::disconnect, 25, TimeUnit.SECONDS);
      try {
        if (down.getResponseCode() != 200)
          throw new IOException("download_http");
        if (Thread.currentThread().isInterrupted())
          throw new InterruptedException();
        timing.put("down_setup_ms", SystemClock.elapsedRealtime() - t);
        stage = 4;
        if (detailed)
          load = new LoadProbe(32);
        // Measure body transfer separately from TLS/DNS setup.
        t = SystemClock.elapsedRealtime();
        try (InputStream in = down.getInputStream()) {
          count = 0;
          byte[] buffer = new byte[32768];
          int n;
          while (true) {
            long readStart = SystemClock.elapsedRealtime();
            n = in.read(buffer);
            downMaxReadMs = Math.max(downMaxReadMs, SystemClock.elapsedRealtime() - readStart);
            if (n == -1)
              break;
            if (Thread.currentThread().isInterrupted())
              throw new InterruptedException();
            count += n;
            if (count > size)
              throw new IOException("download_size");
          }
        }
      } finally {
        downDeadline.cancel(false);
        down.disconnect();
      }
      if (count != size)
        throw new IOException("download_size");
      timing.put("down_body_ms", SystemClock.elapsedRealtime() - t);
      double d = size * 8.0 / Math.max(1, SystemClock.elapsedRealtime() - t) / 1000;
      if (Thread.currentThread().isInterrupted())
        throw new InterruptedException();
      byte[] data = new byte[size];
      new java.security.SecureRandom().nextBytes(data);
      stage = 5;
      HttpsURLConnection up = (HttpsURLConnection) new URL(origin + "/__up").openConnection();
      if (privateLab)
        up.setSSLSocketFactory(Credentials.tls(this, true).getSocketFactory());
      up.setConnectTimeout(5000);
      up.setReadTimeout(10000);
      up.setRequestMethod("POST");
      up.setDoOutput(true);
      up.setFixedLengthStreamingMode(size);
      up.setInstanceFollowRedirects(false);
      t = SystemClock.elapsedRealtime();
      ScheduledFuture<?> upDeadline = httpDeadlines.schedule(up::disconnect, 25, TimeUnit.SECONDS);
      try {
        try (OutputStream out = up.getOutputStream()) {
          timing.put("up_setup_ms", SystemClock.elapsedRealtime() - t);
          stage = 6;
          if (Thread.currentThread().isInterrupted())
            throw new InterruptedException();
          t = SystemClock.elapsedRealtime();
          for (int offset = 0; offset < data.length; offset += 32768) {
            if (Thread.currentThread().isInterrupted())
              throw new InterruptedException();
            long writeStart = SystemClock.elapsedRealtime();
            out.write(data, offset, Math.min(32768, data.length - offset));
            upMaxWriteMs = Math.max(upMaxWriteMs, SystemClock.elapsedRealtime() - writeStart);
          }
        }
        timing.put("up_write_ms", SystemClock.elapsedRealtime() - t);
        stage = 7;
        if (up.getResponseCode() != 200)
          throw new IOException("upload_http");
        try (InputStream in = up.getInputStream()) {
          Credentials.read(in, 65536);
        }
      } finally {
        upDeadline.cancel(false);
        up.disconnect();
      }
      timing.put("up_body_ack_ms", SystemClock.elapsedRealtime() - t);
      stage = 8;
      double u = size * 8.0 / Math.max(1, SystemClock.elapsedRealtime() - t) / 1000;
      return new JSONObject()
          .put("screen_on", getSystemService(android.os.PowerManager.class).isInteractive())
          .put("cpu_lock", labWake != null && labWake.isHeld())
          .put("endpoint", privateLab ? "private-estonia" : "cloudflare")
          .put("down_max_read_ms", downMaxReadMs)
          .put("up_max_write_ms", upMaxWriteMs)
          .put("down", d)
          .put("up", u)
          .put("latency", latency)
          .put("bytes_per_direction", size)
          .put("method", "body-4mib-v2")
          .put("discord", discord);
    } catch (Exception e) {
      transferError = safe(e);
      throw e;
    } finally {
      if (detailed) {
        if (load != null) {
          load.close();
          record
          ("load", measuredRoute, load.metrics(), "");
        }
        timing.put("stage", stage)
            .put("elapsed_ms", SystemClock.elapsedRealtime() - measurementStart);
        record
        ("transfer", measuredRoute, timing, transferError);
      }
    }
  }

  private static final class NetworkChanged extends IOException {}
  private void beginNetwork() throws NetworkChanged {
    operationNetwork = NetworkAccess.select(this);
    operationKind = NetworkAccess.kind(this, operationNetwork);
    checkNetwork();
  }
  private boolean sameNetwork() {
    return operationNetwork != null && operationNetwork.equals(NetworkAccess.select(this));
  }
  private void checkNetwork() throws NetworkChanged {
    if (!sameNetwork())
      throw new NetworkChanged();
  }
  private String networkKind() {
    return NetworkAccess.kind(this, NetworkAccess.select(this));
  }
  private JSONObject ranking() throws Exception {
    android.util.AtomicFile file =
        new android.util.AtomicFile(new File(getFilesDir(), "ranking-" + operationKind + ".json"));
    try (InputStream in = file.openRead()) {
      return new JSONObject(new String(Credentials.read(in, 65536), StandardCharsets.UTF_8));
    }
  }
  private void saveRanking(JSONObject r) throws Exception {
    checkNetwork();
    android.util.AtomicFile file = new android.util.AtomicFile(
        new File(getFilesDir(), "ranking-" + r.getString("network") + ".json"));
    FileOutputStream out = file.startWrite();
    try {
      out.write(r.toString(2).getBytes(StandardCharsets.UTF_8));
      file.finishWrite(out);
    } catch (Exception e) {
      file.failWrite(out);
      throw e;
    }
  }
  private boolean hasRanking() {
    try {
      JSONArray paths = ranking().getJSONArray("paths");
      java.util.Set<String> found = new java.util.HashSet<>();
      for (int i = 0; i < paths.length(); i++) found.add(paths.getJSONObject(i).getString("id"));
      return paths.length() == IDS.length
          && found.equals(new java.util.HashSet<>(java.util.Arrays.asList(IDS)));
    } catch (Exception e) {
      return false;
    }
  }
  private RankingPolicy policy() throws Exception {
    JSONArray paths = ranking().getJSONArray("paths");
    double[] scores = new double[IDS.length];
    int[] losses = new int[IDS.length];
    Arrays.fill(losses, 3);
    for (int i = 0; i < paths.length(); i++) {
      JSONObject p = paths.getJSONObject(i);
      for (int j = 0; j < IDS.length; j++)
        if (IDS[j].equals(p.optString("id"))) {
          scores[j] = p.optDouble("score", 0);
          losses[j] = Math.max(0, p.optInt("losses", 3));
        }
    }
    return new RankingPolicy(scores, losses);
  }
  private int best() {
    try {
      return policy().first();
    } catch (Exception e) {
      return -1;
    }
  }
  private void lose(String id) throws Exception {
    JSONObject r = ranking();
    JSONArray a = r.getJSONArray("paths");
    for (int i = 0; i < a.length(); i++) {
      JSONObject p = a.getJSONObject(i);
      if (id.equals(p.getString("id")))
        p.put("losses", Math.min(3, p.optInt("losses") + 1));
    }
    saveRanking(r);
  }
  private int next(String id) throws Exception {
    for (int i = 0; i < IDS.length; i++)
      if (IDS[i].equals(id))
        return policy().after(i);
    return -1;
  }
  private static final ScheduledExecutorService httpDeadlines =
      Executors.newScheduledThreadPool(2, r -> {
        Thread t = new Thread(r, "evgenium-http-deadline");
        t.setDaemon(true);
        return t;
      });
  private static final ThreadPoolExecutor requests =
      new ThreadPoolExecutor(2, 2, 30, TimeUnit.SECONDS, new ArrayBlockingQueue<>(2), r -> {
        Thread t = new Thread(r, "evgenium-http");
        t.setDaemon(true);
        return t;
      });
  public static String textGet(String url, int max) throws Exception {
    Future<String> task;
    try {
      task = requests.submit(() -> textGetBlocking(url, max));
    } catch (RejectedExecutionException e) {
      throw new IOException("probe_busy", e);
    }
    try {
      return task.get(12, TimeUnit.SECONDS);
    } catch (TimeoutException e) {
      task.cancel(true);
      throw new IOException("probe_deadline", e);
    } catch (ExecutionException e) {
      Throwable cause = e.getCause();
      if (cause instanceof Exception)
        throw (Exception) cause;
      throw new IOException("probe_failed", cause);
    } catch (InterruptedException e) {
      task.cancel(true);
      Thread.currentThread().interrupt();
      throw e;
    }
  }
  private static String textGetBlocking(String url, int max) throws Exception {
    HttpsURLConnection c = (HttpsURLConnection) new URL(url).openConnection();
    c.setConnectTimeout(5000);
    c.setReadTimeout(7000);
    c.setInstanceFollowRedirects(false);
    try {
      if (c.getResponseCode() != 200)
        throw new IOException("http_" + c.getResponseCode());
      try (InputStream in = c.getInputStream()) {
        return new String(Credentials.read(in, max), StandardCharsets.UTF_8);
      }
    } finally {
      c.disconnect();
    }
  }
  private void record(String phase, String route, JSONObject values, String error) {
    try {
      JSONObject r =
          new JSONObject()
              .put("time", System.currentTimeMillis())
              .put("phase", phase)
              .put("route", route)
              .put("network", networkKind())
              .put("screen_on", getSystemService(android.os.PowerManager.class).isInteractive())
              .put(
                  "device_idle", getSystemService(android.os.PowerManager.class).isDeviceIdleMode())
              .put("values", values)
              .put("carrier", TunnelCarrier.activeMetrics())
              .put("error", error);
      File file = new File(getFilesDir(), "diagnostics.jsonl");
      if (file.length() > 1024 * 1024)
        file.renameTo(new File(getFilesDir(), "diagnostics.previous.jsonl"));
      try (FileOutputStream out = new FileOutputStream(file, true)) {
        out.write((r.toString() + "\n").getBytes(StandardCharsets.UTF_8));
      }
    } catch (Exception ignored) {
    }
  }
  private static String safe(Exception e) {
    return e.getClass().getSimpleName() + ":"
        + (e.getMessage() == null ? "unknown"
                                  : e.getMessage().replaceAll("EVN1-[A-Za-z0-9_-]+", "[redacted]"));
  }
  @Override
  public void onDestroy() {
    if (instance == this) {
      instance = null;
      running = false;
      verified = false;
    }
    cancel = true;
    handler.removeCallbacksAndMessages(null);
    worker.shutdownNow();
    try {
      unbindService(connection);
    } catch (Exception ignored) {
    }
    if (labWake != null && labWake.isHeld())
      labWake.release();
    super.onDestroy();
  }
}
