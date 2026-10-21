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

/** Single owner of connection orchestration; UI only sends commands and displays state. */
public class Engine extends Service {
  public static final String[] IDS = {"ru-udp", "ee-udp", "ee-tls", "ee-evgt"};
  public static final String[] LABELS = {
      "HSVDS → Эстония", "Эстония · UDP", "Эстония · TLS", "Эстония · EvgeniumTunnel"};
  public static volatile String status = "Не подключено";
  public static volatile String current = "";
  private volatile VpnStateService vpn;
  private volatile boolean cancel;
  private final ExecutorService worker = Executors.newSingleThreadExecutor();
  private final Handler handler = new Handler(Looper.getMainLooper());
  private String connectedNetwork = "";
  private long generation;
  private int consecutive;
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
    if (i == null)
      return START_NOT_STICKY;
    String cmd = i.getStringExtra("command");
    int route = i.getIntExtra("route", -1);
    if ("stop".equals(cmd)) {
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
      return START_NOT_STICKY;
    }
    busy = true;
    cancel = false;
    exhausted = false;
    consecutive = 0;
    long mine = ++generation;
    worker.execute(() -> {
      try {
        if ("rank".equals(cmd) || (route < 0 && !hasRanking()))
          rank();
        else if (route >= 0)
          connectRoute(route);
        else
          connectRanked(best());
        if (!cancel && mine == generation)
          handler.postDelayed(() -> monitor(mine), 15000);
      } catch (Exception e) {
        set("Ошибка: " + safe(e));
        record
        ("failed", current, new JSONObject(), safe(e));
      } finally {
        busy = false;
      }
    });
    return START_NOT_STICKY;
  }
  private void monitor(long mine) {
    if (cancel || exhausted || mine != generation)
      return;
    if (busy) {
      handler.postDelayed(() -> monitor(mine), 15000);
      return;
    }
    busy = true;
    worker.execute(() -> {
      try {
        ConnectivityManager cm = getSystemService(ConnectivityManager.class);
        boolean internet = false;
        for (Network n : cm.getAllNetworks()) {
          NetworkCapabilities cap = cm.getNetworkCapabilities(n);
          if (cap != null && !cap.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
              && cap.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET))
            internet = true;
        }
        if (!internet) {
          consecutive = 0;
          set("Ожидаю доступную сеть");
          return;
        }
        String kind = networkKind();
        if (!kind.equals(connectedNetwork) && !"unknown".equals(kind)) {
          consecutive = 0;
          record
          ("network_changed", current, new JSONObject(), "");
          connectedNetwork = kind;
          if (hasRanking())
            connectRanked(best());
          else
            rank();
          return;
        }
        if (vpn != null && vpn.getState() == VpnStateService.State.CONNECTED
            && Credentials.EE.equals(ExitProbe.get(this))) {
          consecutive = 0;
          set("Подключено: " + label(current));
          return;
        }
        throw new IOException("health_failed");
      } catch (Exception e) {
        record
        ("health_failed", current, new JSONObject(), safe(e));
        if (++consecutive >= 2) {
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
        if (!cancel && mine == generation)
          handler.postDelayed(() -> monitor(mine), 15000);
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
    if (cancel)
      throw new InterruptedException();
    if (route < 0 || route >= IDS.length)
      throw new IOException("no_available_route");
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
      p.setPort(route == 0 ? 24550 : route == 1 ? 443 : 24573);
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
      VpnStateService v = vpn;
      if (v == null || v.getProfile() == null || !uuid.equals(v.getProfile().getUUID()))
        continue;
      if (v.getState() == VpnStateService.State.CONNECTED) {
        String ip = ExitProbe.get(this);
        if (!Credentials.EE.equals(ip))
          throw new IOException("unexpected_exit");
        connectedNetwork = networkKind();
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
        new JSONObject().put("created", System.currentTimeMillis()).put("network", networkKind());
    JSONArray results = new JSONArray();
    for (int i = 0; i < IDS.length && !cancel; i++) {
      JSONObject r = new JSONObject().put("id", IDS[i]).put("losses", 0);
      long start = SystemClock.elapsedRealtime();
      try {
        connectRoute(i);
        set("Измеряю: " + LABELS[i]);
        JSONObject m = measure();
        r.put("metrics", m)
            .put("score",
                2 * m.getDouble("down") * m.getDouble("up")
                    / (m.getDouble("down") + m.getDouble("up"))
                    / (1 + m.getDouble("latency") / 200));
      } catch (Exception e) {
        if (cancel)
          throw e;
        r.put("score", 0).put("losses", 1).put("error", safe(e));
      }
      r.put("elapsed_ms", SystemClock.elapsedRealtime() - start);
      results.put(r);
      record
      ("rank", IDS[i], r, "");
      ranking.put("paths", results);
      saveRanking(ranking);
    }
    if (!cancel) {
      if (best() < 0)
        noRoutes();
      else
        connectRanked(best());
    }
  }
  private JSONObject measure() throws Exception {
    final int size = 1024 * 1024;
    long t = SystemClock.elapsedRealtime();
    textGet("https://discord.com/api/v10/gateway", 4096);
    long latency;
    try (Socket probe = new Socket()) {
      t = SystemClock.elapsedRealtime();
      probe.connect(new InetSocketAddress("1.1.1.1", 443), 5000);
      latency = SystemClock.elapsedRealtime() - t;
    }
    t = SystemClock.elapsedRealtime();
    HttpsURLConnection down =
        (HttpsURLConnection) new URL("https://speed.cloudflare.com/__down?bytes=" + size)
            .openConnection();
    down.setConnectTimeout(5000);
    down.setReadTimeout(10000);
    down.setInstanceFollowRedirects(false);
    int count;
    try {
      if (down.getResponseCode() != 200)
        throw new IOException("download_http");
      try (InputStream in = down.getInputStream()) {
        count = Credentials.read(in, size + 1).length;
      }
    } finally {
      down.disconnect();
    }
    if (count != size)
      throw new IOException("download_size");
    double d = size * 8.0 / Math.max(1, SystemClock.elapsedRealtime() - t) / 1000;
    byte[] data = new byte[size];
    new java.security.SecureRandom().nextBytes(data);
    HttpsURLConnection up =
        (HttpsURLConnection) new URL("https://speed.cloudflare.com/__up").openConnection();
    up.setConnectTimeout(5000);
    up.setReadTimeout(10000);
    up.setRequestMethod("POST");
    up.setDoOutput(true);
    up.setFixedLengthStreamingMode(size);
    up.setInstanceFollowRedirects(false);
    t = SystemClock.elapsedRealtime();
    try {
      try (OutputStream out = up.getOutputStream()) {
        out.write(data);
      }
      if (up.getResponseCode() != 200)
        throw new IOException("upload_http");
      try (InputStream in = up.getInputStream()) {
        Credentials.read(in, 65536);
      }
    } finally {
      up.disconnect();
    }
    double u = size * 8.0 / Math.max(1, SystemClock.elapsedRealtime() - t) / 1000;
    return new JSONObject()
        .put("down", d)
        .put("up", u)
        .put("latency", latency)
        .put("bytes_per_direction", size);
  }
  private String networkKind() {
    ConnectivityManager cm = getSystemService(ConnectivityManager.class);
    boolean cell = false;
    for (Network n : cm.getAllNetworks()) {
      NetworkCapabilities cap = cm.getNetworkCapabilities(n);
      if (cap != null && !cap.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
          && cap.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) {
        if (cap.hasTransport(NetworkCapabilities.TRANSPORT_WIFI))
          return "wifi";
        if (cap.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR))
          cell = true;
      }
    }
    return cell ? "cellular" : "unknown";
  }

  private JSONObject ranking() throws Exception {
    try (InputStream in = openFileInput("ranking-" + networkKind() + ".json")) {
      return new JSONObject(new String(Credentials.read(in, 65536), StandardCharsets.UTF_8));
    }
  }
  private void saveRanking(JSONObject r) throws Exception {
    try (FileOutputStream out = openFileOutput(
             "ranking-" + r.optString("network", networkKind()) + ".json", MODE_PRIVATE)) {
      out.write(r.toString(2).getBytes(StandardCharsets.UTF_8));
      out.getFD().sync();
    }
  }
  private boolean hasRanking() {
    try {
      return ranking().getJSONArray("paths").length() == 4;
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
      JSONObject r = new JSONObject()
                         .put("time", System.currentTimeMillis())
                         .put("phase", phase)
                         .put("route", route)
                         .put("network", networkKind())
                         .put("values", values)
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
    cancel = true;
    handler.removeCallbacksAndMessages(null);
    worker.shutdownNow();
    try {
      unbindService(connection);
    } catch (Exception ignored) {
    }
    super.onDestroy();
  }
}
