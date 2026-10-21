/* SPDX-License-Identifier: GPL-2.0-or-later */
package org.strongswan.android.evgenium;
import android.app.*;
import android.content.*;
import android.graphics.Color;
import android.net.VpnService;
import android.os.*;
import android.text.InputType;
import android.view.*;
import android.widget.*;
import java.io.*;
import java.nio.charset.StandardCharsets;

public class HomeActivity extends Activity {
  private TextView status, details, deviceName;
  private EditText token;
  private Spinner route;
  private String pending = "connect";
  private final Handler ui = new Handler(Looper.getMainLooper());
  private final Runnable refresh = new Runnable() {
    public void run() {
      status.setText(Engine.status);
      try {
        deviceName.setText(
            Credentials.profile(HomeActivity.this).optString("device_name", "Устройство"));
      } catch (Exception ignored) {
      }
      ui.postDelayed(this, 1000);
    }
  };
  @Override
  public void onCreate(Bundle state) {
    super.onCreate(state);
    LinearLayout root = new LinearLayout(this);
    root.setOrientation(LinearLayout.VERTICAL);
    root.setPadding(40, 60, 40, 40);
    root.setBackgroundColor(Color.rgb(18, 27, 24));
    ScrollView scroll = new ScrollView(this);
    scroll.setFillViewport(true);
    scroll.addView(root);
    setContentView(scroll);
    title(root, "EVGENIUM", 30);
    title(root, "Android · 0.1.0 alpha", 14);
    status = title(root, Engine.status, 22);
    status.setPadding(0, 35, 0, 25);
    deviceName = title(root, "Устройство ещё не зарегистрировано", 18);
    button(root, "Переименовать устройство", () -> {
      EditText name = new EditText(this);
      name.setSingleLine(true);
      name.setText(deviceName.getText());
      new AlertDialog.Builder(this)
          .setTitle("Имя в панели сети")
          .setView(name)
          .setNegativeButton("Отмена", null)
          .setPositiveButton("Сохранить", (d, w) -> new Thread(() -> {
            try {
              String actual = Credentials.rename(this, name.getText().toString());
              runOnUiThread(() -> {
                deviceName.setText(actual);
                Toast.makeText(this, "Имя сохранено", Toast.LENGTH_SHORT).show();
              });
            } catch (Exception e) {
              runOnUiThread(()
                                -> Toast
                                    .makeText(this, "Не удалось сохранить: " + e.getMessage(),
                                        Toast.LENGTH_LONG)
                                    .show());
            }
          }).start())
          .show();
    });
    title(root, "Токен клиента", 16);
    token = new EditText(this);
    token.setSingleLine(true);
    token.setTextColor(Color.WHITE);
    token.setHintTextColor(Color.LTGRAY);
    token.setHint("EVN1-…");
    token.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
    root.addView(token);
    CheckBox show = new CheckBox(this);
    show.setText("Показать токен");
    show.setTextColor(Color.LTGRAY);
    root.addView(show);
    show.setOnCheckedChangeListener((v, checked) -> {
      int cursor = token.getSelectionStart();
      token.setTransformationMethod(
          checked ? null : android.text.method.PasswordTransformationMethod.getInstance());
      token.setSelection(Math.max(0, cursor));
    });
    button(root, "Подтвердить токен", () -> {
      String value = token.getText().toString().trim();
      Engine.status = "Получаю сертификат устройства…";
      new Thread(() -> {
        try {
          Credentials.enroll(this, value);
          Engine.status = "Доступ выдан. Можно подключаться.";
          runOnUiThread(() -> token.setText(""));
        } catch (Exception e) {
          Engine.status =
              "Ошибка регистрации: " + e.getClass().getSimpleName() + ": " + e.getMessage();
        }
      }).start();
    });
    route = new Spinner(this);
    String[] options = new String[5];
    options[0] = "Автоматически по рейтингу";
    System.arraycopy(Engine.LABELS, 0, options, 1, 4);
    ArrayAdapter<String> adapter =
        new ArrayAdapter<>(this, android.R.layout.simple_spinner_dropdown_item, options);
    route.setAdapter(adapter);
    root.addView(route);
    button(root, "Подключить", () -> prepare("connect"));
    button(root, "Проверить маршруты", () -> prepare("rank"));
    button(root, "Отключить", () -> command("stop"));
    button(root, "Показать результаты", () -> details.setText(results()));
    button(root, "Системная защита VPN",
        () -> startActivity(new Intent("android.settings.VPN_SETTINGS")));
    details = title(root,
        "Тестовая версия. Проверка четырёх маршрутов расходует до 8 МБ полезных данных плюс "
            + "служебный трафик. Отчёты сохраняются только на телефоне. Для защиты при остановке "
            + "приложения системой включите «Постоянный VPN» и «Блокировать соединения без VPN» в "
            + "системных настройках. Эта версия ещё проходит проверку.\n\nЯдро strongSwan · GPLv2+",
        14);
    if (Build.VERSION.SDK_INT >= 33
        && checkSelfPermission("android.permission.POST_NOTIFICATIONS")
            != getPackageManager().PERMISSION_GRANTED)
      requestPermissions(new String[] {"android.permission.POST_NOTIFICATIONS"}, 2);
    handleDebug(getIntent());
  }
  private String results() {
    StringBuilder out = new StringBuilder();
    for (String kind : new String[] {"wifi", "cellular"})
      try (InputStream in = openFileInput("ranking-" + kind + ".json")) {
        org.json.JSONObject r = new org.json.JSONObject(
            new String(Credentials.read(in, 65536), StandardCharsets.UTF_8));
        out.append(kind.equals("wifi") ? "Wi-Fi" : "Мобильная сеть")
            .append(" · ")
            .append(java.text.DateFormat.getDateTimeInstance().format(
                new java.util.Date(r.getLong("created"))))
            .append("\n");
        org.json.JSONArray paths = r.getJSONArray("paths");
        for (int j = 0; j < paths.length(); j++) {
          org.json.JSONObject p = paths.getJSONObject(j);
          String id = p.getString("id"), label = id;
          for (int k = 0; k < Engine.IDS.length; k++)
            if (Engine.IDS[k].equals(id))
              label = Engine.LABELS[k];
          out.append(label).append("\n");
          org.json.JSONObject m = p.optJSONObject("metrics");
          if (m != null)
            out.append(String.format(java.util.Locale.ROOT,
                "↓ %.1f · ↑ %.1f Мбит/с · %d мс\nРейтинг %.2f · сбоев %d/3\n", m.optDouble("down"),
                m.optDouble("up"), m.optLong("latency"), p.optDouble("score"), p.optInt("losses")));
          else
            out.append("Не прошёл проверку: ").append(p.optString("error")).append("\n");
          out.append("\n");
        }
      } catch (Exception ignored) {
      }
    return out.length() > 0 ? out.toString() : "Проверок ещё не было.";
  }
  private TextView title(LinearLayout root, String s, int size) {
    TextView t = new TextView(this);
    t.setText(s);
    t.setTextSize(size);
    t.setTextColor(Color.rgb(210, 237, 213));
    t.setPadding(0, 10, 0, 10);
    root.addView(t);
    return t;
  }
  private void button(LinearLayout root, String s, Runnable action) {
    Button b = new Button(this);
    b.setText(s);
    b.setAllCaps(false);
    root.addView(b);
    b.setOnClickListener(v -> action.run());
  }
  private void prepare(String cmd) {
    pending = cmd;
    Intent permission = VpnService.prepare(this);
    if (permission != null)
      startActivityForResult(permission, 1);
    else
      command(cmd);
  }
  private void command(String cmd) {
    Intent i = new Intent(this, Engine.class)
                   .putExtra("command", cmd)
                   .putExtra("route", route.getSelectedItemPosition() - 1);
    startForegroundService(i);
  }
  @Override
  protected void onActivityResult(int request, int result, Intent data) {
    super.onActivityResult(request, result, data);
    if (request == 1 && result == RESULT_OK)
      command(pending);
  }
  @Override
  protected void onResume() {
    super.onResume();
    ui.post(refresh);
  }
  @Override
  protected void onPause() {
    ui.removeCallbacks(refresh);
    super.onPause();
  }
  @Override
  protected void onNewIntent(Intent i) {
    super.onNewIntent(i);
    setIntent(i);
    handleDebug(i);
  }
  /**
   * Lab automation accepts no secrets in Intents. ADB places a one-use token in app-private
   * storage.
   */
  private void handleDebug(Intent i) {
    if ((getApplicationInfo().flags & android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) == 0)
      return;
    if (i.hasExtra("lab-forward"))
      getSharedPreferences("evgenium", 0)
          .edit()
          .putBoolean("lab-forward", i.getBooleanExtra("lab-forward", false))
          .commit();
    String cmd = i.getStringExtra("lab");
    if (cmd == null)
      return;
    if ("fault".equals(cmd)) {
      TunnelCarrier.debugFault(this);
      new Thread(() -> {
        try {
          org.json.JSONArray probes = new org.json.JSONArray();
          long end = SystemClock.elapsedRealtime() + 120000;
          while (SystemClock.elapsedRealtime() < end) {
            org.json.JSONObject p =
                new org.json.JSONObject().put("time", System.currentTimeMillis());
            try {
              String ip = ExitProbe.get(this);
              p.put("result", Credentials.EE.equals(ip) ? "estonia" : "UNEXPECTED_EXIT");
            } catch (Exception e) {
              p.put("result", "blocked").put("error", e.getClass().getSimpleName());
            }
            probes.put(p);
            Thread.sleep(1500);
          }
          try (FileOutputStream out = openFileOutput("fault-probes.json", MODE_PRIVATE)) {
            out.write(probes.toString(2).getBytes(StandardCharsets.UTF_8));
          }
          android.util.Log.i("Evgenium", "fault_probe_finished");
        } catch (Exception e) {
          android.util.Log.w("Evgenium", "fault_probe_failed");
        }
      }).start();
      return;
    }
    if ("enroll".equals(cmd)) {
      new Thread(() -> {
        File f = new File(getFilesDir(), "lab-token");
        try (InputStream in = new FileInputStream(f)) {
          String t = new String(Credentials.read(in, 128), StandardCharsets.UTF_8).trim();
          Credentials.enroll(this, t);
          Engine.status = "Доступ выдан";
        } catch (Exception e) {
          Engine.status = "enroll_" + e.getClass().getSimpleName() + ":" + e.getMessage();
        } finally {
          f.delete();
          android.util.Log.i("Evgenium", Engine.status);
        }
      }).start();
      return;
    }
    if ("baseline".equals(cmd)) {
      new Thread(() -> {
        try {
          android.net.ConnectivityManager cm =
              getSystemService(android.net.ConnectivityManager.class);
          for (android.net.Network n : cm.getAllNetworks()) {
            android.net.NetworkCapabilities caps = cm.getNetworkCapabilities(n);
            if (caps != null && caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN))
              throw new IOException("Disconnect VPN before baseline");
          }
          org.json.JSONArray out = new org.json.JSONArray();
          String[] hosts = {Credentials.RU, Credentials.EE, Credentials.EE, "1.1.1.1", "yandex.ru"};
          int[] ports = {8443, 24571, 24578, 443, 443};
          for (int k = 0; k < hosts.length; k++) {
            org.json.JSONObject r =
                new org.json.JSONObject().put("host", hosts[k]).put("port", ports[k]);
            long t = android.os.SystemClock.elapsedRealtime();
            try (java.net.Socket socket = new java.net.Socket()) {
              socket.connect(new java.net.InetSocketAddress(hosts[k], ports[k]), 5000);
              r.put("ok", true);
            } catch (Exception e) {
              r.put("error", e.getClass().getSimpleName());
            }
            r.put("ms", android.os.SystemClock.elapsedRealtime() - t);
            out.put(r);
          }
          try (FileOutputStream f = openFileOutput("baseline.json", MODE_PRIVATE)) {
            f.write(out.toString(2).getBytes(StandardCharsets.UTF_8));
          }
          Engine.status = "Базовая проверка сохранена";
        } catch (Exception e) {
          Engine.status = "baseline_" + e.getMessage();
        }
        android.util.Log.i("Evgenium", Engine.status);
      }).start();
      return;
    }
    if (i.hasExtra("route"))
      route.setSelection(i.getIntExtra("route", -1) + 1);
    if ("connect".equals(cmd) || "rank".equals(cmd))
      prepare(cmd);
    else if ("stop".equals(cmd))
      command(cmd);
  }
}
