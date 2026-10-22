/* SPDX-License-Identifier: GPL-2.0-or-later */
package org.strongswan.android.evgenium;
import android.app.*;
import android.content.*;
import android.graphics.*;
import android.graphics.drawable.GradientDrawable;
import android.net.VpnService;
import android.os.*;
import android.text.InputType;
import android.view.*;
import android.widget.*;
import java.io.*;
import java.nio.charset.StandardCharsets;

public class HomeActivity extends Activity {
  private static final int BG = 0xff121b16, CARD = 0xff1c2820, INK = 0xffe9f0e6, MUTED = 0xff9bab9a,
                           LIME = 0xffbbf08b;
  private TextView status, deviceName, diagnosticStatus;
  private EditText token;
  private Spinner route;
  private PowerControl power;
  private Button runDiagnostic, collectDiagnostic, sendDiagnostic;
  private String pending = "connect", page = "home";
  private final Handler ui = new Handler(Looper.getMainLooper());
  private final Runnable refresh = new Runnable() {
    public void run() {
      if (status != null)
        status.setText(Engine.status);
      if (power != null)
        power.state(Engine.verified, Engine.running);
      if (diagnosticStatus != null)
        diagnosticStatus.setText(DiagnosticReports.summary(HomeActivity.this));
      if (runDiagnostic != null)
        runDiagnostic.setEnabled(!Engine.working() && !DiagnosticReports.sending);
      if (collectDiagnostic != null)
        collectDiagnostic.setEnabled(!Engine.diagnosing && !DiagnosticReports.sending);
      if (sendDiagnostic != null)
        sendDiagnostic.setEnabled(DiagnosticReports.exists(HomeActivity.this) && !Engine.diagnosing
            && !DiagnosticReports.sending);
      for (Button b : new Button[] {runDiagnostic, collectDiagnostic, sendDiagnostic})
        if (b != null)
          b.setAlpha(b.isEnabled() ? 1f : .4f);
      ui.postDelayed(this, 1000);
    }
  };
  private int dp(float n) {
    return Math.round(n * getResources().getDisplayMetrics().density);
  }
  private GradientDrawable shape(int color, int radius) {
    GradientDrawable d = new GradientDrawable();
    d.setColor(color);
    d.setCornerRadius(dp(radius));
    return d;
  }
  private LinearLayout column() {
    LinearLayout v = new LinearLayout(this);
    v.setOrientation(LinearLayout.VERTICAL);
    return v;
  }
  private LinearLayout frame(String title) {
    status = null;
    power = null;
    deviceName = null;
    diagnosticStatus = null;
    runDiagnostic = null;
    collectDiagnostic = null;
    sendDiagnostic = null;
    LinearLayout root = column();
    root.setBackgroundColor(BG);
    root.setPadding(dp(24), dp(12), dp(24), dp(16));
    root.setOnApplyWindowInsetsListener((v, insets) -> {
      v.setPadding(dp(24) + insets.getSystemWindowInsetLeft(),
          dp(12) + insets.getSystemWindowInsetTop(), dp(24) + insets.getSystemWindowInsetRight(),
          dp(16) + insets.getSystemWindowInsetBottom());
      return insets.consumeSystemWindowInsets();
    });
    setContentView(root);
    root.requestApplyInsets();
    LinearLayout header = new LinearLayout(this);
    header.setGravity(Gravity.CENTER_VERTICAL);
    Button gear = new Button(this);
    gear.setAllCaps(false);
    gear.setText(title == null ? "⚙" : "‹");
    gear.setTextSize(28);
    gear.setTextColor(INK);
    gear.setPadding(0, 0, 0, 0);
    gear.setBackground(shape(CARD, 16));
    gear.setContentDescription(title == null ? "Настройки" : "Назад");
    header.addView(gear, new LinearLayout.LayoutParams(dp(52), dp(52)));
    gear.setOnClickListener(v -> {
      if (title == null)
        settings();
      else
        home();
    });
    TextView brand = new TextView(this);
    brand.setText(title == null ? "EVGENIUM" : title);
    brand.setTextSize(title == null ? 17 : 22);
    brand.setTypeface(Typeface.create("sans-serif-medium", 0));
    brand.setTextColor(INK);
    brand.setPadding(dp(18), 0, 0, 0);
    header.addView(brand, new LinearLayout.LayoutParams(0, dp(52), 1));
    brand.setGravity(Gravity.CENTER_VERTICAL);
    root.addView(header);
    return root;
  }
  @Override
  public void onCreate(Bundle state) {
    setTheme(android.R.style.Theme_Material_NoActionBar);
    super.onCreate(state);
    getWindow().setStatusBarColor(BG);
    getWindow().setNavigationBarColor(BG);
    getWindow().getDecorView().setSystemUiVisibility(0);
    route = new Spinner(this);
    String[] options = new String[Engine.LABELS.length + 1];
    options[0] = "Автоматически по рейтингу";
    System.arraycopy(Engine.LABELS, 0, options, 1, Engine.LABELS.length);
    route.setAdapter(
        new ArrayAdapter<String>(this, android.R.layout.simple_spinner_dropdown_item, options));
    route.setSelection(Math.min(
        Engine.IDS.length, Math.max(0, getPreferences(0).getInt("selected-route", -1) + 1)));
    home();
    if (state != null && "settings".equals(state.getString("page")))
      settings();
    else if (state != null && "diagnostics".equals(state.getString("page")))
      diagnostics();
    if (Build.VERSION.SDK_INT >= 33
        && checkSelfPermission("android.permission.POST_NOTIFICATIONS")
            != getPackageManager().PERMISSION_GRANTED)
      requestPermissions(new String[] {"android.permission.POST_NOTIFICATIONS"}, 2);
    handleDebug(getIntent());
  }
  private boolean enrolled() {
    return new File(getFilesDir(), "device.json").isFile();
  }
  private void home() {
    page = "home";
    LinearLayout root = frame(null);
    LinearLayout body = column();
    root.addView(body, new LinearLayout.LayoutParams(-1, 0, 1));
    power = new PowerControl(this);
    power.setContentDescription("Включить VPN");
    boolean landscape = getResources().getConfiguration().orientation
        == android.content.res.Configuration.ORIENTATION_LANDSCAPE;
    if (landscape)
      body.setOrientation(LinearLayout.HORIZONTAL);
    body.addView(power,
        landscape ? new LinearLayout.LayoutParams(0, -1, 6)
                  : new LinearLayout.LayoutParams(-1, 0, 6));
    power.state(Engine.verified, Engine.running);
    power.setOnClickListener(v -> {
      if (Engine.running) {
        command("stop");
        return;
      }
      if (!enrolled()) {
        settings();
        new AlertDialog.Builder(this)
            .setTitle("Добавьте токен")
            .setMessage(
                "Вставьте токен клиента в настройках. Он подходит для всех ваших устройств.")
            .setPositiveButton("Понятно", null)
            .show();
        return;
      }
      prepare("connect");
    });
    LinearLayout bottom = column();
    bottom.setGravity(Gravity.BOTTOM);
    body.addView(bottom,
        landscape ? new LinearLayout.LayoutParams(0, -1, 4)
            : getResources().getConfiguration().screenHeightDp < 700
            ? new LinearLayout.LayoutParams(-1, -2)
            : new LinearLayout.LayoutParams(-1, 0, 4));
    TextView word = title(bottom, "ВАША СЕТЬ. ВАШ КОНТРОЛЬ.", 11);
    word.setLetterSpacing(.16f);
    word.setTextColor(MUTED);
    LinearLayout card = column();
    card.setPadding(dp(20), dp(18), dp(20), dp(18));
    card.setBackground(shape(CARD, 22));
    bottom.addView(card, new LinearLayout.LayoutParams(-1, -2));
    title(card, "Состояние соединения", 13).setTextColor(MUTED);
    status = title(card, Engine.status, 19);
    status.setAccessibilityLiveRegion(View.ACCESSIBILITY_LIVE_REGION_POLITE);
    title(bottom, "Тестовая версия · " + version(), 12).setTextColor(MUTED);
  }
  private LinearLayout content(String name) {
    LinearLayout root = frame(name);
    ScrollView scroll = new ScrollView(this);
    scroll.setFillViewport(true);
    LinearLayout c = column();
    c.setPadding(0, dp(20), 0, dp(12));
    scroll.addView(c);
    root.addView(scroll, new LinearLayout.LayoutParams(-1, 0, 1));
    return c;
  }
  private void settings() {
    page = "settings";
    LinearLayout c = content("Настройки");
    title(c, "ВАШЕ УСТРОЙСТВО", 12).setTextColor(MUTED);
    String name = "Устройство ещё не зарегистрировано";
    try {
      name = Credentials.profile(this).optString("device_name", "Устройство");
    } catch (Exception ignored) {
    }
    deviceName = title(c, name, 22);
    button(c, "Изменить имя устройства", this::rename).setEnabled(enrolled());
    title(c, "Токен клиента", 18);
    token = new EditText(this);
    token.setSingleLine(true);
    token.setTextColor(INK);
    token.setHintTextColor(MUTED);
    token.setHint(enrolled() ? "Токен уже подтверждён" : "EVN1-…");
    token.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
    token.setPadding(dp(16), dp(12), dp(16), dp(12));
    token.setBackground(shape(CARD, 12));
    c.addView(token, new LinearLayout.LayoutParams(-1, dp(54)));
    CheckBox show = new CheckBox(this);
    show.setText("Показать вводимый токен");
    show.setTextColor(MUTED);
    c.addView(show);
    show.setOnCheckedChangeListener((v, on) -> {
      int n = token.getSelectionStart();
      token.setTransformationMethod(
          on ? null : android.text.method.PasswordTransformationMethod.getInstance());
      token.setSelection(Math.max(0, n));
    });
    Button enroll = button(c, enrolled() ? "Заменить токен" : "Подтвердить токен", () -> enroll());
    enroll.setEnabled(!Engine.running);
    title(c, "Маршрут", 18);
    if (route.getParent() != null)
      ((android.view.ViewGroup) route.getParent()).removeView(route);
    c.addView(route, new LinearLayout.LayoutParams(-1, dp(54)));
    button(c, "Восстановить · проверить маршруты", () -> confirmTests(false));
    button(c, "Результаты проверки маршрутов", () -> textDialog("Рейтинг маршрутов", results()));
    title(c, "ПОМОЧЬ УЛУЧШИТЬ VPN", 12).setTextColor(MUTED);
    button(c, "Полная диагностика", this::diagnostics);
    button(c, "Системная защита VPN",
        () -> startActivity(new Intent("android.settings.VPN_SETTINGS")));
    title(c,
        "Для защиты при остановке приложения Android включите постоянный VPN и блокировку "
            + "соединений без VPN в системных настройках.",
        13)
        .setTextColor(MUTED);
    title(c, "Evgenium " + version() + " · strongSwan · GPLv2+", 12).setTextColor(MUTED);
  }
  private void diagnostics() {
    page = "diagnostics";
    LinearLayout c = content("Диагностика");
    title(c, "Помогите сделать связь лучше", 25);
    title(c,
        "Проверим все 5 маршрутов, скорость в обе стороны и доступность сервисов. Отчёт сначала "
            + "сохраняется на телефоне. Отправка — только по вашему подтверждению.",
        15)
        .setTextColor(MUTED);
    diagnosticStatus = title(c, DiagnosticReports.summary(this), 16);
    runDiagnostic = button(c, "Начать полную проверку", () -> confirmTests(true));
    collectDiagnostic = button(c, "Собрать отчёт без новых тестов", () -> {
      try {
        DiagnosticReports.prepare(this, "snapshot");
      } catch (Exception e) {
        toast("Не удалось собрать отчёт");
      }
    });
    button(c, "Просмотреть отчёт", () -> {
      try {
        textDialog("Содержимое отчёта", DiagnosticReports.preview(this).toString(2));
      } catch (Exception e) {
        toast("Сначала соберите отчёт");
      }
    });
    sendDiagnostic = button(c, "Отправить отчёт",
        ()
            -> new AlertDialog.Builder(this)
                .setTitle("Отправить разработчику?")
                .setMessage("Будут переданы модель и версия Android, результаты тестов, события "
                    + "VPN и технические счётчики. Сервер свяжет отчёт с сертификатом "
                    + "этого устройства. Токены, ключи, содержимое трафика и история "
                    + "посещений не передаются.")
                .setNegativeButton("Отмена", null)
                .setPositiveButton("Отправить", (d, w) -> DiagnosticReports.send(this))
                .show());
    title(c,
        "Если связь пропала, соберите текущий отчёт. Он останется здесь; отправьте его после "
            + "восстановления сети. Автоматической отправки нет.",
        13)
        .setTextColor(MUTED);
  }
  private void confirmTests(boolean diagnostic) {
    if (!enrolled()) {
      toast("Сначала подтвердите токен в настройках");
      return;
    }
    new AlertDialog.Builder(this)
        .setTitle(diagnostic ? "Полная диагностика" : "Перепроверить маршруты?")
        .setMessage("Проверка займёт несколько минут и обновит рейтинг. Во время переключений "
            + "возможны паузы связи. Расход — около 60 МБ, при повторах больше. Отчёт не "
            + "отправляется автоматически.")
        .setNegativeButton("Отмена", null)
        .setPositiveButton("Начать", (d, w) -> prepare(diagnostic ? "diagnose" : "rank"))
        .show();
  }
  private void enroll() {
    if (Engine.running) {
      toast("Сначала отключите VPN");
      return;
    }
    final EditText field = token;
    String value = field.getText().toString().trim();
    new Thread(() -> {
      try {
        Credentials.enroll(this, value);
        runOnUiThread(() -> {
          field.setText("");
          settings();
          toast("Токен подтверждён");
        });
      } catch (Exception e) {
        runOnUiThread(() -> toast("Не удалось подтвердить токен. Проверьте токен и подключение."));
      }
    }).start();
  }
  private void rename() {
    EditText field = new EditText(this);
    field.setSingleLine(true);
    field.setText(deviceName.getText());
    new AlertDialog.Builder(this)
        .setTitle("Имя устройства")
        .setView(field)
        .setNegativeButton("Отмена", null)
        .setPositiveButton("Сохранить", (d, w) -> new Thread(() -> {
          try {
            String value = Credentials.rename(this, field.getText().toString());
            runOnUiThread(() -> {
              if (deviceName != null)
                deviceName.setText(value);
              toast("Имя сохранено");
            });
          } catch (Exception e) {
            runOnUiThread(() -> toast("Не удалось сохранить имя"));
          }
        }).start())
        .show();
  }
  private String version() {
    try {
      return getPackageManager().getPackageInfo(getPackageName(), 0).versionName;
    } catch (Exception e) {
      return "alpha";
    }
  }
  private void toast(String s) {
    Toast.makeText(this, s, Toast.LENGTH_LONG).show();
  }
  private void textDialog(String name, String text) {
    ScrollView scroll = new ScrollView(this);
    TextView view = new TextView(this);
    view.setText(text);
    view.setTextIsSelectable(true);
    view.setPadding(dp(20), dp(12), dp(20), dp(12));
    scroll.addView(view);
    new AlertDialog.Builder(this)
        .setTitle(name)
        .setView(scroll)
        .setPositiveButton("Закрыть", null)
        .show();
  }
  private TextView title(LinearLayout root, String s, int size) {
    TextView t = new TextView(this);
    t.setText(s);
    t.setTextSize(size);
    t.setTextColor(INK);
    t.setPadding(0, dp(10), 0, dp(10));
    root.addView(t);
    return t;
  }
  private Button button(LinearLayout root, String s, Runnable action) {
    Button b = new Button(this);
    b.setText(s);
    b.setTextSize(15);
    b.setAllCaps(false);
    b.setTextColor(INK);
    b.setBackground(shape(CARD, 14));
    b.setMinHeight(dp(52));
    LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-1, -2);
    lp.topMargin = dp(10);
    root.addView(b, lp);
    b.setOnClickListener(v -> action.run());
    return b;
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
    getPreferences(0).edit().putInt("selected-route", route.getSelectedItemPosition() - 1).apply();
    startForegroundService(new Intent(this, Engine.class)
            .putExtra("command", cmd)
            .putExtra("route", route.getSelectedItemPosition() - 1));
  }
  @Override
  protected void onActivityResult(int request, int result, Intent data) {
    super.onActivityResult(request, result, data);
    if (request == 1 && result == RESULT_OK)
      command(pending);
  }
  @Override
  protected void onSaveInstanceState(Bundle state) {
    state.putString("page", page);
    super.onSaveInstanceState(state);
  }
  @Override
  public void onBackPressed() {
    if (!"home".equals(page)) {
      home();
      return;
    }
    super.onBackPressed();
  }
  @Override
  protected void onResume() {
    super.onResume();
    ui.removeCallbacks(refresh);
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
          else if (p.has("warning"))
            out.append("Подключение работает; скорость не измерена.\n");
          else
            out.append("Не прошёл проверку: ").append(p.optString("error")).append("\n");
          out.append("\n");
        }
      } catch (Exception ignored) {
      }
    return out.length() > 0 ? out.toString() : "Проверок ещё не было.";
  }
  /**
   * Lab automation accepts no secrets in Intents. ADB places a one-use token in app-private
   * storage.
   */
  private void handleDebug(Intent i) {
    if ((getApplicationInfo().flags & android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) == 0)
      return;
    if (i.hasExtra("lab-traffic-power"))
      getSharedPreferences("evgenium", 0)
          .edit()
          .putBoolean("lab-traffic-power", i.getBooleanExtra("lab-traffic-power", true))
          .commit();
    if (i.hasExtra("lab-wake"))
      getSharedPreferences("evgenium", 0)
          .edit()
          .putBoolean("lab-wake", i.getBooleanExtra("lab-wake", false))
          .commit();
    if (i.hasExtra("lab-dials")) {
      int dials = i.getIntExtra("lab-dials", 1);
      if (dials == 1 || dials == 3)
        getSharedPreferences("evgenium", 0).edit().putInt("lab-dials", dials).commit();
    }
    if (i.hasExtra("lab-batch")) {
      int batch = i.getIntExtra("lab-batch", 1);
      if (batch == 1 || batch == 10 || batch == 32)
        getSharedPreferences("evgenium", 0).edit().putInt("lab-batch", batch).commit();
    }
    if (i.hasExtra("lab-age")) {
      int age = i.getIntExtra("lab-age", 500);
      if (age == 500 || age == 1500 || age == 3000)
        getSharedPreferences("evgenium", 0).edit().putInt("lab-age", age).commit();
    }
    if (i.hasExtra("lab-send-buffer")) {
      int buffer = i.getIntExtra("lab-send-buffer", 0);
      if (buffer == 0 || buffer == 1048576 || buffer == 4194304)
        getSharedPreferences("evgenium", 0).edit().putInt("lab-send-buffer", buffer).commit();
    }
    if (i.hasExtra("lab-udp-port")) {
      int port = i.getIntExtra("lab-udp-port", 443);
      if (port == 443 || port == 24570)
        getSharedPreferences("evgenium", 0).edit().putInt("lab-udp-port", port).commit();
    }
    if (i.hasExtra("lab-forward"))
      getSharedPreferences("evgenium", 0)
          .edit()
          .putBoolean("lab-forward", i.getBooleanExtra("lab-forward", false))
          .commit();
    if (i.hasExtra("lab-private-speed"))
      getSharedPreferences("evgenium", 0)
          .edit()
          .putBoolean("lab-private-speed", i.getBooleanExtra("lab-private-speed", false))
          .commit();
    String cmd = i.getStringExtra("lab");
    i.removeExtra("lab"); // Do not repeat an ADB command when Android recreates the screen.
    if (cmd == null)
      return;
    if ("mobile-check".equals(cmd)) {
      CarrierLab.mobileCheck(this);
      return;
    }
    if ("packet-lab".equals(cmd)) {
      CarrierLab.start(this);
      return;
    }
    if ("fault".equals(cmd) || "heartbeat-fault".equals(cmd)) {
      if ("heartbeat-fault".equals(cmd))
        TunnelCarrier.debugHeartbeatFault(this);
      else
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
      route.setSelection(Math.max(0, Math.min(Engine.IDS.length, i.getIntExtra("route", -1) + 1)));
    if ("connect".equals(cmd) || "rank".equals(cmd))
      prepare(cmd);
    else if ("stop".equals(cmd) || "measure".equals(cmd))
      command(cmd);
  }
}
