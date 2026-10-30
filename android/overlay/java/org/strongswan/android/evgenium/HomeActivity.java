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
  private static final int BG = 0xff141217, CARD = 0xff211c24, INK = 0xfffff1e9, MUTED = 0xffbaa8af,
                           ACCENT = 0xffff586d;
  private TextView status, deviceName, diagnosticStatus, protectionStatus;
  private EditText token;
  private Spinner route;
  private PowerControl power;
  private Button runDiagnostic, tokenAction, updateAction;
  private boolean editingToken;
  private static volatile boolean enrollingToken;
  private boolean permissionPending;
  private static volatile int enrollmentRevision;
  private static volatile String enrollmentMessage = "";
  private int observedEnrollment;
  private String pending = "connect", page = "home";
  private final Handler ui = new Handler(Looper.getMainLooper());
  private final Runnable refresh = new Runnable() {
    public void run() {
      if (observedEnrollment != enrollmentRevision) {
        observedEnrollment = enrollmentRevision;
        if ("settings".equals(page)) settings();
        toast(enrollmentMessage);
      }
      if (protectionStatus != null) textIfChanged(protectionStatus, Protection.summary(HomeActivity.this));
      if (status != null)
        textIfChanged(status, Engine.status + ("home".equals(page) && Engine.running ? "\n" + Protection.summary(HomeActivity.this) : ""));
      if (power != null)
        power.state(Engine.verified, Engine.running);
      if (diagnosticStatus != null)
        textIfChanged(diagnosticStatus, DiagnosticReports.summary(HomeActivity.this));
      if (runDiagnostic != null) {
        runDiagnostic.setEnabled(!Engine.working() && !DiagnosticReports.sending);
        textIfChanged(runDiagnostic, DiagnosticReports.pendingUpload(HomeActivity.this)
                ? "Повторить отправку отчёта"
                : "Полная диагностика");
        runDiagnostic.setAlpha(runDiagnostic.isEnabled() ? 1f : .4f);
      }
      if (updateAction != null) { textIfChanged(updateAction, AppUpdates.status); updateAction.setEnabled(!AppUpdates.busy.get()); }
      if (tokenAction != null) {
        tokenAction.setEnabled(!enrollingToken);
        textIfChanged(tokenAction, enrollingToken ? "Проверяю…" : editingToken ? "Подтвердить" : "Изменить");
        if (token != null) token.setEnabled(editingToken && !enrollingToken);
        tokenAction.setAlpha(tokenAction.isEnabled() ? 1f : .4f);
      }
      ui.postDelayed(this, 1000);
    }
  };
  private static void textIfChanged(TextView view, String value) {
    if (!value.contentEquals(view.getText())) view.setText(value);
  }
  private int dp(float n) {
    return Math.round(n * getResources().getDisplayMetrics().density);
  }
  private GradientDrawable shape(int color, int radius) {
    GradientDrawable d = new GradientDrawable();
    d.setColor(color);
    d.setCornerRadius(dp(Math.min(radius, 8)));
    d.setStroke(dp(1), 0xff48303c);
    return d;
  }
  private LinearLayout column() {
    LinearLayout v = new LinearLayout(this);
    v.setOrientation(LinearLayout.VERTICAL);
    return v;
  }
  private LinearLayout frame(String title) {
    status = null;
    protectionStatus = null;
    power = null;
    deviceName = null;
    diagnosticStatus = null;
    runDiagnostic = null;
    tokenAction = null;
    updateAction = null;
    token = null;
    editingToken = false;
    getWindow().clearFlags(WindowManager.LayoutParams.FLAG_SECURE);
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
    brand.setText(title == null ? "EVGENIUM / NETWORK" : title);
    brand.setTextSize(title == null ? 15 : 22);
    brand.setTypeface(Typeface.create("sans-serif-medium", 0));
    brand.setTextColor(INK);
    if (title == null)
      brand.setLetterSpacing(.09f);
    brand.setPadding(dp(18), 0, 0, 0);
    header.addView(brand, new LinearLayout.LayoutParams(0, dp(52), 1));
    brand.setGravity(Gravity.CENTER_VERTICAL);
    root.addView(header);
    View rule = new View(this);
    rule.setBackgroundColor(ACCENT);
    LinearLayout.LayoutParams ruleParams = new LinearLayout.LayoutParams(dp(44), dp(3));
    ruleParams.topMargin = dp(16);
    root.addView(rule, ruleParams);
    return root;
  }
  @Override
  public void onCreate(Bundle state) {
    setTheme(org.strongswan.android.R.style.EvgeniumTheme);
    super.onCreate(state);
    getWindow().setStatusBarColor(BG);
    getWindow().setNavigationBarColor(BG);
    getWindow().getDecorView().setSystemUiVisibility(0);
    if (Build.VERSION.SDK_INT >= 33)
      getOnBackInvokedDispatcher().registerOnBackInvokedCallback(
          android.window.OnBackInvokedDispatcher.PRIORITY_DEFAULT, this::navigateBack);
    route = new Spinner(this);
    String[] options = new String[Engine.LABELS.length + 1];
    options[0] = "Автоматически по рейтингу";
    System.arraycopy(Engine.LABELS, 0, options, 1, Engine.LABELS.length);
    route.setAdapter(
        new ArrayAdapter<String>(this, android.R.layout.simple_spinner_dropdown_item, options));
    route.setSelection(Math.min(
        Engine.IDS.length, Math.max(0, getPreferences(0).getInt("selected-route", -1) + 1)));
    route.setOnItemSelectedListener(new AdapterView.OnItemSelectedListener() {
      public void onItemSelected(AdapterView<?> p, View v, int position, long id) {
        getPreferences(0).edit().putInt("selected-route", position - 1).apply();
      }
      public void onNothingSelected(AdapterView<?> p) {}
    });
    if (state != null) {
      pending = state.getString("pending", "connect");
      permissionPending = state.getBoolean("permission-pending", false);
    }
    observedEnrollment = state == null ? enrollmentRevision : state.getInt("enrollment-revision", enrollmentRevision);
    home();
    if (state != null && "settings".equals(state.getString("page")))
      settings();
    else if (state != null && "diagnostics".equals(state.getString("page")))
      settings();
    if (!getPreferences(0).getBoolean("notifications-asked", false) && Build.VERSION.SDK_INT >= 33
        && checkSelfPermission("android.permission.POST_NOTIFICATIONS")
            != getPackageManager().PERMISSION_GRANTED)
    {
      getPreferences(0).edit().putBoolean("notifications-asked", true).apply();
      requestPermissions(new String[] {"android.permission.POST_NOTIFICATIONS"}, 2);
    }
    handleDebug(getIntent());
    importReleaseToken(getIntent());
    notificationAction(getIntent());
  }
  private boolean enrolled() {
    try {
      return Credentials.profile(this).optString("identity").matches("device-[a-f0-9]{24}")
          && Credentials.key() != null
          && java.util.Arrays.equals(Credentials.certificate(this).getPublicKey().getEncoded(),
              Credentials.store().getCertificate(Credentials.ALIAS).getPublicKey().getEncoded());
    } catch (Exception e) { return false; }
  }
  private void home() {
    page = "home";
    LinearLayout root = frame(null);
    LinearLayout body = column();
    ScrollView homeScroll = new ScrollView(this);
    homeScroll.setFillViewport(true);
    homeScroll.addView(body);
    root.addView(homeScroll, new LinearLayout.LayoutParams(-1, 0, 1));
    power = new PowerControl(this);
    power.setContentDescription("Включить VPN");
    boolean landscape = getResources().getConfiguration().orientation
        == android.content.res.Configuration.ORIENTATION_LANDSCAPE;
    if (landscape)
      body.setOrientation(LinearLayout.HORIZONTAL);
    body.addView(power,
        landscape ? new LinearLayout.LayoutParams(0, dp(260), 6)
                  : new LinearLayout.LayoutParams(-1, dp(Math.max(220, getResources().getConfiguration().screenHeightDp * .50f))));
    power.state(Engine.verified, Engine.running);
    power.setOnClickListener(v -> {
      if (Engine.running) {
        requestStop();
        return;
      }
      if (enrollingToken) { toast("Дождитесь подтверждения токена"); return; }
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
        landscape ? new LinearLayout.LayoutParams(0, -2, 4)
                  : new LinearLayout.LayoutParams(-1, -2));
    TextView word = title(bottom, "СВЯЗЬ В ВАШЕМ РИТМЕ", 11);
    word.setLetterSpacing(.16f);
    word.setTextColor(ACCENT);
    LinearLayout card = column();
    card.setPadding(dp(20), dp(18), dp(20), dp(18));
    card.setBackground(shape(CARD, 22));
    bottom.addView(card, new LinearLayout.LayoutParams(-1, -2));
    title(card, "СОСТОЯНИЕ СОЕДИНЕНИЯ", 11).setTextColor(MUTED);
    status = title(card, Engine.status, 19);
    status.setAccessibilityLiveRegion(View.ACCESSIBILITY_LIVE_REGION_POLITE);
    title(bottom, "Тестовая версия · " + version(), 12).setTextColor(MUTED);
  }
  private void requestStop() {
    if (!Engine.running) return;
    if (Protection.lockdown(this)) {
      new AlertDialog.Builder(this).setTitle("Отключить VPN?")
        .setMessage("Android блокирует соединения без VPN. После отключения интернет останется заблокирован до подключения VPN или отключения блокировки в системных настройках.")
        .setNegativeButton("Остаться", null)
        .setPositiveButton("Отключить", (d,w) -> command("stop")).show();
    } else command("stop");
  }
  private void notificationAction(Intent intent) {
    if (intent == null) return;
    if (org.strongswan.android.ui.VpnProfileControlActivity.DISCONNECT.equals(intent.getAction())) {
      intent.setAction(null); requestStop();
    }
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
    editingToken = !enrolled();
    LinearLayout tokenRow = new LinearLayout(this);
    tokenRow.setGravity(Gravity.CENTER_VERTICAL);
    token = new EditText(this);
    token.setSingleLine(true);
    token.setTextSize(14);
    token.setTextColor(INK);
    token.setHintTextColor(MUTED);
    token.setHint(editingToken ? "Введите токен" : "Токен подтверждён");
    token.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
        | InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD);
    token.setFilters(new android.text.InputFilter[] {new android.text.InputFilter.LengthFilter(256)});
    token.setSaveEnabled(false);
    token.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO);
    token.setEnabled(editingToken);
    token.setPadding(dp(12), dp(8), dp(12), dp(8));
    token.setBackground(shape(CARD, 8));
    tokenRow.addView(token, new LinearLayout.LayoutParams(0, dp(54), 1));
    tokenAction = button(tokenRow, editingToken ? "Подтвердить" : "Изменить", () -> {
      if (enrollingToken)
        return;
      if (Engine.running || DiagnosticReports.sending) {
        toast("Сначала отключите VPN и дождитесь отправки отчёта"); return;
      }
      if (editingToken) {
        enroll();
        return;
      }
      try {
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        token.setText(Credentials.token(this));
        editingToken = true;
        token.setEnabled(true);
        tokenAction.setText("Подтвердить");
        token.requestFocus();
        token.setSelection(token.length());
      } catch (Exception e) {
        editingToken = true;
        token.setText("");
        token.setHint("Введите токен");
        token.setEnabled(true);
        tokenAction.setText("Подтвердить");
        token.requestFocus();
        toast("Сохранённый токен недоступен. Вставьте его заново.");
      }
    });
    tokenAction.setTextSize(13);
    tokenAction.setSingleLine(true);
    tokenAction.setPadding(dp(10), 0, dp(10), 0);
    LinearLayout.LayoutParams actionParams = new LinearLayout.LayoutParams(-2, dp(54));
    actionParams.leftMargin = dp(8);
    tokenAction.setLayoutParams(actionParams);
    c.addView(tokenRow, new LinearLayout.LayoutParams(-1, dp(54)));
    title(c, "Маршрут", 18);
    title(c, "Выбор применяется при следующем подключении. Автоматический режим быстро находит рабочий маршрут и сам восстанавливает соединение.", 13).setTextColor(MUTED);
    if (route.getParent() != null)
      ((android.view.ViewGroup) route.getParent()).removeView(route);
    c.addView(route, new LinearLayout.LayoutParams(-1, dp(54)));
    button(c, "Обновить рейтинг маршрутов", () -> confirmTests(false));
    button(c, "Результаты проверки маршрутов", () -> textDialog("Рейтинг маршрутов", results()));
    title(c, "ПОМОЧЬ УЛУЧШИТЬ VPN", 12).setTextColor(MUTED);
    runDiagnostic = button(c, "Полная диагностика", () -> {
      if (Engine.working() || DiagnosticReports.sending)
        return;
      if (DiagnosticReports.pendingUpload(this))
        DiagnosticReports.send(this);
      else
        confirmTests(true);
    });
    diagnosticStatus = title(c, DiagnosticReports.summary(this), 13);
    diagnosticStatus.setTextColor(MUTED);
    protectionStatus = title(c, Protection.summary(this), 13);
    protectionStatus.setTextColor(ACCENT);
    button(c, "Разрешить работу в фоне", () -> {
      android.os.PowerManager pm = getSystemService(android.os.PowerManager.class);
      if (pm.isIgnoringBatteryOptimizations(getPackageName())) { toast("Ограничение батареи уже снято"); return; }
      try { startActivity(new Intent(android.provider.Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS,
          android.net.Uri.parse("package:"+getPackageName()))); }
      catch(Exception e) { startActivity(new Intent(android.provider.Settings.ACTION_APPLICATION_DETAILS_SETTINGS,
          android.net.Uri.parse("package:"+getPackageName()))); }
    });
    button(c, "Системная защита VPN",
        () -> startActivity(new Intent("android.settings.VPN_SETTINGS")));
    title(c,
        "Для защиты при остановке приложения Android включите постоянный VPN и блокировку "
            + "соединений без VPN в системных настройках.",
        13)
        .setTextColor(MUTED);
    updateAction = button(c, AppUpdates.status, () -> AppUpdates.check(this));
    if ((getApplicationInfo().flags & android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0)
      button(c, "Перенести токен в релизную версию", this::exportReleaseToken);
    title(c, "Evgenium " + version() + " · strongSwan · GPLv2+", 12).setTextColor(MUTED);
  }
  private void exportReleaseToken() {
    try {
      android.content.pm.PackageInfo target = getPackageManager().getPackageInfo(UpdatePolicy.PACKAGE, AppUpdates.flags());
      if (!UpdatePolicy.SIGNER.equals(AppUpdates.signer(target))) throw new SecurityException();
      new AlertDialog.Builder(this).setTitle("Перенести доступ?")
        .setMessage("Токен будет передан установленной релизной версии Evgenium на этом телефоне. Затем подтвердите его там.")
        .setNegativeButton("Отмена", null).setPositiveButton("Перенести", (d,w) -> {
          try {
            startActivity(new Intent().setClassName(UpdatePolicy.PACKAGE, HomeActivity.class.getName())
              .putExtra("import-token", Credentials.token(this)));
          } catch(Exception e) { toast("Не удалось перенести токен"); }
        }).show();
    } catch(Exception e) { toast("Сначала установите подписанную релизную версию"); }
  }
  private void importReleaseToken(Intent intent) {
    if (!UpdatePolicy.PACKAGE.equals(getPackageName()) || intent == null) return;
    String value = intent.getStringExtra("import-token");
    intent.removeExtra("import-token");
    if (value == null || !value.matches("EVN1-[A-Za-z0-9_-]{43}")) return;
    if (enrolled() || Engine.running) { toast("Доступ уже настроен"); return; }
    new AlertDialog.Builder(this).setTitle("Перенести доступ из лабораторной версии?")
      .setMessage("Этот телефон зарегистрируется как новое устройство вашего пользователя.")
      .setNegativeButton("Отмена", null).setPositiveButton("Подтвердить", (d,w) -> {
        settings(); token.setText(value); enroll();
      }).show();
  }
  private void confirmTests(boolean diagnostic) {
    if (enrollingToken || Engine.working() || DiagnosticReports.sending) { toast("Дождитесь завершения текущей операции"); return; }
    if (!enrolled()) {
      toast("Сначала подтвердите токен в настройках");
      return;
    }
    new AlertDialog.Builder(this)
        .setTitle(diagnostic ? "Проверить и отправить отчёт?" : "Перепроверить маршруты?")
        .setMessage("Проверка займёт примерно 3–9 минут и обновит рейтинг. Во время переключений "
            + "возможны паузы связи. Расход — около 80 МБ, при повторах больше."
            + (diagnostic ? "\n\nПосле проверки автоматически отправим модель и версию Android, "
                        + "результаты скорости, DNS и пакетных проб, задержки, события VPN и "
                          + "технические счётчики. Сервер свяжет "
                        + "отчёт "
                        + "с сертификатом устройства. Токены, ключи, содержимое трафика и история "
                        + "посещений не передаются."
                          : ""))
        .setNegativeButton("Отмена", null)
        .setPositiveButton(diagnostic ? "Проверить и отправить" : "Начать",
            (d, w) -> prepare(diagnostic ? "diagnose-send" : "rank"))
        .show();
  }

  private void enroll() {
    if (DiagnosticReports.sending) { toast("Дождитесь отправки отчёта"); return; }
    if (Engine.running) {
      toast("Сначала отключите VPN");
      return;
    }
    if (enrollingToken)
      return;
    final EditText field = token;
    final String value;
    try { value = UserInput.token(field.getText().toString()); }
    catch (IllegalArgumentException e) { field.requestFocus(); field.setError(e.getMessage()); return; }
    final boolean hadAccess = enrolled();
    enrollingToken = true;
    tokenAction.setEnabled(false);
    tokenAction.setText("Проверяю…");
    field.setEnabled(false);
    new Thread(() -> {
      try {
        Credentials.enroll(getApplicationContext(), value);
        enrollmentMessage = "Токен подтверждён";
      } catch (Exception e) {
        android.util.Log.w("Evgenium", "enrollment_failed_"+e.getClass().getSimpleName());
        enrollmentMessage = "Не удалось подтвердить токен. Проверьте токен и подключение."
            + (hadAccess ? " Предыдущий доступ сохранён." : "");
      } finally {
        enrollingToken = false;
        enrollmentRevision++;
      }
    }).start();
  }
  private void rename() {
    if (enrollingToken) { toast("Дождитесь подтверждения токена"); return; }
    EditText field = new EditText(this);
    field.setSingleLine(true);
    field.setText(deviceName.getText());
    field.setFilters(new android.text.InputFilter[] {new android.text.InputFilter.LengthFilter(128)});
    AlertDialog dialog = new AlertDialog.Builder(this)
        .setTitle("Имя устройства")
        .setView(field)
        .setNegativeButton("Отмена", null)
        .setPositiveButton("Сохранить", null).create();
    dialog.setOnShowListener(ignored -> dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v -> {
      final String name;
      try { name = UserInput.name(field.getText().toString()); }
      catch (IllegalArgumentException e) { field.requestFocus(); field.setError(e.getMessage()); return; }
      dialog.getButton(AlertDialog.BUTTON_POSITIVE).setEnabled(false);
      new Thread(() -> {
        try {
          String value = Credentials.rename(getApplicationContext(), name);
          runOnUiThread(() -> {
            if (isDestroyed() || isFinishing()) return;
            if (deviceName != null) deviceName.setText(value);
            dialog.dismiss(); toast("Имя сохранено");
          });
        } catch (Exception e) {
          runOnUiThread(() -> {
            if (isDestroyed() || isFinishing()) return;
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setEnabled(true);
            field.setError("Не удалось сохранить. Проверьте соединение и повторите.");
          });
        }
      }).start();
    }));
    dialog.show();
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
    b.setPadding(dp(16), dp(12), dp(16), dp(12));
    b.setGravity(Gravity.CENTER_VERTICAL | Gravity.START);
    LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-1, -2);
    lp.topMargin = dp(10);
    root.addView(b, lp);
    b.setOnClickListener(v -> action.run());
    return b;
  }
  private void prepare(String cmd) {
    if (permissionPending || enrollingToken) return;
    pending = cmd;
    Intent permission = VpnService.prepare(this);
    if (permission != null) {
      permissionPending = true;
      startActivityForResult(permission, 1);
    } else
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
    if (request == 1) {
      permissionPending = false;
      if (result == RESULT_OK) command(pending);
      else toast("Разрешение VPN не выдано. Нажмите включение ещё раз и разрешите подключение.");
    }
  }
  @Override
  protected void onSaveInstanceState(Bundle state) {
    state.putString("page", page);
    state.putInt("enrollment-revision", observedEnrollment);
    state.putString("pending", pending);
    state.putBoolean("permission-pending", permissionPending);
    super.onSaveInstanceState(state);
  }
  @Override
  public void onBackPressed() { navigateBack(); }
  private void navigateBack() {
    if (!"home".equals(page)) home();
    else finish(); // leaving the screen does not stop the VPN service
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
    importReleaseToken(i);
    notificationAction(i);
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
        if (r.optBoolean("provisional", false)) {
          out.append("Быстрое подключение: скорость ещё не измерялась.\n");
          int last = getSharedPreferences("evgenium", 0).getInt("last-stable-" + kind, -1);
          if (last >= 0 && last < Engine.LABELS.length)
            out.append("Последний стабильный маршрут: ").append(Engine.LABELS[last]).append("\n");
          out.append("Подробные замеры доступны в полной диагностике.\n\n");
          continue;
        }
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
            out.append(UserMessages.connection(p.optString("error"))).append("\n");
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
    if ("renew-check".equals(cmd)) {
      new Thread(() -> {
        try { Credentials.enroll(this, Credentials.token(this)); android.util.Log.i("Evgenium", "renewal_check_ok"); }
        catch(Exception e) { android.util.Log.e("Evgenium", "renewal_check_failed_"+e.getClass().getSimpleName()); }
      }).start(); return;
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
