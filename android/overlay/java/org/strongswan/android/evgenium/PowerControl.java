/* SPDX-License-Identifier: GPL-2.0-or-later */
package org.strongswan.android.evgenium;
import android.content.Context;
import android.graphics.*;
import android.view.View;
import android.view.accessibility.AccessibilityNodeInfo;
/** Native, resolution-independent control with a full-size accessible touch target. */
final class PowerControl extends View {
  private final Paint p = new Paint(Paint.ANTI_ALIAS_FLAG);
  private String label = "Включить", hint = "Нажмите для подключения";
  private boolean connected;
  PowerControl(Context c) {
    super(c);
    setClickable(true);
    setFocusable(true);
    setImportantForAccessibility(IMPORTANT_FOR_ACCESSIBILITY_YES);
  }
  void state(boolean on, boolean running) {
    String next = on ? "Отключить" : running ? "Отменить" : "Включить";
    String sub = on ? "Соединение защищено"
        : running   ? "Устанавливаем соединение"
                    : "Нажмите для подключения";
    if (next.equals(label) && sub.equals(hint))
      return;
    connected = on;
    label = next;
    hint = sub;
    setContentDescription(label + " VPN");
    invalidate();
  }
  @Override
  public void onInitializeAccessibilityNodeInfo(AccessibilityNodeInfo n) {
    super.onInitializeAccessibilityNodeInfo(n);
    n.setClassName("android.widget.Button");
    n.setText(label + " VPN");
  }
  @Override
  public boolean performClick() {
    super.performClick();
    return true;
  }
  @Override
  protected void onDraw(Canvas c) {
    super.onDraw(c);
    float cx = getWidth() / 2f, cy = getHeight() / 2f;
    float radius = Math.min(getWidth() * .45f, getHeight() * .46f), scale = radius / 150f;
    p.setStyle(Paint.Style.STROKE);
    p.setStrokeWidth(1.5f * scale);
    p.setColor(Color.rgb(48, 66, 51));
    c.drawCircle(cx, cy, radius, p);
    c.drawCircle(cx, cy, radius - 12 * scale, p);
    p.setStyle(Paint.Style.FILL);
    p.setColor(isPressed() ? Color.rgb(169, 222, 121)
            : connected    ? Color.rgb(187, 240, 139)
                           : Color.rgb(32, 47, 35));
    c.drawCircle(cx, cy, radius - 24 * scale, p);
    int ink = connected ? Color.rgb(25, 43, 23) : Color.rgb(187, 240, 139);
    p.setColor(ink);
    p.setStyle(Paint.Style.STROKE);
    p.setStrokeWidth(5 * scale);
    p.setStrokeCap(Paint.Cap.ROUND);
    float y = cy - 25 * scale, r = 29 * scale;
    c.drawArc(new RectF(cx - r, y - r, cx + r, y + r), -48, 276, false, p);
    c.drawLine(cx, y - 39 * scale, cx, y - 5 * scale, p);
    p.setStyle(Paint.Style.FILL);
    p.setTypeface(Typeface.create("sans-serif-medium", Typeface.NORMAL));
    p.setTextAlign(Paint.Align.CENTER);
    p.setTextSize(23 * scale);
    c.drawText(label, cx, cy + 44 * scale, p);
    p.setTypeface(Typeface.create("sans-serif", Typeface.NORMAL));
    p.setTextSize(10.5f * scale);
    c.drawText(hint, cx, cy + 68 * scale, p);
  }
  @Override
  protected void drawableStateChanged() {
    super.drawableStateChanged();
    invalidate();
  }
}
