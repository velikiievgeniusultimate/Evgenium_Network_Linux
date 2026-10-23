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
    float scale = Math.min(getWidth() / 370f, getHeight() / 370f);
    c.save();
    c.translate(cx, cy);
    c.scale(scale, scale);
    // Tapered helical coils: bright front turns and burgundy return faces.
    for (int side : new int[] {-1, 1}) {
      c.save();
      c.scale(side, 1);
      c.translate(-174, -156);
      c.scale(1.35f, 2.65f);
      Path coil = new Path();
      coil.reset();
      coil.moveTo(10, 6);
      coil.cubicTo(-4, 17, 1, 29, 12, 38);
      coil.cubicTo(4, 52, 13, 63, 22, 70);
      coil.cubicTo(17, 82, 28, 98, 34, 112);
      coil.cubicTo(37, 95, 44, 82, 37, 68);
      coil.cubicTo(48, 55, 49, 46, 41, 36);
      coil.cubicTo(58, 13, 40, -4, 10, 6);
      coil.close();
      p.setStyle(Paint.Style.FILL);
      p.setColor(0xff702a40);
      c.drawPath(coil, p);
      coil.reset();
      coil.moveTo(44, 7);
      coil.cubicTo(10, -4, -8, 12, 8, 27);
      coil.cubicTo(15, 34, 32, 38, 41, 43);
      coil.lineTo(46, 31);
      coil.cubicTo(33, 24, 13, 22, 12, 15);
      coil.cubicTo(18, 9, 31, 8, 44, 7);
      coil.close();
      p.setStyle(Paint.Style.FILL);
      p.setColor(connected ? 0xffff586d : 0xffb74661);
      c.drawPath(coil, p);
      coil.reset();
      coil.moveTo(5, 26);
      coil.cubicTo(-3, 44, 13, 53, 34, 59);
      coil.cubicTo(38, 61, 40, 64, 41, 67);
      coil.lineTo(45, 53);
      coil.cubicTo(31, 44, 10, 42, 11, 34);
      coil.close();
      p.setStyle(Paint.Style.FILL);
      p.setColor(connected ? 0xffff586d : 0xffb74661);
      c.drawPath(coil, p);
      coil.reset();
      coil.moveTo(12, 51);
      coil.cubicTo(8, 67, 21, 77, 33, 80);
      coil.lineTo(38, 90);
      coil.lineTo(41, 75);
      coil.cubicTo(30, 66, 19, 63, 18, 58);
      coil.close();
      p.setStyle(Paint.Style.FILL);
      p.setColor(connected ? 0xffff586d : 0xffb74661);
      c.drawPath(coil, p);
      coil.reset();
      coil.moveTo(22, 76);
      coil.cubicTo(20, 89, 31, 101, 34, 112);
      coil.lineTo(39, 93);
      coil.cubicTo(31, 88, 29, 83, 29, 81);
      coil.close();
      p.setStyle(Paint.Style.FILL);
      p.setColor(connected ? 0xffff586d : 0xffb74661);
      c.drawPath(coil, p);
      coil.reset();
      coil.moveTo(39, 8);
      coil.cubicTo(21, 3, 4, 11, 8, 20);
      coil.moveTo(7, 34);
      coil.cubicTo(7, 43, 23, 48, 34, 52);
      coil.moveTo(16, 60);
      coil.cubicTo(17, 67, 27, 71, 33, 73);
      p.setStyle(Paint.Style.STROKE);
      p.setStrokeWidth(.7f);
      p.setColor(0xffffacb8);
      c.drawPath(coil, p);
      c.restore();
    }
    p.setStyle(Paint.Style.FILL);
    p.setColor(isPressed() ? 0xff492533 : connected ? 0xff371d2a : 0xff211c24);
    c.drawCircle(0, -12, 112, p);
    p.setStyle(Paint.Style.STROKE);
    p.setStrokeWidth(1.2f);
    p.setColor(connected ? 0xffff586d : 0xff754052);
    c.drawCircle(0, -12, 112, p);
    p.setStrokeWidth(3);
    c.drawArc(new RectF(-121, -133, 121, 109), -112, 44, false, p);
    c.drawArc(new RectF(-121, -133, 121, 109), 68, 44, false, p);
    p.setColor(0xfffff1e9);
    p.setStrokeWidth(4);
    p.setStrokeCap(Paint.Cap.ROUND);
    c.drawArc(new RectF(-27, -66, 27, -12), -48, 276, false, p);
    c.drawLine(0, -76, 0, -44, p);
    p.setStyle(Paint.Style.FILL);
    p.setTypeface(Typeface.create("sans-serif-medium", Typeface.NORMAL));
    p.setTextAlign(Paint.Align.CENTER);
    p.setTextSize(25);
    c.drawText(label, 0, 36, p);
    p.setTypeface(Typeface.create("sans-serif", Typeface.NORMAL));
    p.setTextSize(10.5f);
    p.setColor(0xffd0b5bf);
    c.drawText(hint, 0, 59, p);
    p.setColor(connected ? 0xffa6d8c2 : 0xffbaa8af);
    c.drawCircle(0, 86, 3, p);
    p.setTypeface(Typeface.create("monospace", Typeface.NORMAL));
    p.setTextSize(10);
    p.setColor(0xffbaa8af);
    c.drawText("E V G E N I U M", 0, 164, p);
    c.restore();
  }
  @Override
  protected void drawableStateChanged() {
    super.drawableStateChanged();
    invalidate();
  }
}
