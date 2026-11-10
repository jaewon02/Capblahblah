package com.siem.alarm.common;

/** 위험 등급. 선언 순서가 낮음 → 높음 순서이므로 ordinal()로 비교한다. */
public enum Severity {
    INFO, LOW, MEDIUM, HIGH, CRITICAL;

    public boolean atLeast(Severity other) {
        return this.ordinal() >= other.ordinal();
    }

    public static Severity max(Severity a, Severity b) {
        if (a == null) return b;
        if (b == null) return a;
        return a.atLeast(b) ? a : b;
    }
}
