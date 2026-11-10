package com.siem.alarm.rule;

public enum DetectMethod {
    /** 조건 기반 탐지: 이벤트 1건이 조건에 일치하면 바로 탐지 (No 131–132). */
    CONDITION,
    /** 반복 행위 탐지: 시간 창 안에서 같은 대상의 이벤트가 임계 횟수 이상이면 탐지 (No 133–134). */
    THRESHOLD
}
