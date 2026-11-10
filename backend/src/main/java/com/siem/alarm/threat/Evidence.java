package com.siem.alarm.threat;

/**
 * 탐지 근거 (threat_event.evidence JSONB). 명세서 예시 형식: {"cond":"≥10회/5분","observed":"318회/5분"}
 * 탐지 당시 조건을 스냅샷으로 남겨 규칙이 바뀌어도 설명 가능.
 */
public record Evidence(String cond, String observed) {
}
