package com.siem.alarm.alert;

/** 경보 처리 상태: 미확인 → 확인 → 처리 완료 (No 147–148). 오탐 여부는 별도 컬럼. */
public enum AlertStatus {
    NEW, ACK, RESOLVED;

    /** 다음 단계. 처리 완료면 null. */
    public AlertStatus next() {
        return switch (this) {
            case NEW -> ACK;
            case ACK -> RESOLVED;
            case RESOLVED -> null;
        };
    }
}
