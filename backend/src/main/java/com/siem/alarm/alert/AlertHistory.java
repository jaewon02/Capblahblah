package com.siem.alarm.alert;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** TB_19 경보 처리 이력. 상태 변경 · 오탐 지정/해제 내역 (No 148, 150). */
@Entity
@Table(name = "alert_history")
@Getter
@Setter
@NoArgsConstructor
public class AlertHistory {

    /** action 값 (명세서: STATUS/FALSE_POSITIVE/ASSIGN/COMMENT) */
    public static final String ACTION_STATUS = "STATUS";
    public static final String ACTION_FALSE_POSITIVE = "FALSE_POSITIVE";

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long historyId;

    private Long alertId;
    private String action;
    private String fromValue;
    private String toValue;
    private String comment;
    /** 시스템 자동이면 NULL */
    private Long actorId;
    private Instant createdAt;
}
