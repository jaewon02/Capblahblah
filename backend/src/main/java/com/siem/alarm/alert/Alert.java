package com.siem.alarm.alert;

import com.siem.alarm.common.Severity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/** TB_18 경보. 생성은 AlertService(JDBC), 조회 · 상태 변경은 JPA. */
@Entity
@Table(name = "alert")
@Getter
@Setter
@NoArgsConstructor
public class Alert {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long alertId;

    private String alertNo;
    private Long threatId;

    @Enumerated(EnumType.STRING)
    private Severity severity;

    private String title;

    @Enumerated(EnumType.STRING)
    private AlertStatus status;

    @Column(name = "is_false_positive")
    private boolean falsePositive;

    /** [권장] */
    private Long assigneeId;
    /** [권장·확장] */
    private Long incidentId;

    private Instant createdAt;
    private Instant ackedAt;
    private Instant resolvedAt;
    private Instant updatedAt;
}
