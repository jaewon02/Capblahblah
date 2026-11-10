package com.siem.alarm.threat;

import com.siem.alarm.common.Severity;
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
import org.hibernate.annotations.ColumnTransformer;

/** TB_15 위협 이벤트(탐지 결과). 생성은 ThreatService(JDBC), 조회는 JPA. */
@Entity
@Table(name = "threat_event")
@Getter
@Setter
@NoArgsConstructor
public class ThreatEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long threatId;

    private String threatNo;
    private Long ruleId;
    private int ruleVersion;
    private Instant detectedAt;
    private Instant firstEventTime;
    private Instant lastEventTime;
    private String groupKey;

    @ColumnTransformer(read = "host(source_ip)", write = "?::inet")
    private String sourceIp;

    private String userAccount;
    private Long targetId;
    private String logTypeCode;
    private int eventCount;

    @Enumerated(EnumType.STRING)
    private Severity severity;

    @Enumerated(EnumType.STRING)
    private Severity originalSeverity;

    @ColumnTransformer(write = "?::jsonb")
    private String evidence;

    private String cause;
    private String flowSummary;
    private Instant summaryGeneratedAt;
}
