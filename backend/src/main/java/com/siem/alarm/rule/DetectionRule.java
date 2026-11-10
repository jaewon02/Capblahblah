package com.siem.alarm.rule;

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
import org.hibernate.annotations.ColumnTransformer;

/** TB_14 탐지 규칙 */
@Entity
@Table(name = "detection_rule")
@Getter
@Setter
@NoArgsConstructor
public class DetectionRule {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long ruleId;

    private String name;
    private String description;

    @Enumerated(EnumType.STRING)
    private DetectMethod detectMethod;

    private String logTypeCode;
    private String eventTypeCode;

    @ColumnTransformer(write = "?::jsonb")
    private String conditionExpr;

    /** SOURCE_IP / USER_ACCOUNT / TARGET */
    private String groupBy;

    private Integer timeWindowSec;
    private Integer thresholdCount;

    @Enumerated(EnumType.STRING)
    private Severity severity;

    private int suppressSec;

    @ColumnTransformer(write = "?::jsonb")
    private String exceptions;

    private String mitreTechnique;

    @Column(name = "is_active")
    private boolean active;

    private int version;
    private Long createdBy;
    private Long updatedBy;
    private Instant createdAt;
    private Instant updatedAt;
    private Instant deletedAt;
}
