package com.siem.alarm.common;

import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.ColumnTransformer;

/** TB_04 관리자 작업 이력. INSERT 전용 (DB 계정에 UPDATE/DELETE 권한 없음). */
@Entity
@Table(name = "admin_audit_log")
@Getter
@Setter
@NoArgsConstructor
public class AdminAuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long auditId;

    private Long userId;
    private String menu;
    private String action;
    private String targetTable;
    private String targetId;

    @ColumnTransformer(write = "?::jsonb")
    private String beforeValue;

    @ColumnTransformer(write = "?::jsonb")
    private String afterValue;

    private String summary;

    @ColumnTransformer(write = "?::inet")
    private String clientIp;

    private Instant createdAt;
}
