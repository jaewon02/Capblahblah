package com.siem.alarm.common;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuditService {

    /** admin_audit_log.action 값 (명세서: CREATE/UPDATE/DELETE/APPROVE/REJECT/LOCK/PASSWORD_CHANGE) */
    public static final String CREATE = "CREATE";
    public static final String UPDATE = "UPDATE";
    public static final String DELETE = "DELETE";

    private final AdminAuditLogRepository repository;
    private final ObjectMapper objectMapper;
    private final CurrentUser currentUser;

    /** 호출한 쪽 트랜잭션 안에서 기록된다. 업무 변경이 롤백되면 이력도 함께 롤백. */
    public void record(String menu, String action, String targetTable, Object targetId,
                       Object before, Object after, String summary) {
        AdminAuditLog log = new AdminAuditLog();
        log.setUserId(currentUser.userId());
        log.setMenu(menu);
        log.setAction(action);
        log.setTargetTable(targetTable);
        log.setTargetId(targetId == null ? null : String.valueOf(targetId));
        log.setBeforeValue(toJson(before));
        log.setAfterValue(toJson(after));
        log.setSummary(summary.length() > 500 ? summary.substring(0, 500) : summary);
        log.setClientIp(currentUser.clientIp());
        log.setCreatedAt(Instant.now());
        repository.save(log);
    }

    private String toJson(Object value) {
        if (value == null) return null;
        try {
            return objectMapper.writeValueAsString(value);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException(e);
        }
    }
}
