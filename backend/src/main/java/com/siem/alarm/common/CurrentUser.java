package com.siem.alarm.common;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

/**
 * 현재 요청의 관리자 정보.
 * TODO: WBS 3.2(로그인 · 인증 · 세션) 완료 후 admin_session 의 user_id 를 반환하도록 교체.
 *       그 전까지 admin_user 행이 없으므로 user_id 컬럼(created_by, actor_id 등)에는 NULL 이 기록된다.
 */
@Component
public class CurrentUser {

    /** admin_user.user_id. 로그인 연동 전에는 null. */
    public Long userId() {
        return null;
    }

    /** 요청 IP (admin_audit_log.client_ip). 요청 밖(스케줄러)에서는 null. */
    public String clientIp() {
        if (!(RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attrs)) {
            return null;
        }
        HttpServletRequest request = attrs.getRequest();
        return request.getRemoteAddr();
    }
}
