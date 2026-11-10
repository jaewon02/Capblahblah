package com.siem.alarm.code;

import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Sort;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** 규칙 등록 화면의 로그 유형 · 이벤트 유형 선택 목록. */
@RestController
@RequestMapping("/api/codes")
@RequiredArgsConstructor
public class CodeController {

    private final LogTypeRepository logTypes;
    private final EventTypeRepository eventTypes;

    @GetMapping("/log-types")
    public List<LogType> logTypes() {
        return logTypes.findAll(Sort.by("sortOrder", "logTypeCode"));
    }

    @GetMapping("/event-types")
    public List<EventType> eventTypes() {
        return eventTypes.findAll(Sort.by("logTypeCode", "eventTypeCode"));
    }
}
