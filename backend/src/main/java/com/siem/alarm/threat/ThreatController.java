package com.siem.alarm.threat;

import com.siem.alarm.common.PageResponse;
import com.siem.alarm.common.Severity;
import com.siem.alarm.threat.ThreatDtos.ThreatDetail;
import com.siem.alarm.threat.ThreatDtos.ThreatItem;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/threats")
@RequiredArgsConstructor
public class ThreatController {

    private final ThreatService service;

    @GetMapping
    public PageResponse<ThreatItem> search(
            @RequestParam(required = false) Long ruleId,
            @RequestParam(required = false) Severity severity,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size) {
        return service.search(ruleId, severity, page, size);
    }

    @GetMapping("/{threatId}")
    public ThreatDetail detail(@PathVariable Long threatId) {
        return service.detail(threatId);
    }
}
