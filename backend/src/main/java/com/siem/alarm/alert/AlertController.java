package com.siem.alarm.alert;

import com.siem.alarm.alert.AlertDtos.AlertResponse;
import com.siem.alarm.alert.AlertDtos.AlertSearch;
import com.siem.alarm.alert.AlertDtos.AlertSummary;
import com.siem.alarm.alert.AlertDtos.FalsePositiveRequest;
import com.siem.alarm.alert.AlertDtos.StatusRequest;
import com.siem.alarm.common.PageResponse;
import com.siem.alarm.common.Severity;
import jakarta.validation.Valid;
import java.time.LocalDate;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/alerts")
@RequiredArgsConstructor
public class AlertController {

    private final AlertService service;

    /** 예: GET /api/alerts?status=NEW&severity=HIGH&from=2026-11-23&to=2026-11-24 (날짜는 KST) */
    @GetMapping
    public PageResponse<AlertResponse> search(
            @RequestParam(required = false) AlertStatus status,
            @RequestParam(required = false) Boolean falsePositive,
            @RequestParam(required = false) Severity severity,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate from,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate to,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size) {
        return service.search(new AlertSearch(status, falsePositive, severity, from, to), page, size);
    }

    @GetMapping("/summary")
    public AlertSummary summary(
            @RequestParam(required = false) Severity severity,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate from,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate to) {
        return service.summary(new AlertSearch(null, null, severity, from, to));
    }

    @GetMapping("/{alertId}")
    public AlertResponse get(@PathVariable Long alertId) {
        return service.get(alertId);
    }

    @GetMapping("/{alertId}/history")
    public List<AlertHistory> history(@PathVariable Long alertId) {
        return service.histories(alertId);
    }

    @PatchMapping("/{alertId}/status")
    public AlertResponse changeStatus(@PathVariable Long alertId, @Valid @RequestBody StatusRequest req) {
        return service.changeStatus(alertId, req.status());
    }

    @PatchMapping("/{alertId}/false-positive")
    public AlertResponse setFalsePositive(@PathVariable Long alertId, @Valid @RequestBody FalsePositiveRequest req) {
        return service.setFalsePositive(alertId, req.falsePositive(), req.comment());
    }
}
