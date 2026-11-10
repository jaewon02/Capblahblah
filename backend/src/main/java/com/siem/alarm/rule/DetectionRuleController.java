package com.siem.alarm.rule;

import jakarta.validation.Valid;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/rules")
@RequiredArgsConstructor
public class DetectionRuleController {

    private final DetectionRuleService service;

    @GetMapping
    public List<RuleResponse> list() {
        return service.list();
    }

    @GetMapping("/{ruleId}")
    public RuleResponse get(@PathVariable Long ruleId) {
        return service.get(ruleId);
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public RuleResponse create(@Valid @RequestBody RuleRequest req) {
        return service.create(req);
    }

    @PutMapping("/{ruleId}")
    public RuleResponse update(@PathVariable Long ruleId, @Valid @RequestBody RuleRequest req) {
        return service.update(ruleId, req);
    }

    @PatchMapping("/{ruleId}/active")
    public RuleResponse setActive(@PathVariable Long ruleId, @RequestBody ActiveRequest req) {
        return service.setActive(ruleId, req.active());
    }

    @DeleteMapping("/{ruleId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void delete(@PathVariable Long ruleId) {
        service.delete(ruleId);
    }

    public record ActiveRequest(boolean active) {
    }
}
