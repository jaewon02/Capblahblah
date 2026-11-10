package com.siem.alarm.rule;

import java.util.List;
import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;

public interface DetectionRuleRepository extends JpaRepository<DetectionRule, Long> {

    List<DetectionRule> findByDeletedAtIsNullOrderByRuleIdAsc();

    Optional<DetectionRule> findByRuleIdAndDeletedAtIsNull(Long ruleId);

    /** 탐지 엔진: 활성 규칙만 적용 (No 129). */
    List<DetectionRule> findByActiveTrueAndDeletedAtIsNull();
}
