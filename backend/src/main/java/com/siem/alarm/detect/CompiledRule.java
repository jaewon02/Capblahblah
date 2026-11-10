package com.siem.alarm.detect;

import com.fasterxml.jackson.databind.JsonNode;
import com.siem.alarm.rule.ConditionCodec;
import com.siem.alarm.rule.DetectionRule;
import com.siem.alarm.rule.RuleCondition;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** 탐지 1회 실행 동안 쓰도록 조건 · 정규식을 미리 컴파일한 규칙. */
final class CompiledRule {

    private static final Pattern RANGE = Pattern.compile("\\s*(-?\\d+)\\s*-\\s*(-?\\d+)\\s*");
    private static final Set<String> IP_FIELDS = Set.of("source_ip", "dest_ip");
    private static final Pattern IP_LITERAL = Pattern.compile("[0-9a-fA-F:.]+(/\\d{1,3})?");

    private final DetectionRule rule;
    private final List<RuleCondition> conditions;
    private final List<Predicate<EventView>> conditionTests;
    private final List<Predicate<EventView>> exceptionTests;

    private CompiledRule(DetectionRule rule, List<RuleCondition> conditions, Map<String, List<String>> exceptions) {
        this.rule = rule;
        this.conditions = conditions;
        this.conditionTests = conditions.stream().map(CompiledRule::compile).toList();
        this.exceptionTests = exceptions.entrySet().stream()
                .map(e -> compileException(e.getKey(), e.getValue()))
                .toList();
    }

    static CompiledRule of(DetectionRule rule, ConditionCodec codec) {
        return new CompiledRule(rule, codec.readConditions(rule.getConditionExpr()),
                codec.readExceptions(rule.getExceptions()));
    }

    DetectionRule rule() {
        return rule;
    }

    List<RuleCondition> conditions() {
        return conditions;
    }

    /** 이벤트 유형 · 로그 유형 · 조건이 모두 일치하고, 예외 조건에 하나도 걸리지 않으면 true. */
    boolean matches(EventView e) {
        if (rule.getEventTypeCode() != null && !rule.getEventTypeCode().equals(e.event().eventTypeCode())) {
            return false;
        }
        if (rule.getLogTypeCode() != null && !rule.getLogTypeCode().equals(e.event().logTypeCode())) {
            return false;
        }
        for (Predicate<EventView> test : conditionTests) {
            if (!test.test(e)) return false;
        }
        for (Predicate<EventView> exception : exceptionTests) {
            if (exception.test(e)) return false;
        }
        return true;
    }

    /**
     * 그룹 키 (threat_event.group_key, 명세서 예: 203.0.113.47 / deploy@db-01).
     * SOURCE_IP → 출발지 IP, USER_ACCOUNT → 계정@호스트, TARGET → 호스트명.
     * 그룹 기준이 없는 조건 기반 규칙은 호스트명 → 출발지 IP 순으로 사용.
     */
    String groupKey(EventView e) {
        String group = rule.getGroupBy();
        if (group == null) {
            String host = e.value("host_name");
            return host != null ? host : e.value("source_ip");
        }
        return switch (group) {
            case "SOURCE_IP" -> e.value("source_ip");
            case "USER_ACCOUNT" -> {
                String user = e.value("user_account");
                String host = e.value("host_name");
                yield user == null ? null : host == null ? user : user + "@" + host;
            }
            case "TARGET" -> {
                String host = e.value("host_name");
                yield host != null ? host : "target-" + e.value("target_id");
            }
            default -> null;
        };
    }

    private static Predicate<EventView> compile(RuleCondition c) {
        String field = c.field();
        String expected = c.text();
        return switch (c.op()) {
            case "eq" -> e -> expected != null && expected.equals(e.value(field));
            case "ne" -> e -> expected != null && !expected.equals(e.value(field));
            case "contains" -> e -> {
                String v = e.value(field);
                return v != null && expected != null && v.contains(expected);
            };
            case "regex" -> {
                Pattern p = Pattern.compile(expected == null ? "" : expected);
                yield e -> {
                    String v = e.value(field);
                    return v != null && p.matcher(v).find();
                };
            }
            case "in" -> {
                Set<String> set = new HashSet<>();
                JsonNode value = c.value();
                if (value != null && value.isArray()) value.forEach(n -> set.add(n.asText()));
                yield e -> set.contains(e.value(field));
            }
            case "between", "not_between" -> {
                int[] range = range(expected);
                boolean inside = c.op().equals("between");
                yield e -> {
                    Integer n = toInt(e.value(field));
                    return n != null && inside == (n >= range[0] && n < range[1]);
                };
            }
            case "hour_between", "hour_not_between" -> {
                int[] range = range(expected);
                boolean inside = c.op().equals("hour_between");
                // 반열림 구간 [lo, hi): "9-18" → 09:00 ~ 17:59 (KST)
                yield e -> {
                    int h = e.hourKst();
                    return inside == (h >= range[0] && h < range[1]);
                };
            }
            default -> throw new IllegalArgumentException("지원하지 않는 연산자: " + c.op());
        };
    }

    /** 예외 조건: 필드 값이 목록 중 하나와 같으면(IP 필드는 CIDR 포함) 탐지 제외. */
    private static Predicate<EventView> compileException(String field, List<String> values) {
        boolean ip = IP_FIELDS.contains(field);
        return e -> {
            String v = e.value(field);
            if (v == null) return false;
            for (String candidate : values) {
                if (ip ? ipMatches(v, candidate) : candidate.equals(v)) return true;
            }
            return false;
        };
    }

    private static boolean ipMatches(String ip, String cidrOrIp) {
        // IP 리터럴만 비교 (호스트명이면 InetAddress 가 DNS 조회를 하므로 제외)
        if (!IP_LITERAL.matcher(ip).matches() || !IP_LITERAL.matcher(cidrOrIp).matches()) return false;
        try {
            int slash = cidrOrIp.indexOf('/');
            byte[] addr = InetAddress.getByName(ip).getAddress();
            byte[] net = InetAddress.getByName(slash < 0 ? cidrOrIp : cidrOrIp.substring(0, slash)).getAddress();
            if (addr.length != net.length) return false;
            int bits = slash < 0 ? addr.length * 8 : Integer.parseInt(cidrOrIp.substring(slash + 1));
            for (int i = 0; i < addr.length && bits > 0; i++, bits -= 8) {
                int mask = bits >= 8 ? 0xFF : (0xFF << (8 - bits)) & 0xFF;
                if ((addr[i] & mask) != (net[i] & mask)) return false;
            }
            return true;
        } catch (UnknownHostException | NumberFormatException e) {
            return false;
        }
    }

    private static int[] range(String text) {
        Matcher m = RANGE.matcher(text == null ? "" : text);
        if (!m.matches()) throw new IllegalArgumentException("범위 형식 오류: " + text);
        return new int[] {Integer.parseInt(m.group(1)), Integer.parseInt(m.group(2))};
    }

    private static Integer toInt(String s) {
        if (s == null) return null;
        try {
            return Integer.parseInt(s.trim());
        } catch (NumberFormatException e) {
            return null;
        }
    }
}
