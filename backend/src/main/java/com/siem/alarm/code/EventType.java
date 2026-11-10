package com.siem.alarm.code;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.NoArgsConstructor;

/** TB_11 이벤트 유형 코드 */
@Entity
@Table(name = "event_type")
@Getter
@NoArgsConstructor
public class EventType {

    @Id
    private String eventTypeCode;

    private String name;
    private String logTypeCode;
    private String attackType;
    private String mitreTechnique;
    private String defaultSeverity;
}
