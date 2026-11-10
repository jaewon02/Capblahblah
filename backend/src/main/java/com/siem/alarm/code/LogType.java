package com.siem.alarm.code;

import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.NoArgsConstructor;

/** TB_05 로그 유형 코드 */
@Entity
@Table(name = "log_type")
@Getter
@NoArgsConstructor
public class LogType {

    @Id
    private String logTypeCode;

    private String name;
    private short sortOrder;
}
