package com.siem.alarm.alert;

import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AlertHistoryRepository extends JpaRepository<AlertHistory, Long> {

    List<AlertHistory> findByAlertIdOrderByCreatedAtAscHistoryIdAsc(Long alertId);
}
