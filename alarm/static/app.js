// 화면 보조 스크립트. 없어도 기본 동작(조회 · 등록 · 처리)은 폼 전송으로 된다.
(function () {
  'use strict';

  // ───── 삭제 확인 ─────
  document.querySelectorAll('form[data-confirm]').forEach(function (form) {
    form.addEventListener('submit', function (e) {
      if (!window.confirm(form.dataset.confirm)) e.preventDefault();
    });
  });

  // ───── 오탐 지정: 사유 입력(선택), 취소하면 지정 안 함 ─────
  document.querySelectorAll('form[data-fp-prompt]').forEach(function (form) {
    form.addEventListener('submit', function (e) {
      var comment = window.prompt(form.dataset.fpPrompt, '');
      if (comment === null) {
        e.preventDefault();
        return;
      }
      form.elements.comment.value = comment;
    });
  });

  // ───── 탐지 결과: 행 클릭 시 상세로 이동 ─────
  document.querySelectorAll('tr[data-href]').forEach(function (tr) {
    tr.addEventListener('click', function (e) {
      if (e.target.closest('a')) return;
      window.location.href = tr.dataset.href;
    });
  });

  // ───── 규칙 등록 · 수정 폼 ─────
  var form = document.getElementById('rule-form');
  if (!form) return;

  var method = form.querySelector('[data-method]');
  var logType = form.querySelector('[data-log-type]');
  var eventType = form.querySelector('[data-event-type]');
  var groupBy = form.querySelector('[data-group-by]');
  var condList = form.querySelector('[data-cond-list]');
  var tplCond = document.getElementById('tpl-cond');
  var tplOpsNormal = document.getElementById('tpl-ops-normal');
  var tplOpsHour = document.getElementById('tpl-ops-hour');

  // 탐지 방식: 반복 행위면 시간 창 · 임계 횟수 표시, 그룹 기준 '자동' 숨김
  function applyMethod() {
    var threshold = method.value === 'THRESHOLD';
    form.querySelectorAll('[data-threshold-only]').forEach(function (el) { el.hidden = !threshold; });
    form.querySelectorAll('[data-threshold-only] input').forEach(function (el) { el.required = threshold; });
    var auto = groupBy.querySelector('[data-condition-only]');
    auto.hidden = threshold;
    auto.disabled = threshold;
    if (threshold && !groupBy.value) groupBy.value = 'SOURCE_IP';
  }
  method.addEventListener('change', applyMethod);

  // 로그 유형을 고르면 그 유형의 이벤트 유형만 표시
  function filterEventTypes() {
    Array.prototype.forEach.call(eventType.options, function (opt) {
      if (!opt.dataset.logType) return;
      var visible = !logType.value || opt.dataset.logType === logType.value;
      opt.hidden = !visible;
      opt.disabled = !visible;
    });
  }
  logType.addEventListener('change', function () {
    eventType.value = '';
    filterEventTypes();
  });

  // 추가 조건
  function setupRow(row) {
    var field = row.querySelector('[data-cond-field]');
    var op = row.querySelector('[data-cond-op]');
    var value = row.querySelector('[data-cond-value]');
    var extra = row.querySelector('[data-cond-extra]');

    function placeholder() {
      value.placeholder = op.value.indexOf('between') >= 0 ? '9-18' : op.value === 'in' ? 'a, b, c' : '값';
    }
    function showExtra() {
      var on = field.value === 'extra.';
      extra.hidden = !on;
      extra.required = on;
    }
    field.addEventListener('change', function () {
      var hour = field.value === 'event_time';
      var wasHour = op.querySelector('option[value^="hour_"]') !== null;
      if (hour !== wasHour || hour) {
        op.innerHTML = (hour ? tplOpsHour : tplOpsNormal).innerHTML;
        op.value = hour ? 'hour_not_between' : 'eq';
        value.value = hour ? '9-18' : '';
      }
      showExtra();
      placeholder();
    });
    op.addEventListener('change', placeholder);
    row.querySelector('[data-cond-remove]').addEventListener('click', function () { row.remove(); });
    showExtra();
  }

  condList.querySelectorAll('.cond').forEach(setupRow);
  form.querySelector('[data-cond-add]').addEventListener('click', function () {
    var frag = tplCond.content.cloneNode(true);
    var row = frag.querySelector('.cond');
    condList.appendChild(frag);
    setupRow(row);
  });

  applyMethod();
  filterEventTypes();

  // 저장 실패로 폼이 다시 그려졌으면 오류 문구가 보이도록 폼으로 이동
  var formError = form.querySelector('.error');
  if (formError) formError.scrollIntoView({ block: 'center' });
})();
