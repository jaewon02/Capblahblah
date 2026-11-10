export default function Placeholder({ title, wbs }) {
  return (
    <>
      <header className="page-head">
        <div>
          <h1>{title}</h1>
          <div className="muted sub">WBS {wbs} 담당 화면 — 준비 중</div>
        </div>
      </header>
    </>
  );
}
