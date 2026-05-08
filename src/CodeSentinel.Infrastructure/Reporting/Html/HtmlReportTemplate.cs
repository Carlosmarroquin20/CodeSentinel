namespace CodeSentinel.Infrastructure.Reporting.Html;

// Template fragments for the HTML report. Kept as constants in a single place
// so the visual style can be reviewed independently of the writer logic.
internal static class HtmlReportTemplate
{
    public const string HeadStart = """
        <!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1">
          <title>CodeSentinel Security Report</title>
          <style>
        """;

    public const string HeadEnd = """
          </style>
        </head>
        """;

    public const string EmbeddedCss = """
        :root {
          --critical: #dc2626;
          --high: #ea580c;
          --medium: #ca8a04;
          --low: #2563eb;
          --info: #6b7280;
          --fg: #1f2937;
          --muted: #6b7280;
          --border: #e5e7eb;
          --bg-subtle: #f9fafb;
          --grade-a: #10b981;
          --grade-b: #84cc16;
          --grade-c: #eab308;
          --grade-d: #f97316;
          --grade-f: #dc2626;
        }
        * { box-sizing: border-box; }
        body {
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
          color: var(--fg);
          background: #ffffff;
          margin: 0;
          padding: 2rem;
          line-height: 1.5;
        }
        .container { max-width: 1200px; margin: 0 auto; }
        header {
          border-bottom: 1px solid var(--border);
          padding-bottom: 1rem;
          margin-bottom: 2rem;
        }
        header h1 { margin: 0 0 0.5rem 0; font-size: 1.875rem; font-weight: 600; }
        .meta { color: var(--muted); font-size: 0.875rem; }
        .meta span { margin-right: 1.5rem; }
        .summary {
          display: grid;
          grid-template-columns: auto 1fr;
          gap: 2rem;
          padding: 1.5rem;
          background: var(--bg-subtle);
          border: 1px solid var(--border);
          border-radius: 8px;
          margin-bottom: 2rem;
          align-items: center;
        }
        .score {
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          width: 120px;
          height: 120px;
          border-radius: 50%;
          color: #ffffff;
          font-weight: 600;
        }
        .score-A { background: var(--grade-a); }
        .score-B { background: var(--grade-b); }
        .score-C { background: var(--grade-c); }
        .score-D { background: var(--grade-d); }
        .score-F { background: var(--grade-f); }
        .score-value { font-size: 2.5rem; line-height: 1; }
        .score-grade { font-size: 0.875rem; opacity: 0.95; margin-top: 0.25rem; }
        .stats { display: flex; gap: 2.5rem; flex-wrap: wrap; }
        .stat-label {
          color: var(--muted);
          font-size: 0.75rem;
          text-transform: uppercase;
          letter-spacing: 0.05em;
          margin-bottom: 0.25rem;
        }
        .stat-value { font-size: 1.5rem; font-weight: 600; }
        .findings h2 { font-size: 1.25rem; margin: 0 0 1rem 0; }
        table { width: 100%; border-collapse: collapse; }
        th, td {
          text-align: left;
          padding: 0.75rem;
          border-bottom: 1px solid var(--border);
          vertical-align: top;
        }
        th {
          background: var(--bg-subtle);
          font-weight: 600;
          font-size: 0.75rem;
          color: var(--muted);
          text-transform: uppercase;
          letter-spacing: 0.05em;
        }
        .badge {
          display: inline-block;
          padding: 0.125rem 0.625rem;
          border-radius: 9999px;
          font-size: 0.6875rem;
          font-weight: 600;
          color: #ffffff;
          text-transform: uppercase;
          letter-spacing: 0.05em;
        }
        .badge-critical { background: var(--critical); }
        .badge-high { background: var(--high); }
        .badge-medium { background: var(--medium); }
        .badge-low { background: var(--low); }
        .badge-info { background: var(--info); }
        .rule-id { font-family: ui-monospace, "SF Mono", Consolas, monospace; font-size: 0.875rem; color: var(--muted); }
        .location { font-family: ui-monospace, "SF Mono", Consolas, monospace; font-size: 0.875rem; }
        .snippet {
          font-family: ui-monospace, "SF Mono", Consolas, monospace;
          background: #f3f4f6;
          padding: 0.5rem 0.75rem;
          border-radius: 4px;
          font-size: 0.8125rem;
          overflow-x: auto;
          white-space: pre;
          margin: 0;
        }
        .no-findings {
          text-align: center;
          padding: 3rem;
          background: #f0fdf4;
          border: 1px solid #86efac;
          border-radius: 8px;
          color: #166534;
        }
        """;
}
