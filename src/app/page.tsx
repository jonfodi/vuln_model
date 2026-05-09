import { ArrowRight, ShieldAlert, SignalHigh, Wrench } from "lucide-react";
import Link from "next/link";
import { SearchBox } from "@/components/search-box";

const feedItems = [
  {
    label: "Act Now",
    title: "Known exploited vulnerabilities",
    description:
      "Issues with KEV status, public exploit evidence, strong impact, or urgent fix paths.",
    icon: ShieldAlert,
  },
  {
    label: "Investigate",
    title: "Conditional exploitability",
    description:
      "Serious vulnerabilities where reachability, configuration, or source disagreement matters.",
    icon: SignalHigh,
  },
  {
    label: "Fix Paths",
    title: "Affected ranges and remediation",
    description:
      "Version ranges, fixed releases, patches, workarounds, and the evidence behind each claim.",
    icon: Wrench,
  },
];

const examples = ["CVE-2021-44228", "react", "next", "vercel", "lodash"];

export default function Home() {
  return (
    <main className="mx-auto flex min-h-screen w-full max-w-6xl flex-col gap-10 px-5 py-8 sm:px-8">
      <header className="flex items-center justify-between gap-4 border-b border-stone-300 pb-5">
        <div>
          <p className="text-sm font-semibold uppercase tracking-[0.14em] text-emerald-700">
            Vulnerability Intelligence
          </p>
          <h1 className="mt-2 text-3xl font-semibold text-stone-950 sm:text-4xl">
            Search what matters, then inspect the evidence.
          </h1>
        </div>
        <Link
          href="/vulnerability/CVE-2021-44228"
          className="hidden items-center gap-2 rounded-md border border-stone-300 bg-white px-4 py-2 text-sm font-medium text-stone-900 shadow-sm transition hover:bg-stone-100 sm:flex"
        >
          Sample page
          <ArrowRight className="h-4 w-4" aria-hidden="true" />
        </Link>
      </header>

      <section className="grid gap-5 lg:grid-cols-[minmax(0,1fr)_320px]">
        <div className="flex flex-col gap-5">
          <SearchBox />
          <div className="flex flex-wrap gap-2">
            {examples.map((example) => (
              <Link
                href={`/vulnerability/${encodeURIComponent(example)}`}
                key={example}
                className="rounded-md border border-stone-300 bg-white px-3 py-1.5 text-sm text-stone-700 transition hover:border-stone-500 hover:text-stone-950"
              >
                {example}
              </Link>
            ))}
          </div>
        </div>

        <aside className="rounded-md border border-stone-300 bg-white p-4 shadow-sm">
          <p className="text-sm font-semibold text-stone-950">MVP Slice</p>
          <p className="mt-2 text-sm leading-6 text-stone-600">
            First target: a decision-grade vulnerability page that combines
            affected software, exploit signals, likely outcomes, fixes, source
            comparison, and evidence.
          </p>
        </aside>
      </section>

      <section className="grid gap-4 md:grid-cols-3">
        {feedItems.map((item) => {
          const Icon = item.icon;

          return (
            <article
              key={item.label}
              className="rounded-md border border-stone-300 bg-white p-5 shadow-sm"
            >
              <div className="flex items-center gap-3">
                <div className="rounded-md border border-emerald-200 bg-emerald-50 p-2 text-emerald-700">
                  <Icon className="h-5 w-5" aria-hidden="true" />
                </div>
                <span className="text-xs font-semibold uppercase tracking-[0.14em] text-emerald-700">
                  {item.label}
                </span>
              </div>
              <h2 className="mt-4 text-lg font-semibold text-stone-950">
                {item.title}
              </h2>
              <p className="mt-2 text-sm leading-6 text-stone-600">
                {item.description}
              </p>
            </article>
          );
        })}
      </section>
    </main>
  );
}

