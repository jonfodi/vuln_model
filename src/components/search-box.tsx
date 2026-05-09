"use client";

import { Search } from "lucide-react";
import { useRouter } from "next/navigation";
import { FormEvent, useState } from "react";

export function SearchBox() {
  const router = useRouter();
  const [query, setQuery] = useState("");

  function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    const value = query.trim();
    if (!value) {
      return;
    }

    router.push(`/vulnerability/${encodeURIComponent(value)}`);
  }

  return (
    <form
      onSubmit={onSubmit}
      className="flex w-full max-w-3xl items-center gap-2 rounded-md border border-stone-300 bg-white p-2 shadow-sm"
    >
      <Search className="h-5 w-5 shrink-0 text-stone-500" aria-hidden="true" />
      <input
        value={query}
        onChange={(event) => setQuery(event.target.value)}
        className="min-w-0 flex-1 border-0 bg-transparent px-1 py-2 text-base text-stone-950 outline-none placeholder:text-stone-400"
        placeholder="Search CVE-2021-44228, GHSA, react, next, vercel..."
        aria-label="Search vulnerabilities, packages, frameworks, or platforms"
      />
      <button
        type="submit"
        className="rounded-md bg-stone-950 px-4 py-2 text-sm font-medium text-white transition hover:bg-stone-800"
      >
        Search
      </button>
    </form>
  );
}

