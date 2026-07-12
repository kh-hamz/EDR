import { useCallback, useEffect, useState } from "react";

// Loading/error/data state for a GET-style loader. Pages pass a loader that
// closes over its inputs and list those inputs in deps so the data refetches
// when they change; reload() refetches after a mutation.
export function useApi<T>(loader: () => Promise<T>, deps: unknown[] = []) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  // eslint-style exhaustive-deps does not apply, deps are the caller's inputs
  const reload = useCallback(() => {
    setLoading(true);
    setError(null);
    loader()
      .then(setData)
      .catch((e: unknown) => setError(e instanceof Error ? e.message : String(e)))
      .finally(() => setLoading(false));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  useEffect(() => {
    reload();
  }, [reload]);

  return { data, error, loading, reload };
}
