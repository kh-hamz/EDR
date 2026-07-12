import { afterEach, expect, it, vi } from "vitest";
import { api, ApiError, buildQuery, setToken } from "../../src/api/client";

function mockFetch(status: number, body: unknown) {
  const fn = vi.fn().mockResolvedValue({
    ok: status < 400,
    status,
    json: () => Promise.resolve(body),
  });
  vi.stubGlobal("fetch", fn);
  return fn;
}

afterEach(() => {
  vi.unstubAllGlobals();
  localStorage.clear();
});

it("sends the stored token as a bearer header", async () => {
  setToken("secret-token");
  const fetchMock = mockFetch(200, []);
  await api.hosts();
  const [url, init] = fetchMock.mock.calls[0];
  expect(url).toBe("http://localhost:8000/hosts");
  expect(init.headers.Authorization).toBe("Bearer secret-token");
});

it("surfaces the backend error detail", async () => {
  mockFetch(503, { detail: "LLM not configured" });
  await expect(api.explain("T1571")).rejects.toThrow("LLM not configured");
  await expect(api.explain("T1571")).rejects.toBeInstanceOf(ApiError);
});

it("posts hunt queries as JSON with content type", async () => {
  const fetchMock = mockFetch(200, { filters: {}, total: 0, events: [] });
  await api.hunt("everything on victim-01");
  const [url, init] = fetchMock.mock.calls[0];
  expect(url).toBe("http://localhost:8000/hunt");
  expect(init.method).toBe("POST");
  expect(init.headers["Content-Type"]).toBe("application/json");
  expect(JSON.parse(init.body)).toEqual({ query: "everything on victim-01", size: 50 });
});

it("buildQuery keeps set params and drops empty ones", () => {
  expect(buildQuery({ status: "open", severity: undefined })).toBe("?status=open");
  expect(buildQuery({})).toBe("");
});
